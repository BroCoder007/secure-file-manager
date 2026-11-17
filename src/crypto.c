#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#ifndef O_NONBLOCK
#define O_NONBLOCK 0
#endif
#define fsync _commit
#define lstat stat
#endif

#define IO_SIZE 65536
#define HEADER_SIZE 44
#define TAG_SIZE 16
#define KDF_ROUNDS 600000
#define GCM_MAX_BYTES (((uint64_t)1 << 36) - 32)

/* Wire format: magic[8], version[1], cipher[1], reserved[2], PBKDF2 rounds[4,
 * big endian], salt[16], nonce[12], ciphertext[N], tag[16]. The entire 44-byte
 * header is AAD. Cipher=1 means AES-256-GCM; version=1. Fixed KDF parameters in
 * this version prevent attacker-controlled excessive derivation work. */
static const unsigned char magic[8] = {'S', 'F', 'M', 'E', 'N', 'C', '\r', '\n'};
static _Thread_local char last_error[256];

const char *crypto_last_error(void) { return last_error[0] ? last_error : "Operation failed."; }

static int fail(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(last_error, sizeof(last_error), format, args);
    va_end(args);
    return 0;
}

static int valid_password(const char *password) {
    if (!password || !*password)
        return fail("Enter a nonempty password.");
    if (strlen(password) > INT_MAX)
        return fail("Password is too long.");
    return 1;
}

/* O_NONBLOCK prevents special files blocking before fstat can reject them. */
static FILE *open_input(const char *path, struct stat *info) {
    int flags = O_RDONLY | O_NONBLOCK;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef _WIN32
    flags |= O_BINARY;
#ifdef O_NOINHERIT
    flags |= O_NOINHERIT;
#endif
#endif
    if (!path || !*path) {
        fail("Choose an input file.");
        return NULL;
    }
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        fail("Input must be an accessible regular file, not a symbolic link.");
        return NULL;
    }
#endif
    int fd = open(path, flags);
    if (fd < 0) {
        fail("Cannot open input: %s", strerror(errno));
        return NULL;
    }
    if (fstat(fd, info) != 0 || !S_ISREG(info->st_mode)) {
        fail("Input must be a regular file, not a directory or special file.");
        close(fd);
        return NULL;
    }
    FILE *file = fdopen(fd, "rb");
    if (!file) {
        fail("Cannot read input: %s", strerror(errno));
        close(fd);
    }
    return file;
}

typedef struct {
    FILE *file;
    char *temporary;
    const char *destination;
} Output;

static int output_open(Output *out, const char *path) {
    struct stat existing;
    if (!path || !*path)
        return fail("Choose a destination file.");
    if (lstat(path, &existing) == 0)
        return fail("Destination already exists. Choose a new filename.");
    if (errno != ENOENT)
        return fail("Cannot inspect destination: %s", strerror(errno));
    size_t length = strlen(path);
    if (length > SIZE_MAX - 20)
        return fail("Destination path is too long.");
    out->temporary = malloc(length + 20);
    if (!out->temporary)
        return fail("Not enough memory to create output.");
    snprintf(out->temporary, length + 20, "%s.sfm-XXXXXX", path);
    out->destination = path;
    int fd;
#ifdef _WIN32
    /* MinGW does not consistently provide mkstemp. Secure random names plus
     * exclusive creation retain the same collision/race behavior. Windows
     * access control inherits the containing directory's ACL. */
    unsigned char random[6];
    fd = -1;
    for (int attempt = 0; attempt < 32; ++attempt) {
        if (RAND_bytes(random, sizeof(random)) != 1) {
            errno = EIO;
            break;
        }
        snprintf(out->temporary, length + 20, "%s.sfm-%02x%02x%02x%02x%02x%02x", path, random[0],
                 random[1], random[2], random[3], random[4], random[5]);
        int output_flags = O_WRONLY | O_CREAT | O_EXCL | O_BINARY;
#ifdef O_NOINHERIT
        output_flags |= O_NOINHERIT;
#endif
        fd = open(out->temporary, output_flags, 0600);
        if (fd >= 0 || errno != EEXIST)
            break;
    }
#else
    fd = mkstemp(out->temporary); /* 0600; same directory/filesystem */
#endif
    if (fd < 0) {
        int saved = errno;
        free(out->temporary);
        out->temporary = NULL; /* Never unlink a path we did not create. */
        return fail("Cannot create private output: %s", strerror(saved));
    }
#ifdef _WIN32
    _setmode(fd, O_BINARY);
#else
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        int saved = errno;
        close(fd);
        return fail("Cannot protect output descriptor: %s", strerror(saved));
    }
#endif
    out->file = fdopen(fd, "wb");
    if (!out->file) {
        close(fd);
        return fail("Cannot write output: %s", strerror(errno));
    }
    return 1;
}

static int output_write(Output *out, const unsigned char *data, size_t size) {
    if (!out || !size) /* A null output discards plaintext during verification. */
        return 1;
    if (fwrite(data, 1, size, out->file) != size)
        return fail("Cannot write output: %s", strerror(errno));
    return 1;
}

static int output_commit(Output *out) {
    if (fflush(out->file) != 0 || fsync(fileno(out->file)) != 0)
        return fail("Cannot finish output: %s", strerror(errno));
    FILE *file = out->file;
    out->file = NULL;
    if (fclose(file) != 0)
        return fail("Cannot close output: %s", strerror(errno));
    /* Atomic no-replace publication, including when another process races us.
     * POSIX rename would overwrite a destination; link never does. */
#ifdef _WIN32
    if (!MoveFileExA(out->temporary, out->destination, MOVEFILE_WRITE_THROUGH))
        return fail("Cannot publish output; destination may exist or be inaccessible.");
    /* The source pathname is vacant after a move. Do not let cleanup unlink
     * an unrelated file recreated there by a concurrent process. */
    free(out->temporary);
    out->temporary = NULL;
#else
    if (link(out->temporary, out->destination) != 0) {
        if (errno == EEXIST)
            return fail("Destination already exists. Choose a new filename.");
        return fail("Cannot publish output: %s", strerror(errno));
    }
#endif
    return 1;
}

static void output_cleanup(Output *out) {
    if (out->file)
        fclose(out->file);
    if (out->temporary) {
        unlink(out->temporary);
        free(out->temporary);
    }
}

static void put_u32(unsigned char *out, uint32_t value) {
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static uint32_t get_u32(const unsigned char *in) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static int derive(const char *password, const unsigned char *salt, int salt_size, int rounds,
                  unsigned char *key, int key_size) {
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, salt_size, rounds, EVP_sha256(),
                          key_size, key) != 1)
        return fail("Could not derive encryption key.");
    return 1;
}

int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    FILE *input = NULL;
    Output output = {0};
    EVP_CIPHER_CTX *ctx = NULL;
    struct stat info;
    unsigned char header[HEADER_SIZE] = {0}, key[32] = {0}, tag[TAG_SIZE];
    unsigned char inbuf[IO_SIZE], outbuf[IO_SIZE + EVP_MAX_BLOCK_LENGTH];
    size_t count;
    uint64_t total = 0;
    int written, ok = 0;
    last_error[0] = '\0';
    if (!valid_password(password) || !(input = open_input(input_file, &info)))
        goto done;
    if (info.st_size < 0 || (uint64_t)info.st_size > GCM_MAX_BYTES) {
        fail("File exceeds the AES-GCM per-file limit (64 GiB minus 32 bytes).");
        goto done;
    }
    memcpy(header, magic, sizeof(magic));
    header[8] = header[9] = 1;
    put_u32(header + 12, KDF_ROUNDS);
    if (RAND_bytes(header + 16, 16) != 1 || RAND_bytes(header + 32, 12) != 1) {
        fail("Could not obtain secure random salt and nonce.");
        goto done;
    }
    if (!derive(password, header + 16, 16, KDF_ROUNDS, key, sizeof(key)))
        goto done;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, header + 32) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &written, header, HEADER_SIZE) != 1) {
        fail("Could not initialize authenticated encryption.");
        goto done;
    }
    if (!output_open(&output, output_file) || !output_write(&output, header, HEADER_SIZE))
        goto done;
    while ((count = fread(inbuf, 1, sizeof(inbuf), input)) > 0) {
        total += count;
        if (total > GCM_MAX_BYTES) {
            fail("File grew beyond the AES-GCM per-file limit.");
            goto done;
        }
        if (EVP_EncryptUpdate(ctx, outbuf, &written, inbuf, (int)count) != 1) {
            fail("Encryption failed.");
            goto done;
        }
        if (!output_write(&output, outbuf, (size_t)written))
            goto done;
    }
    if (ferror(input)) {
        fail("Cannot read complete input file.");
        goto done;
    }
    if (EVP_EncryptFinal_ex(ctx, outbuf, &written) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        fail("Could not finish authenticated encryption.");
        goto done;
    }
    if (!output_write(&output, outbuf, (size_t)written) || !output_write(&output, tag, TAG_SIZE))
        goto done;
    if (fclose(input) != 0) {
        input = NULL;
        fail("Cannot close input file.");
        goto done;
    }
    input = NULL;
    ok = output_commit(&output);
done:
    if (input)
        fclose(input);
    output_cleanup(&output);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(inbuf, sizeof(inbuf));
    OPENSSL_cleanse(outbuf, sizeof(outbuf));
    return ok;
}

static int decrypt_stream(const char *input_file, const char *output_file, const char *password,
                          int allow_legacy) {
    FILE *input = NULL;
    Output output = {0};
    Output *sink = output_file ? &output : NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    struct stat info;
    unsigned char header[HEADER_SIZE] = {0}, derived[48] = {0}, tag[TAG_SIZE];
    unsigned char inbuf[IO_SIZE], outbuf[IO_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint64_t remaining;
    int modern, written, ok = 0;
    last_error[0] = '\0';
    if (!valid_password(password) || !(input = open_input(input_file, &info)))
        goto done;
    if (fread(header, 1, 8, input) != 8) {
        fail("Encrypted file is truncated or invalid.");
        goto done;
    }
    modern = memcmp(header, magic, sizeof(magic)) == 0;
    if (modern) {
        if (info.st_size < HEADER_SIZE + TAG_SIZE ||
            fread(header + 8, 1, HEADER_SIZE - 8, input) != HEADER_SIZE - 8) {
            fail("Authenticated file is truncated.");
            goto done;
        }
        if (header[8] != 1 || header[9] != 1 || header[10] || header[11] ||
            get_u32(header + 12) != KDF_ROUNDS) {
            fail("Unsupported or damaged encrypted file header.");
            goto done;
        }
        remaining = (uint64_t)info.st_size - HEADER_SIZE - TAG_SIZE;
        if (remaining > GCM_MAX_BYTES) {
            fail("Encrypted file exceeds the AES-GCM per-file limit.");
            goto done;
        }
        if (!derive(password, header + 16, 16, KDF_ROUNDS, derived, 32))
            goto done;
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, derived, header + 32) != 1 ||
            EVP_DecryptUpdate(ctx, NULL, &written, header, HEADER_SIZE) != 1) {
            fail("Could not initialize authenticated decryption.");
            goto done;
        }
    } else {
        if (!allow_legacy) {
            fail("Unknown or damaged authenticated file header. For an original CBC file, "
                 "explicitly choose legacy recovery.");
            goto done;
        }
        /* Refuse near-matching damaged magic instead of silently downgrading.
         * Original markerless CBC files remain readable for migration. */
        unsigned int matching = 0;
        for (size_t i = 0; i < sizeof(magic); ++i)
            matching += header[i] == magic[i];
        if (matching >= 6 || info.st_size < 24 || (info.st_size - 8) % 16 != 0) {
            fail("Encrypted file is damaged or has an unsupported format.");
            goto done;
        }
        remaining = (uint64_t)info.st_size - 8;
        if (!derive(password, header, 8, 10000, derived, sizeof(derived)))
            goto done;
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, derived, derived + 32) != 1) {
            fail("Could not initialize legacy decryption.");
            goto done;
        }
    }
    if (sink && !output_open(sink, output_file))
        goto done;
    while (remaining > 0) {
        size_t count = remaining < IO_SIZE ? (size_t)remaining : IO_SIZE;
        if (fread(inbuf, 1, count, input) != count) {
            fail("Cannot read complete encrypted file.");
            goto done;
        }
        if (EVP_DecryptUpdate(ctx, outbuf, &written, inbuf, (int)count) != 1) {
            fail("Incorrect password or damaged encrypted file.");
            goto done;
        }
        if (!output_write(sink, outbuf, (size_t)written))
            goto done;
        remaining -= count;
    }
    if (modern && (fread(tag, 1, TAG_SIZE, input) != TAG_SIZE ||
                   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1)) {
        fail("Authentication tag is missing or invalid.");
        goto done;
    }
    if (fgetc(input) != EOF || ferror(input)) {
        fail("Encrypted file changed while it was being read.");
        goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, outbuf, &written) != 1) {
        fail(modern ? "Incorrect password or authentication failed. File may have been modified."
                    : "Incorrect password or damaged legacy file.");
        goto done;
    }
    if (!output_write(sink, outbuf, (size_t)written))
        goto done;
    if (fclose(input) != 0) {
        input = NULL;
        fail("Cannot close encrypted input file.");
        goto done;
    }
    input = NULL;
    ok = sink ? output_commit(sink) : 1;
done:
    if (input)
        fclose(input);
    output_cleanup(&output);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(derived, sizeof(derived));
    OPENSSL_cleanse(inbuf, sizeof(inbuf));
    OPENSSL_cleanse(outbuf, sizeof(outbuf));
    return ok;
}

int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    if (!output_file || !*output_file) {
        last_error[0] = '\0';
        return fail("Choose a destination file.");
    }
    return decrypt_stream(input_file, output_file, password, 0);
}

int verify_encrypted_file(const char *input_file, const char *password) {
    return decrypt_stream(input_file, NULL, password, 0);
}

int decrypt_legacy_file(const char *input_file, const char *output_file, const char *password) {
    if (!output_file || !*output_file) {
        last_error[0] = '\0';
        return fail("Choose a destination file.");
    }
    return decrypt_stream(input_file, output_file, password, 1);
}

int verify_legacy_encrypted_file(const char *input_file, const char *password) {
    return decrypt_stream(input_file, NULL, password, 1);
}

int hash_file(const char *algorithm, const char *input_file, unsigned char *hash_output,
              unsigned int *hash_len) {
    FILE *input = NULL;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *digest = NULL;
    struct stat info;
    unsigned char buffer[IO_SIZE];
    size_t count;
    int ok = 0;
    last_error[0] = '\0';
    if (hash_len)
        *hash_len = 0;
    if (!algorithm || !hash_output || !hash_len)
        return fail("Invalid checksum arguments.");
    if (strcmp(algorithm, "sha256") == 0)
        digest = EVP_sha256();
    else if (strcmp(algorithm, "sha512") == 0)
        digest = EVP_sha512();
    else
        return fail("Unsupported checksum algorithm. Choose sha256 or sha512.");
    input = open_input(input_file, &info);
    if (!input)
        goto done;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, digest, NULL) != 1) {
        fail("Could not initialize checksum.");
        goto done;
    }
    while ((count = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, count) != 1) {
            fail("Could not update checksum.");
            goto done;
        }
    }
    if (ferror(input)) {
        fail("Cannot read complete input file for checksum.");
        goto done;
    }
    if (EVP_DigestFinal_ex(ctx, hash_output, hash_len) != 1) {
        fail("Could not finish checksum.");
        goto done;
    }
    if (fclose(input) != 0) {
        input = NULL;
        fail("Cannot close checksum input file.");
        goto done;
    }
    input = NULL;
    ok = 1;
done:
    if (input)
        fclose(input);
    EVP_MD_CTX_free(ctx);
    OPENSSL_cleanse(buffer, sizeof(buffer));
    if (!ok) {
        OPENSSL_cleanse(hash_output, EVP_MAX_MD_SIZE);
        *hash_len = 0;
    }
    return ok;
}
