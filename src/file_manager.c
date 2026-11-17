#define _POSIX_C_SOURCE 200809L
#include "file_manager.h"
#include "crypto.h"

#include <dirent.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#endif

static _Thread_local char vault_error[512];

const char *vault_last_error(void) {
    return vault_error[0] ? vault_error : "The operation could not be completed.";
}

static int fail(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(vault_error, sizeof(vault_error), format, args);
    va_end(args);
    return 0;
}

/* Windows stat follows links, so explicitly reject all reparse points. */
static int inspect_path(const char *path, struct stat *st) {
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(path);
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        errno = ELOOP;
        return -1;
    }
    return stat(path, st);
#else
    return lstat(path, st);
#endif
}

int ensure_vault_directory(void) {
    struct stat st;
    vault_error[0] = '\0';
    if (inspect_path(VAULT_DIR, &st) != 0) {
        if (errno != ENOENT)
            return fail("Cannot inspect the vault: %s", strerror(errno));
#ifdef _WIN32
        int created = _mkdir(VAULT_DIR);
#else
        int created = mkdir(VAULT_DIR, 0700);
#endif
        if (created != 0 && errno != EEXIST)
            return fail("Cannot create the vault: %s", strerror(errno));
        if (inspect_path(VAULT_DIR, &st) != 0)
            return fail("Cannot inspect the new vault: %s", strerror(errno));
    }
    if (!S_ISDIR(st.st_mode))
        return fail("The vault must be a real directory, not a symbolic link.");
#ifndef _WIN32
    if (st.st_uid != geteuid())
        return fail("The vault must be owned by the current user.");
    if ((st.st_mode & 0077) != 0)
        return fail("The vault is not private. Set its permissions to 0700 (chmod 700 .vault).");
#endif
    return 1;
}

static int valid_name(const char *name) {
    if (!name || !name[0] || !strcmp(name, ".") || !strcmp(name, ".."))
        return 0;
    size_t len = strlen(name);
    if (len <= 4 || strcmp(name + len - 4, ".enc"))
        return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p)
        if (*p == '/' || *p == '\\' || *p < 32 || *p == 127
#ifdef _WIN32
            || *p == ':'
#endif
        )
            return 0;
    return 1;
}

static char *vault_path(const char *name) {
    if (!valid_name(name)) {
        fail("Choose a vault filename ending in .enc, without directory components.");
        return NULL;
    }
    size_t len = strlen(name);
    if (len > SIZE_MAX - sizeof(VAULT_DIR) - 1) {
        fail("The filename is too long.");
        return NULL;
    }
    size_t size = sizeof(VAULT_DIR) + len + 1;
    char *path = malloc(size);
    if (!path) {
        fail("Not enough memory to prepare the vault path.");
        return NULL;
    }
    snprintf(path, size, "%s/%s", VAULT_DIR, name);
    return path;
}

static int regular_file(const char *path, struct stat *st) {
    if (inspect_path(path, st) != 0)
        return fail("Cannot inspect the vault file: %s", strerror(errno));
    if (!S_ISREG(st->st_mode))
        return fail("Only regular vault files are allowed; symbolic links are rejected.");
    return 1;
}

int handle_file_encryption(const char *input_path, const char *output_path, const char *password) {
    vault_error[0] = '\0';
    return encrypt_file(input_path, output_path, password) || fail("%s", crypto_last_error());
}

int handle_file_decryption(const char *input_path, const char *output_path, const char *password) {
    vault_error[0] = '\0';
    return decrypt_file(input_path, output_path, password) || fail("%s", crypto_last_error());
}

int handle_legacy_file_decryption(const char *input_path, const char *output_path,
                                  const char *password) {
    vault_error[0] = '\0';
    return decrypt_legacy_file(input_path, output_path, password) ||
           fail("%s", crypto_last_error());
}

int list_vault_files(void) {
    if (!ensure_vault_directory())
        return 0;
    DIR *dir = opendir(VAULT_DIR);
    if (!dir)
        return fail("Cannot open the vault: %s", strerror(errno));
    puts("Files in vault:");
    int result = 1;
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno)
                result = fail("Cannot read the vault: %s", strerror(errno));
            break;
        }
        if (!valid_name(entry->d_name))
            continue;
        char *path = vault_path(entry->d_name);
        if (!path) {
            result = 0;
            break;
        }
        struct stat st;
        /* Works on filesystems without dirent.d_type support. */
        if (inspect_path(path, &st) == 0 && S_ISREG(st.st_mode))
            printf("- %s\n", entry->d_name);
        free(path);
    }
    if (closedir(dir) != 0 && result)
        result = fail("Cannot close the vault directory: %s", strerror(errno));
    return result;
}

int add_file_to_vault(const char *file_path, const char *password) {
    if (!ensure_vault_directory())
        return 0;
    if (!file_path || !file_path[0])
        return fail("Choose a file to add.");
    const char *name = strrchr(file_path, '/');
#ifdef _WIN32
    const char *backslash = strrchr(file_path, '\\');
    if (backslash && (!name || backslash > name))
        name = backslash;
#endif
    name = name ? name + 1 : file_path;
    size_t len = strlen(name);
    if (!len || len > SIZE_MAX - 5)
        return fail("The filename is invalid or too long.");
    char *encrypted_name = malloc(len + 5);
    if (!encrypted_name)
        return fail("Not enough memory to prepare the filename.");
    memcpy(encrypted_name, name, len);
    memcpy(encrypted_name + len, ".enc", 5);
    char *path = vault_path(encrypted_name);
    free(encrypted_name);
    if (!path)
        return 0;
    int result = encrypt_file(file_path, path, password);
    if (!result)
        fail("%s", crypto_last_error());
    free(path);
    return result;
}

static int retrieve_vault_file(const char *filename, const char *output_path, const char *password,
                               int allow_legacy) {
    if (!ensure_vault_directory())
        return 0;
    char *path = vault_path(filename);
    if (!path)
        return 0;
    struct stat st;
    int result = regular_file(path, &st);
    if (result) {
        result = allow_legacy ? decrypt_legacy_file(path, output_path, password)
                              : decrypt_file(path, output_path, password);
        if (!result)
            fail("%s", crypto_last_error());
    }
    free(path);
    return result;
}

int retrieve_file_from_vault(const char *filename, const char *output_path, const char *password) {
    return retrieve_vault_file(filename, output_path, password, 0);
}

int retrieve_legacy_file_from_vault(const char *filename, const char *output_path,
                                    const char *password) {
    return retrieve_vault_file(filename, output_path, password, 1);
}

static int delete_vault_file(const char *filename, const char *password, int allow_legacy) {
    if (!ensure_vault_directory())
        return 0;
    char *path = vault_path(filename);
    if (!path)
        return 0;
    struct stat before, after;
    int result = regular_file(path, &before);
    if (result) {
        int verified = allow_legacy ? verify_legacy_encrypted_file(path, password)
                                    : verify_encrypted_file(path, password);
        if (!verified)
            result = fail("Deletion cancelled: %s", crypto_last_error());
    }
    /* Verification never writes plaintext. Refuse to delete a file replaced
     * while its password was being checked. The local vault is owner-only. */
    if (result && !regular_file(path, &after))
        result = 0;
    if (result && (before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
                   before.st_size != after.st_size || before.st_mtime != after.st_mtime))
        result = fail("The vault file changed during verification. Try again.");
    if (result && unlink(path) != 0)
        result = fail("Cannot delete the vault file: %s", strerror(errno));
    free(path);
    return result;
}

int delete_file_from_vault(const char *filename, const char *password) {
    return delete_vault_file(filename, password, 0);
}

int delete_legacy_file_from_vault(const char *filename, const char *password) {
    return delete_vault_file(filename, password, 1);
}

int handle_file_hashing(const char *algorithm, const char *file_path) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    vault_error[0] = '\0';
    if (!hash_file(algorithm, file_path, digest, &len))
        return fail("%s", crypto_last_error());
    for (unsigned int i = 0; i < len; ++i)
        printf("%02x", digest[i]);
    putchar('\n');
    return 1;
}

static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int handle_file_verification(const char *algorithm, const char *file_path,
                             const char *expected_hex) {
    unsigned char digest[EVP_MAX_MD_SIZE], expected[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    vault_error[0] = '\0';
    size_t expected_len = algorithm && !strcmp(algorithm, "sha256")   ? 32
                          : algorithm && !strcmp(algorithm, "sha512") ? 64
                                                                      : 0;
    if (!expected_len)
        return fail("Use sha256 or sha512 for checksum verification.");
    if (!expected_hex || strlen(expected_hex) != expected_len * 2)
        return fail("The expected checksum must contain exactly %zu hexadecimal characters.",
                    expected_len * 2);
    for (size_t i = 0; i < expected_len; ++i) {
        int hi = hex_digit((unsigned char)expected_hex[i * 2]);
        int lo = hex_digit((unsigned char)expected_hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return fail("The expected checksum contains a non-hexadecimal character.");
        expected[i] = (unsigned char)((hi << 4) | lo);
    }
    if (!hash_file(algorithm, file_path, digest, &len))
        return fail("%s", crypto_last_error());
    if (len != expected_len || CRYPTO_memcmp(digest, expected, expected_len) != 0)
        return fail("Checksum mismatch: this file does not match the expected digest.");
    return 1;
}
