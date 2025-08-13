/*
 * =====================================================================================
 *
 * Filename:  crypto.c
 *
 * Description:  Handles all cryptographic operations using the OpenSSL library.
 * Implements AES-256-CBC encryption and decryption.
 *
 * =====================================================================================
 */

#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

// Constants for the encryption scheme
#define SALT_SIZE 8
#define KEY_SIZE 32 // 256 bits for AES-256
#define IV_SIZE 16  // 128-bit block size for AES
#define HASH_BUF_SIZE 4096 // Buffer for reading file during hashing

/**
 * @brief A utility function to print OpenSSL error messages and exit.
 */
void handle_openssl_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// ... (encrypt_file and decrypt_file functions remain the same) ...
int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    // Unchanged from before
    FILE *in_f, *out_f;
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    in_f = fopen(input_file, "rb");
    if (!in_f) {
        perror("Could not open input file for encryption");
        return 0;
    }

    out_f = fopen(output_file, "wb");
    if (!out_f) {
        perror("Could not open output file for encryption");
        fclose(in_f);
        return 0;
    }

    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Error: Could not generate random salt.\n");
        fclose(in_f);
        fclose(out_f);
        return 0;
    }
    fwrite(salt, 1, sizeof(salt), out_f);

    unsigned char derived_key_iv[KEY_SIZE + IV_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(derived_key_iv), derived_key_iv)) {
        fprintf(stderr, "Error: Could not derive key and IV.\n");
        fclose(in_f);
        fclose(out_f);
        return 0;
    }
    memcpy(key, derived_key_iv, KEY_SIZE);
    memcpy(iv, derived_key_iv + KEY_SIZE, IV_SIZE);

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_errors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handle_openssl_errors();

    while ((len = fread(inbuf, 1, sizeof(inbuf), in_f)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, outbuf, &ciphertext_len, inbuf, len)) handle_openssl_errors();
        fwrite(outbuf, 1, ciphertext_len, out_f);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &ciphertext_len)) handle_openssl_errors();
    fwrite(outbuf, 1, ciphertext_len, out_f);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_f);
    fclose(out_f);

    return 1;
}

int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    // Unchanged from before
    FILE *in_f, *out_f;
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    
    in_f = fopen(input_file, "rb");
    if (!in_f) {
        perror("Could not open input file for decryption");
        return 0;
    }

    out_f = fopen(output_file, "wb");
    if (!out_f) {
        perror("Could not open output file for decryption");
        fclose(in_f);
        return 0;
    }

    if (fread(salt, 1, sizeof(salt), in_f) != sizeof(salt)) {
        fprintf(stderr, "Error: Could not read salt from file. File may be corrupted or not an encrypted file.\n");
        fclose(in_f);
        fclose(out_f);
        remove(output_file);
        return 0;
    }

    unsigned char derived_key_iv[KEY_SIZE + IV_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(derived_key_iv), derived_key_iv)) {
        fprintf(stderr, "Error: Could not derive key and IV for decryption.\n");
        fclose(in_f);
        fclose(out_f);
        return 0;
    }
    memcpy(key, derived_key_iv, KEY_SIZE);
    memcpy(iv, derived_key_iv + KEY_SIZE, IV_SIZE);

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    unsigned char inbuf[1024], outbuf[1024];

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_errors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handle_openssl_errors();

    while ((len = fread(inbuf, 1, sizeof(inbuf), in_f)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, outbuf, &plaintext_len, inbuf, len)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_f);
            fclose(out_f);
            remove(output_file);
            return 0;
        }
        fwrite(outbuf, 1, plaintext_len, out_f);
    }

    ret = EVP_DecryptFinal_ex(ctx, outbuf, &plaintext_len);
    
    if (ret > 0) {
        fwrite(outbuf, 1, plaintext_len, out_f);
    } else {
        fclose(in_f);
        fclose(out_f);
        remove(output_file);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_f);
    fclose(out_f);

    return 1;
}


// NEW FUNCTION
/**
 * @brief Hashes a file using the specified algorithm.
 */
int hash_file(const char *algorithm, const char *input_file, unsigned char *hash_output, unsigned int *hash_len) {
    FILE *in_f;
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;
    int bytes_read;
    unsigned char buffer[HASH_BUF_SIZE];

    // 1. Select the hashing algorithm based on the user's choice
    if (strcmp(algorithm, "sha256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(algorithm, "sha512") == 0) {
        md = EVP_sha512();
    } else {
        fprintf(stderr, "Error: Invalid hashing algorithm '%s'.\n", algorithm);
        return 0;
    }

    // 2. Open the input file for reading in binary mode
    in_f = fopen(input_file, "rb");
    if (!in_f) {
        perror("Could not open input file for hashing");
        return 0;
    }

    // 3. Create and initialize the message digest context
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_openssl_errors();

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL))
        handle_openssl_errors();

    // 4. Read the file in chunks and update the digest
    while ((bytes_read = fread(buffer, 1, HASH_BUF_SIZE, in_f)) > 0) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, bytes_read))
            handle_openssl_errors();
    }

    // 5. Finalize the hash, storing the result in hash_output
    if (1 != EVP_DigestFinal_ex(mdctx, hash_output, hash_len))
        handle_openssl_errors();

    // 6. Clean up resources
    EVP_MD_CTX_free(mdctx);
    fclose(in_f);

    return 1;
}
