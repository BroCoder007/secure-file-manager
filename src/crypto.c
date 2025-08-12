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

/**
 * @brief A utility function to print OpenSSL error messages and exit.
 */
void handle_openssl_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/**
 * @brief Encrypts a file.
 */
int encrypt_file(const char *input_file, const char *output_file, const char *password) {
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

    // 1. Generate a cryptographically secure random salt.
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "Error: Could not generate random salt.\n");
        fclose(in_f);
        fclose(out_f);
        return 0;
    }
    // Write the salt to the start of the output file. It's needed for decryption.
    fwrite(salt, 1, sizeof(salt), out_f);

    // 2. Derive a key and IV from the password and salt using PBKDF2.
    unsigned char derived_key_iv[KEY_SIZE + IV_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(derived_key_iv), derived_key_iv)) {
        fprintf(stderr, "Error: Could not derive key and IV.\n");
        fclose(in_f);
        fclose(out_f);
        return 0;
    }
    memcpy(key, derived_key_iv, KEY_SIZE);
    memcpy(iv, derived_key_iv + KEY_SIZE, IV_SIZE);

    // 3. Perform the encryption using AES-256 in CBC mode.
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_openssl_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_openssl_errors();

    while ((len = fread(inbuf, 1, sizeof(inbuf), in_f)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, outbuf, &ciphertext_len, inbuf, len))
            handle_openssl_errors();
        fwrite(outbuf, 1, ciphertext_len, out_f);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, outbuf, &ciphertext_len))
        handle_openssl_errors();
    fwrite(outbuf, 1, ciphertext_len, out_f);

    // 4. Clean up resources.
    EVP_CIPHER_CTX_free(ctx);
    fclose(in_f);
    fclose(out_f);

    return 1;
}

/**
 * @brief Decrypts a file.
 */
int decrypt_file(const char *input_file, const char *output_file, const char *password) {
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

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_openssl_errors();

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
    
    // **FIXED LOGIC HERE**
    if (ret > 0) {
        // Write the final decrypted block if successful
        fwrite(outbuf, 1, plaintext_len, out_f);
    } else {
        // Decryption failed. Clean up the potentially garbage output file.
        fclose(in_f);
        fclose(out_f);
        remove(output_file);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Clean up all resources at the end
    EVP_CIPHER_CTX_free(ctx);
    fclose(in_f);
    fclose(out_f);

    return 1;
}
