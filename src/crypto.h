/*
 * =====================================================================================
 *
 * Filename:  crypto.h
 *
 * Description:  Header for cryptographic functions using OpenSSL.
 *
 * =====================================================================================
 */

#ifndef CRYPTO_H
#define CRYPTO_H

/**
 * @brief Encrypts a file using AES-256-CBC.
 *
 * Derives a key from the password and a random salt using PBKDF2.
 * The salt is prepended to the output file, followed by the IV, and then
 * the ciphertext. This makes the file self-contained for decryption.
 *
 * @param input_file The path to the plaintext file.
 * @param output_file The path where the encrypted file will be saved.
 * @param password The password to use for encryption.
 * @return 1 on success, 0 on failure.
 */
int encrypt_file(const char *input_file, const char *output_file, const char *password);

/**
 * @brief Decrypts a file encrypted with encrypt_file.
 *
 * Reads the salt and IV from the beginning of the input file and uses them
 * with the password to derive the correct decryption key.
 *
 * @param input_file The path to the encrypted file.
 * @param output_file The path where the decrypted file will be saved.
 * @param password The password used for encryption.
 * @return 1 on success, 0 on failure (e.g., wrong password or corrupt file).
 */
int decrypt_file(const char *input_file, const char *output_file, const char *password);

#endif // CRYPTO_H
