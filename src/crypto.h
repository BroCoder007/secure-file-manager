/*
 * =====================================================================================
 *
 * Filename:  crypto.h
 *
 * Description:  Header for cryptographic functions.
 *
 * =====================================================================================
 */

#ifndef CRYPTO_H
#define CRYPTO_H

/**
 * @brief Encrypts a file using AES-256-CBC.
 *
 * Derives a key from the password and a random salt using PBKDF2.
 * The salt is prepended to the output file.
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
 * Reads the salt from the beginning of the input file and uses it with the
 * password to derive the decryption key.
 *
 * @param input_file The path to the encrypted file.
 * @param output_file The path where the decrypted file will be saved.
 * @param password The password used for encryption.
 * @return 1 on success, 0 on failure (e.g., wrong password).
 */
int decrypt_file(const char *input_file, const char *output_file, const char *password);


// NEW FUNCTION
/**
 * @brief Hashes a file using the specified algorithm (sha256 or sha512).
 *
 * @param algorithm A string specifying the hash algorithm ("sha256" or "sha512").
 * @param input_file The path to the file to be hashed.
 * @param hash_output A buffer where the raw hash digest will be stored.
 * @param hash_len A pointer to an unsigned int where the length of the hash will be stored.
 * @return 1 on success, 0 on failure.
 */
int hash_file(const char *algorithm, const char *input_file, unsigned char *hash_output, unsigned int *hash_len);


#endif // CRYPTO_H
