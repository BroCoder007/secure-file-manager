/*
 * =====================================================================================
 *
 * Filename:  file_manager.h
 *
 * Description:  Header file for file_manager.c. Declares the functions
 * that manage the secure vault operations.
 *
 * =====================================================================================
 */

#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

/**
 * @brief Wrapper for file encryption.
 * @param input_path Path to the file to encrypt.
 * @param output_path Path to save the encrypted file.
 * @param password The password for encryption.
 * @return 1 on success, 0 on failure.
 */
int handle_file_encryption(const char* input_path, const char* output_path, const char* password);

/**
 * @brief Wrapper for file decryption.
 * @param input_path Path to the encrypted file.
 * @param output_path Path to save the decrypted file.
 * @param password The password for decryption.
 * @return 1 on success, 0 on failure.
 */
int handle_file_decryption(const char* input_path, const char* output_path, const char* password);

/**
 * @brief Lists all files currently stored in the secure vault.
 */
void list_vault_files();

/**
 * @brief Adds a file to the secure vault. It encrypts and stores it.
 * @param file_path The path of the file to add.
 * @param password The password to encrypt the file with.
 */
void add_file_to_vault(const char* file_path, const char* password);

/**
 * @brief Retrieves a file from the vault. It decrypts and saves it to a specified path.
 * @param filename The name of the file in the vault (without the .enc extension).
 * @param output_path The path to save the decrypted file.
 * @param password The password to decrypt the file.
 */
void retrieve_file_from_vault(const char* filename, const char* output_path, const char* password);

/**
 * @brief Deletes a file from the vault after verifying the password.
 * @param filename The name of the file to delete from the vault.
 * @param password The password for verification before deletion.
 */
void delete_file_from_vault(const char* filename, const char* password);

#endif // FILE_MANAGER_H
