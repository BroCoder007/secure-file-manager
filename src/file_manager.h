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

// Vault management functions
int handle_file_encryption(const char* input_path, const char* output_path, const char* password);
int handle_file_decryption(const char* input_path, const char* output_path, const char* password);
void list_vault_files();
void add_file_to_vault(const char* file_path, const char* password);
void retrieve_file_from_vault(const char* filename, const char* output_path, const char* password);
void delete_file_from_vault(const char* filename, const char* password);

// Hashing function
void handle_file_hashing(const char* algorithm, const char* file_path);


#endif // FILE_MANAGER_H
