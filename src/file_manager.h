#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

/* The vault remains local to the application's working directory. */
#define VAULT_DIR ".vault"

/* Return 1 on success and 0 on failure. Error text belongs to the calling
 * thread and remains valid until that thread's next vault operation. */
const char *vault_last_error(void);
int ensure_vault_directory(void);
int handle_file_encryption(const char *input_path, const char *output_path, const char *password);
int handle_file_decryption(const char *input_path, const char *output_path, const char *password);
int handle_legacy_file_decryption(const char *input_path, const char *output_path,
                                  const char *password);
int list_vault_files(void);
int add_file_to_vault(const char *file_path, const char *password);
int retrieve_file_from_vault(const char *filename, const char *output_path, const char *password);
int delete_file_from_vault(const char *filename, const char *password);
/* Explicit recovery of older, unauthenticated CBC files. Callers must warn
 * that successful decryption cannot prove their password or integrity. */
int retrieve_legacy_file_from_vault(const char *filename, const char *output_path,
                                    const char *password);
int delete_legacy_file_from_vault(const char *filename, const char *password);
int handle_file_hashing(const char *algorithm, const char *file_path);
int handle_file_verification(const char *algorithm, const char *file_path,
                             const char *expected_hex);

#endif
