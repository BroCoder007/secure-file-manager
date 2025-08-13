/*
 * =====================================================================================
 *
 * Filename:  file_manager.c
 *
 * Description:  Core logic for managing files in the secure vault. This includes
 * creating the vault, adding, retrieving, listing, and deleting files.
 *
 * =====================================================================================
 */

#include "file_manager.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h> // For basename()
#include <openssl/evp.h> // Needed for EVP_MAX_MD_SIZE

// The directory where encrypted files are stored.
#define VAULT_DIR ".vault"

// ... (all previous functions like ensure_vault_directory, add_file_to_vault, etc. are unchanged) ...
void ensure_vault_directory() {
    struct stat st = {0};
    if (stat(VAULT_DIR, &st) == -1) {
        mkdir(VAULT_DIR, 0700);
    }
}
int handle_file_encryption(const char* input_path, const char* output_path, const char* password) {
    return encrypt_file(input_path, output_path, password);
}
int handle_file_decryption(const char* input_path, const char* output_path, const char* password) {
    return decrypt_file(input_path, output_path, password);
}
void list_vault_files() {
    ensure_vault_directory();
    DIR *d;
    struct dirent *dir;
    d = opendir(VAULT_DIR);
    if (d) {
        printf("Files in vault:\n");
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) {
                printf("- %s\n", dir->d_name);
            }
        }
        closedir(d);
    } else {
        perror("Could not open vault directory");
    }
}
void add_file_to_vault(const char* file_path, const char* password) {
    ensure_vault_directory();
    char* file_path_copy = strdup(file_path);
    if (!file_path_copy) {
        perror("Failed to duplicate file path");
        return;
    }
    char* name = basename(file_path_copy);
    char vault_path[256];
    snprintf(vault_path, sizeof(vault_path), "%s/%s.enc", VAULT_DIR, name);
    if (access(vault_path, F_OK) == 0) {
        fprintf(stderr, "Error: A file named '%s' already exists in the vault.\n", name);
        free(file_path_copy);
        return;
    }
    if (encrypt_file(file_path, vault_path, password)) {
        printf("File '%s' added to the vault.\n", name);
    } else {
        fprintf(stderr, "Error: Failed to add '%s' to the vault.\n", name);
    }
    free(file_path_copy);
}
void retrieve_file_from_vault(const char* filename, const char* output_path, const char* password) {
    ensure_vault_directory();
    char vault_path[256];
    snprintf(vault_path, sizeof(vault_path), "%s/%s", VAULT_DIR, filename);
    if (access(vault_path, F_OK) != 0) {
        fprintf(stderr, "Error: File '%s' not found in the vault.\n", filename);
        return;
    }
    if (decrypt_file(vault_path, output_path, password)) {
        printf("File '%s' retrieved to '%s'.\n", filename, output_path);
    } else {
        fprintf(stderr, "Error: Failed to retrieve '%s'. Check your password.\n", filename);
    }
}
void delete_file_from_vault(const char* filename, const char* password) {
    ensure_vault_directory();
    char vault_path[256];
    snprintf(vault_path, sizeof(vault_path), "%s/%s", VAULT_DIR, filename);
    if (access(vault_path, F_OK) != 0) {
        fprintf(stderr, "Error: File '%s' not found in the vault.\n", filename);
        return;
    }
    char temp_output[] = "temp_delete_check.tmp";
    if (!decrypt_file(vault_path, temp_output, password)) {
        fprintf(stderr, "Error: Incorrect password. Deletion aborted for safety.\n");
        return;
    }
    remove(temp_output);
    if (remove(vault_path) == 0) {
        printf("File '%s' successfully deleted from the vault.\n", filename);
    } else {
        perror("Error deleting file");
    }
}


// NEW FUNCTION
/**
 * @brief Handles hashing a file and printing the result.
 */
void handle_file_hashing(const char* algorithm, const char* file_path) {
    // EVP_MAX_MD_SIZE is a constant from OpenSSL that guarantees our buffer is large enough
    // for any hash function it supports (e.g., SHA-512 needs 64 bytes).
    unsigned char hash_result[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Call the crypto function to perform the actual hashing
    if (!hash_file(algorithm, file_path, hash_result, &hash_len)) {
        fprintf(stderr, "Error: Hashing process failed for file '%s'.\n", file_path);
        return;
    }

    // Print the results to the user
    printf("Successfully hashed '%s' using %s:\n", file_path, algorithm);
    
    // The hash result is raw binary data. We loop through it and print
    // each byte as a two-digit hexadecimal number.
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash_result[i]);
    }
    printf("\n");
}
