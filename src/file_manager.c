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

// The directory where encrypted files are stored.
#define VAULT_DIR ".vault"

/**
 * @brief Ensures the vault directory exists. If not, it creates it.
 */
void ensure_vault_directory() {
    struct stat st = {0};
    if (stat(VAULT_DIR, &st) == -1) {
        // Create with rwx permissions for the owner only for security.
        mkdir(VAULT_DIR, 0700);
    }
}

/**
 * @brief A wrapper function that calls the main encryption logic.
 */
int handle_file_encryption(const char* input_path, const char* output_path, const char* password) {
    return encrypt_file(input_path, output_path, password);
}

/**
 * @brief A wrapper function that calls the main decryption logic.
 */
int handle_file_decryption(const char* input_path, const char* output_path, const char* password) {
    return decrypt_file(input_path, output_path, password);
}

/**
 * @brief Lists all the regular files inside the vault directory.
 */
void list_vault_files() {
    ensure_vault_directory();
    DIR *d;
    struct dirent *dir;
    d = opendir(VAULT_DIR);
    if (d) {
        printf("Files in vault:\n");
        while ((dir = readdir(d)) != NULL) {
            // We only want to list regular files, not directories like '.' or '..'
            if (dir->d_type == DT_REG) {
                printf("- %s\n", dir->d_name);
            }
        }
        closedir(d);
    } else {
        perror("Could not open vault directory");
    }
}

/**
 * @brief Adds a file to the vault.
 */
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

/**
 * @brief Retrieves a file from the vault.
 */
void retrieve_file_from_vault(const char* filename, const char* output_path, const char* password) {
    ensure_vault_directory();
    char vault_path[256];
    snprintf(vault_path, sizeof(vault_path), "%s/%s", VAULT_DIR, filename);

    // *** DEBUGGING LINE ADDED HERE ***
    printf("DEBUG: Checking for file at path: [%s]\n", vault_path);

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

/**
 * @brief Deletes a file from the vault.
 */
void delete_file_from_vault(const char* filename, const char* password) {
    ensure_vault_directory();
    char vault_path[256];
    snprintf(vault_path, sizeof(vault_path), "%s/%s", VAULT_DIR, filename);

    // *** DEBUGGING LINE ADDED HERE ***
    printf("DEBUG: Checking for file at path: [%s]\n", vault_path);

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
