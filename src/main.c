/*
 * =====================================================================================
 *
 * Filename:  main.c
 *
 * Description:  Entry point for the Secure File Manager. Handles command-line
 * argument parsing and dispatches to the appropriate functions.
 *
 * =====================================================================================
 */

#include "file_manager.h" // <<< THE MISSING LINE WAS HERE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * @brief Prints the usage instructions for the command-line tool.
 */
void print_usage() {
    printf("Secure File Manager\n");
    printf("Usage: ./secure_file_manager <command> [options]\n\n");
    printf("Commands:\n");
    printf("  encrypt <input> <output> <password>     Encrypts a file.\n");
    printf("  decrypt <input> <output> <password>     Decrypts a file.\n");
    printf("  add <file> <password>                   Adds and encrypts a file to the vault.\n");
    printf("  retrieve <file> <output> <password>     Retrieves and decrypts a file from the vault.\n");
    printf("  delete <file> <password>                Deletes a file from the vault.\n");
    printf("  list                                    Lists files in the secure vault.\n");
    printf("  hash <algo> <file>                      Hashes a file. Algo can be 'sha256' or 'sha512'.\n");
    printf("\n");
}

/**
 * @brief Main function of the program.
 *
 * @param argc The number of command-line arguments.
 * @param argv An array of command-line argument strings.
 * @return 0 on success, 1 on error.
 */
int main(int argc, char *argv[]) {
    // Check for the minimum number of arguments
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const char *command = argv[1];

    // Route command to the correct handler function
    if (strcmp(command, "encrypt") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Error: Incorrect arguments for 'encrypt'.\n");
            print_usage();
            return 1;
        }
        if (handle_file_encryption(argv[2], argv[3], argv[4])) {
            printf("File '%s' encrypted successfully to '%s'.\n", argv[2], argv[3]);
        } else {
            fprintf(stderr, "Error: File encryption failed.\n");
        }
    } else if (strcmp(command, "decrypt") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Error: Incorrect arguments for 'decrypt'.\n");
            print_usage();
            return 1;
        }
        if (handle_file_decryption(argv[2], argv[3], argv[4])) {
            printf("File '%s' decrypted successfully to '%s'.\n", argv[2], argv[3]);
        } else {
            fprintf(stderr, "Error: File decryption failed.\n");
        }
    } else if (strcmp(command, "list") == 0) {
        list_vault_files();
    } else if (strcmp(command, "add") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: Incorrect arguments for 'add'.\n");
            print_usage();
            return 1;
        }
        add_file_to_vault(argv[2], argv[3]);
    } else if (strcmp(command, "retrieve") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Error: Incorrect arguments for 'retrieve'.\n");
            print_usage();
            return 1;
        }
        retrieve_file_from_vault(argv[2], argv[3], argv[4]);
    } else if (strcmp(command, "delete") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: Incorrect arguments for 'delete'.\n");
            print_usage();
            return 1;
        }
        delete_file_from_vault(argv[2], argv[3]);
    } 
    // ADDED handler for the hash command
    else if (strcmp(command, "hash") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Error: Incorrect arguments for 'hash'.\n");
            print_usage();
            return 1;
        }
        // argv[2] is the algorithm, argv[3] is the file path
        handle_file_hashing(argv[2], argv[3]);
    } 
    else {
        fprintf(stderr, "Error: Unknown command '%s'.\n", command);
        print_usage();
        return 1;
    }

    return 0;
}
