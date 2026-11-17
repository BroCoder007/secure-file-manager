/* Identical runner for comparing old and current crypto.c implementations. */
#include "crypto.h"
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "hash") == 0) {
        unsigned char digest[64];
        unsigned int length = 0;
        return hash_file(argv[2], argv[3], digest, &length) ? 0 : 1;
    }
    if (argc == 5 && strcmp(argv[1], "encrypt") == 0)
        return encrypt_file(argv[2], argv[3], argv[4]) ? 0 : 1;
    if (argc == 5 && strcmp(argv[1], "decrypt") == 0)
        return decrypt_file(argv[2], argv[3], argv[4]) ? 0 : 1;
    return 2;
}
