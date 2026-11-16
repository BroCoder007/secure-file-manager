#define _POSIX_C_SOURCE 200809L
#include "file_manager.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <termios.h>
#endif

#define PASSWORD_CAPACITY 4096

static void print_usage(FILE *stream) {
    fputs("Secure File Manager 2.0\n"
          "Usage: secure_file_manager <command> [arguments]\n\n"
          "  add <file> <password>                   Encrypt into the local vault\n"
          "  list                                    List encrypted vault files\n"
          "  retrieve <name.enc> <output> <password>  Decrypt a vault file\n"
          "  delete <name.enc> <password>             Verify password and delete\n"
          "  encrypt <input> <output> <password>      Encrypt a standalone file\n"
          "  decrypt <input> <output> <password>      Decrypt a standalone file\n"
          "  decrypt-legacy <input> <output> <password>  Recover an older CBC file\n"
          "  retrieve-legacy <name.enc> <output> <password>  Recover an older vault file\n"
          "  delete-legacy <name.enc> <password>      Delete an older CBC vault file\n"
          "  hash <sha256|sha512> <file>              Print a checksum\n"
          "  verify <sha256|sha512> <file> <hex>      Verify an expected checksum\n"
          "  --help                                  Show this help\n"
          "  --version                               Show the version\n\n"
          "Use '-' for <password> to read it from standard input (hidden on a terminal).\n"
          "Output files must not already exist. Originals are preserved.\n"
          "Legacy commands explicitly allow unauthenticated CBC: padding cannot prove\n"
          "the password or integrity. Check recovered content and re-encrypt it.\n",
          stream);
}

#ifdef _WIN32
static HANDLE password_console;
static DWORD saved_console_mode;
static volatile LONG console_echo_disabled;

static BOOL WINAPI password_console_signal(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT ||
        event == CTRL_LOGOFF_EVENT || event == CTRL_SHUTDOWN_EVENT) {
        if (InterlockedCompareExchange(&console_echo_disabled, 0, 0))
            SetConsoleMode(password_console, saved_console_mode);
    }
    /* Let the normal process termination handler run after echo is restored. */
    return FALSE;
}
#else
static struct termios saved_terminal;
static volatile sig_atomic_t echo_disabled;

static void password_signal(int signum) {
    if (echo_disabled)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_terminal);
    _exit(128 + signum);
}
#endif

/* Piped input is supported for scripts without putting a secret in argv.
 * Terminal echo is restored after reads, failures, and POSIX termination signals. */
static int read_password(char *buffer, size_t capacity) {
    int terminal = isatty(STDIN_FILENO);
#ifdef _WIN32
    HANDLE console = GetStdHandle(STD_INPUT_HANDLE);
    DWORD previous_mode = 0;
#else
    struct sigaction previous_int, previous_term, previous_hup;
#endif
    if (terminal) {
#ifdef _WIN32
        if (!GetConsoleMode(console, &previous_mode)) {
            fputs("Cannot disable terminal echo for password input.\n", stderr);
            return 0;
        }
        password_console = console;
        saved_console_mode = previous_mode;
        if (!SetConsoleCtrlHandler(password_console_signal, TRUE)) {
            fputs("Cannot protect terminal echo settings.\n", stderr);
            return 0;
        }
        InterlockedExchange(&console_echo_disabled, 1);
        if (!SetConsoleMode(console, previous_mode & ~ENABLE_ECHO_INPUT)) {
            InterlockedExchange(&console_echo_disabled, 0);
            SetConsoleCtrlHandler(password_console_signal, FALSE);
            fputs("Cannot disable terminal echo for password input.\n", stderr);
            return 0;
        }
#else
        if (tcgetattr(STDIN_FILENO, &saved_terminal) != 0) {
            fputs("Cannot inspect terminal echo settings.\n", stderr);
            return 0;
        }
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = password_signal;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, &previous_int) != 0)
            return 0;
        if (sigaction(SIGTERM, &action, &previous_term) != 0) {
            sigaction(SIGINT, &previous_int, NULL);
            return 0;
        }
        if (sigaction(SIGHUP, &action, &previous_hup) != 0) {
            sigaction(SIGINT, &previous_int, NULL);
            sigaction(SIGTERM, &previous_term, NULL);
            return 0;
        }
        struct termios hidden = saved_terminal;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        echo_disabled = 1;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) {
            echo_disabled = 0;
            sigaction(SIGINT, &previous_int, NULL);
            sigaction(SIGTERM, &previous_term, NULL);
            sigaction(SIGHUP, &previous_hup, NULL);
            fputs("Cannot disable terminal echo for password input.\n", stderr);
            return 0;
        }
#endif
        fputs("Password: ", stderr);
        fflush(stderr);
    }
    char *read = fgets(buffer, (int)capacity, stdin);
    int restored = 1;
    if (terminal) {
#ifdef _WIN32
        restored = SetConsoleMode(console, previous_mode) != 0;
        InterlockedExchange(&console_echo_disabled, 0);
        SetConsoleCtrlHandler(password_console_signal, FALSE);
#else
        restored = tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_terminal) == 0;
        echo_disabled = 0;
        sigaction(SIGINT, &previous_int, NULL);
        sigaction(SIGTERM, &previous_term, NULL);
        sigaction(SIGHUP, &previous_hup, NULL);
#endif
        fputc('\n', stderr);
    }
    if (!restored) {
        fputs("Cannot restore terminal echo settings.\n", stderr);
        return 0;
    }
    if (!read) {
        fputs("Cannot read a password from standard input.\n", stderr);
        return 0;
    }
    size_t len = strlen(buffer);
    if (len && buffer[len - 1] == '\n')
        buffer[--len] = '\0';
    else if (!feof(stdin)) {
        fputs("The password exceeds the supported input length.\n", stderr);
        return 0;
    }
    if (len && buffer[len - 1] == '\r')
        buffer[--len] = '\0';
    if (!len) {
        fputs("The password must not be empty.\n", stderr);
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc == 2 && !strcmp(argv[1], "--help")) {
        print_usage(stdout);
        return EXIT_SUCCESS;
    }
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("Secure File Manager 2.0 (C / GTK3 / OpenSSL)");
        return EXIT_SUCCESS;
    }
    if (argc < 2) {
        print_usage(stderr);
        return EXIT_FAILURE;
    }
    const char *command = argv[1];
    int required = 0, password_index = 0;
    if (!strcmp(command, "encrypt") || !strcmp(command, "decrypt") ||
        !strcmp(command, "retrieve") || !strcmp(command, "decrypt-legacy") ||
        !strcmp(command, "retrieve-legacy")) {
        required = 5;
        password_index = 4;
    } else if (!strcmp(command, "add") || !strcmp(command, "delete") ||
               !strcmp(command, "delete-legacy")) {
        required = 4;
        password_index = 3;
    } else if (!strcmp(command, "list"))
        required = 2;
    else if (!strcmp(command, "hash"))
        required = 4;
    else if (!strcmp(command, "verify"))
        required = 5;
    else {
        fprintf(stderr, "Unknown command: %s\n\n", command);
        print_usage(stderr);
        return EXIT_FAILURE;
    }
    if (argc != required) {
        fprintf(stderr, "Incorrect arguments for '%s'.\n\n", command);
        print_usage(stderr);
        return EXIT_FAILURE;
    }
    char password_buffer[PASSWORD_CAPACITY] = {0};
    const char *password = password_index ? argv[password_index] : NULL;
    if (password && !strcmp(password, "-")) {
        if (!read_password(password_buffer, sizeof(password_buffer))) {
            OPENSSL_cleanse(password_buffer, sizeof(password_buffer));
            return EXIT_FAILURE;
        }
        password = password_buffer;
    }
    int result;
    if (!strcmp(command, "encrypt"))
        result = handle_file_encryption(argv[2], argv[3], password);
    else if (!strcmp(command, "decrypt"))
        result = handle_file_decryption(argv[2], argv[3], password);
    else if (!strcmp(command, "decrypt-legacy")) {
        fputs("Warning: legacy CBC cannot authenticate the password or file contents.\n", stderr);
        result = handle_legacy_file_decryption(argv[2], argv[3], password);
    } else if (!strcmp(command, "add"))
        result = add_file_to_vault(argv[2], password);
    else if (!strcmp(command, "retrieve"))
        result = retrieve_file_from_vault(argv[2], argv[3], password);
    else if (!strcmp(command, "retrieve-legacy")) {
        fputs("Warning: legacy CBC cannot authenticate the password or file contents.\n", stderr);
        result = retrieve_legacy_file_from_vault(argv[2], argv[3], password);
    } else if (!strcmp(command, "delete"))
        result = delete_file_from_vault(argv[2], password);
    else if (!strcmp(command, "delete-legacy")) {
        fputs("Warning: legacy CBC cannot authenticate the password or file contents.\n", stderr);
        result = delete_legacy_file_from_vault(argv[2], password);
    } else if (!strcmp(command, "list"))
        result = list_vault_files();
    else if (!strcmp(command, "hash"))
        result = handle_file_hashing(argv[2], argv[3]);
    else
        result = handle_file_verification(argv[2], argv[3], argv[4]);
    OPENSSL_cleanse(password_buffer, sizeof(password_buffer));
    if (!result) {
        fprintf(stderr, "Error: %s\n", vault_last_error());
        return EXIT_FAILURE;
    }
    if (!strcmp(command, "verify"))
        puts("Checksum verified.");
    else if (password_index)
        printf("%s completed successfully.\n", command);
    return EXIT_SUCCESS;
}
