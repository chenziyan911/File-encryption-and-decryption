#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "filecryptHead.h"

int main(int argc, char *argv[]) {
    // Enforce correct argument sizes matching professional tool layout syntax
    if (argc != 4) {
        fprintf(stderr, "Usage:   %s <mode (-e|-d)> <input_file> <output_file>\n", argv[0]);
        fprintf(stderr, "Encrypt: %s -e plain.txt secure.enc\n", argv[0]);
        fprintf(stderr, "Decrypt: %s -d secure.enc recovered.txt\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *mode = argv[1];
    const char *input_file = argv[2];
    const char *output_file = argv[3];
    char password[1024];

    // Interactively capture password to safeguard local shell history logs
    printf("Enter password: ");
    fflush(stdout); //forces any text waiting in the output buffer to be written to the screen immediately.
    if (fgets(password, sizeof(password), stdin) == NULL) {
        fprintf(stderr, "Error reading password input.\n");
        return EXIT_FAILURE;
    }
    password[strcspn(password, "\r\n")] = '\0';

    if (password[0] == '\0') {
        fprintf(stderr, "Error: Password input string cannot be blank.\n");
        return EXIT_FAILURE;
    }

    int outcome = 0;
    if (strcmp(mode, "-e") == 0) {
        outcome = encrypt_file(input_file, output_file, password);
    } else if (strcmp(mode, "-d") == 0) {
        outcome = decrypt_file(input_file, output_file, password);
    } else {
        fprintf(stderr, "Error: Invalid mode configuration flag '%s'. Use -e or -d.\n", mode);
        OPENSSL_cleanse(password, sizeof(password));
        return EXIT_FAILURE;
    }

    OPENSSL_cleanse(password, sizeof(password));

    if (outcome) {
        printf("Operation executed successfully.\n");
        return EXIT_SUCCESS;
    } else {
        fprintf(stderr, "Operation execution dropped critical failure fault.\n");
        return EXIT_FAILURE;
    }
}
