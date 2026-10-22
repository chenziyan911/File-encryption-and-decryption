#ifndef FILECRYPT_H
#define FILECRYPT_H

#include <stddef.h>

#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32        // 256-bit AES Key
#define MAC_KEY_LEN 32    // 256-bit HMAC Key
#define HMAC_LEN 32       // SHA-256 Tag Size
#define BUFFER_SIZE 4096

// Core Block Engines
void xor_block(const unsigned char *a, const unsigned char *b, unsigned char *out);
int aes_encrypt_block(const unsigned char *key, const unsigned char *input, unsigned char *output);
int aes_decrypt_block(const unsigned char *key, const unsigned char *ciphertext, unsigned char *plaintext);

int cbc_encrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, size_t length, unsigned char *ciphertext);
int cbc_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, size_t length, unsigned char *plaintext);

// Secure File Operations
int encrypt_file(const char *input_filename, const char *output_filename, const char *password);
int decrypt_file(const char *input_filename, const char *output_filename, const char *password);

// Dummy Dependency stubs (Replace with your actual project implementations)
int generate_salt(unsigned char *salt, size_t len);
int generate_iv(unsigned char *iv, size_t len);
int derive_key(const char *password, const unsigned char *salt, unsigned char *enc_key, unsigned char *mac_key);

#endif
