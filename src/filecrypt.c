#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/params.h> 
#include <openssl/core_names.h>
#include "filecryptHead.h"

#define SALT_LEN 16
#define IV_LEN 16
#define KEY_LEN 32
#define BUFFER_SIZE 4096
#define PBKDF2_ITERATIONS 600000 //"key stretching" cost factor to slow down brute-force and offline GPU/ASIC cracking attempts

/*
 * Generate a cryptographically secure random salt.
 */
int generate_salt(unsigned char *salt, size_t salt_len)
{
    if (salt == NULL || salt_len == 0 || salt_len > 2147483647U) {
        fprintf(stderr, "Error: Invalid salt buffer or length.\n"); //print a message to standard error system (stderr)
        return 0;
    }

    if (RAND_bytes(salt, (int)salt_len) != 1) {   //puts salt_len cryptographically strong pseudo-random bytes into salt
        fprintf(stderr, "Error: Failed to generate salt.\n");
        return 0;
    }

    return 1;
}

/*
 * Generate a cryptographically secure random IV.
 */
int generate_iv(unsigned char *iv, size_t iv_len)
{
    if (iv == NULL || iv_len != IV_LEN) {
        fprintf(stderr, "Error: Invalid IV buffer or length.\n");
        return 0;
    }

    if (RAND_bytes(iv, (int)iv_len) != 1) {
        fprintf(stderr, "Error: Failed to generate IV.\n");
        return 0;
    }

    return 1;
}

/*
 * Derive a 256-bit encryption key from the password and salt.
 */
int derive_key(const char *password, const unsigned char *salt, unsigned char *enc_key, unsigned char *mac_key)
{
    if (password == NULL || salt == NULL || enc_key == NULL || mac_key == NULL) {
        fprintf(stderr, "Error: Invalid key derivation arguments.\n");
        return 0;
    }

    if (PKCS5_PBKDF2_HMAC( //tells OpenSSL what password to process, how to process it, and where to store the resulting encryption key.
            password,
            (int)strlen(password),
            salt,
            SALT_LEN,
            PBKDF2_ITERATIONS, //Specifies how many iterations PBKDF2 performs during key derivation.
            EVP_sha256(), //Specifies SHA-256 as the hash algorithm used by HMAC (Hash-based Message Authentication Code) within PBKDF2. 
            //PBKDF2 repeatedly uses HMAC with the supplied password and salt to derive the encryption key.
            //SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash output.
            KEY_LEN,
            enc_key
            ) != 1){

        fprintf(stderr, "Error: PBKDF2 key derivation failed.\n");
        return 0;
    }
    
      if (PKCS5_PBKDF2_HMAC(
            password,
            (int)strlen(password),
            salt,
            SALT_LEN,
            PBKDF2_ITERATIONS,
            EVP_sha256(),
            KEY_LEN,
            mac_key) != 1){ // Fixed: Balanced closing parenthesis correctly here

        fprintf(stderr, "Error: PBKDF2 MAC key derivation failed.\n");
        return 0;
    }

    return 1;
}

int aes_encrypt_block(
    const unsigned char *key, //this function promises not to modify the key.
    const unsigned char *input,
    unsigned char *output)
{
    int out_len1 = 0; //This stores how many bytes were produced by EVP_EncryptUpdate()
    int out_len2 = 0;
    int success = 0;
    
    // Initialise the context pointer to NULL for safe cleanup tracking
    EVP_CIPHER_CTX *ctx = NULL;

    /*
     * 1. Validate key, input and output
     */
    if (key == NULL || input == NULL || output == NULL) {
        fprintf(stderr, "Error: Invalid key & input & output.\n");
        return 0; // Return failure
    }

    /* 2. Create an EVP_CIPHER_CTX
     */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: Failed to create cipher context.\n");
        return 0;
    } else {
        printf("Cipher context created successfully.\n");
    }   

    /* 3. Initialise it with EVP_aes_256_ecb()
     *   (IV = NULL).
     */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1) {
        fprintf(stderr, "Error: Encryption initialization failed.\n");
        goto cleanup;
    }

    /* 4. Disable padding with EVP_CIPHER_CTX_set_padding(ctx, 0)
     */
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        fprintf(stderr, "Error: Disable padding failed.\n");
        goto cleanup;
    } 

    /* 5. Encrypt exactly 16 bytes
     */
    if (EVP_EncryptUpdate(ctx, output, &out_len1, input, 16) != 1) {
        fprintf(stderr, "Error: Encryption update failed.\n");
        goto cleanup;
    }
    if (EVP_EncryptFinal_ex(ctx, output + out_len1, &out_len2) != 1) {
        fprintf(stderr, "Error: Encryption finalization failed.\n");
        goto cleanup;
    }

    /* 6. Check that exactly 16 bytes were produced
     */
    if ((out_len1 + out_len2) == 16) {
        success = 1;
    }

    /* 7. Free the context
     */
cleanup:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    /* 8. Return success/failure
     */
    return success;
}

int aes_decrypt_block(
    const unsigned char *key,
    const unsigned char *ciphertext,
    unsigned char *plaintext)
{
    int out_len1 = 0;
    int out_len2 = 0;
    int success = 0;
    
    // Initialise pointer to NULL for safe cleanup tracking
    EVP_CIPHER_CTX *ctx = NULL;

    /* 1. Validate the pointers */
    if (key == NULL || ciphertext == NULL || plaintext == NULL) {
        fprintf(stderr, "Error: Invalid key, ciphertext, or plaintext pointer.\n");
        return 0; 
    }

    /* 2. Create an EVP_CIPHER_CTX context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: Failed to create cipher context.\n");
        return 0;
    }

    /* 3. Initialise the permitted AES-256-ECB decryption operation */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1) {
        fprintf(stderr, "Error: Decryption initialization failed.\n");
        goto cleanup;
    }

    /* 4. Disable padding using EVP_CIPHER_CTX_set_padding(ctx, 0) */
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        fprintf(stderr, "Error: Disable padding failed.\n");
        goto cleanup;
    } 

    /* 5. Decrypt exactly 16 bytes */
    if (EVP_DecryptUpdate(ctx, plaintext, &out_len1, ciphertext, 16) != 1) {
        fprintf(stderr, "Error: Decryption update failed.\n");
        goto cleanup;
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len1, &out_len2) != 1) {
        fprintf(stderr, "Error: Decryption finalization failed.\n");
        goto cleanup;
    }

    /* 6. Verify that exactly 16 bytes were produced */
    if ((out_len1 + out_len2) == 16) {
        success = 1;
    } else {
        fprintf(stderr, "Error: Decrypted byte count mismatch (%d bytes).\n", (out_len1 + out_len2));
    }

    /* 7. Free the context and return success or failure */
cleanup:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return success;
}

// CBC processing helpers
//This helper function takes two 16-byte blocks, XORs them bitwise, and stores the result in an output block.
void xor_block(
    const unsigned char *a,
    const unsigned char *b,
    unsigned char *out)
{
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/*In CBC encryption, each plaintext block is XORed with the previous ciphertext block (or the IV for the first block) 
before being run through the single-block AES engine.*/
int cbc_encrypt(
    const unsigned char *key,
    const unsigned char *iv,
    const unsigned char *plaintext,
    size_t length,
    unsigned char *ciphertext)
{
    // Ensure length is a strict multiple of the 16-byte block size
    if (length == 0 || length % 16 != 0) {
        fprintf(stderr, "Error: CBC plaintext length must be a multiple of 16.\n");
        return 0;
    }
    if (key == NULL || iv == NULL || plaintext == NULL || ciphertext == NULL) {
        return 0;
    }

    size_t num_blocks = length / 16;
    const unsigned char *current_iv = iv;

    for (size_t i = 0; i < num_blocks; i++) {
        unsigned char xor_temp[16];
        
        // 1. XOR the plaintext block with the current IV (or previous ciphertext block)
        xor_block(plaintext + (i * 16), current_iv, xor_temp);
        
        // 2. Encrypt the XORed result using your block function
        if (aes_encrypt_block(key, xor_temp, ciphertext + (i * 16)) != 1) {
            fprintf(stderr, "Error: Block encryption failed at block %zu.\n", i);
            return 0;
        }
        
        // 3. The current ciphertext block becomes the IV for the next block
        current_iv = ciphertext + (i * 16);
    }

    return 1; // Success
}

/*In CBC decryption, the ciphertext block is first passed through the single-block AES decryption engine.
 The resulting intermediate state is then XORed with the previous ciphertext block (or the IV for the first block) to reveal the plaintext. */
int cbc_decrypt(
    const unsigned char *key,
    const unsigned char *iv,
    const unsigned char *ciphertext,
    size_t length,
    unsigned char *plaintext)
{
    // Ensure length is a strict multiple of the 16-byte block size
    if (length == 0 || length % 16 != 0) {
        fprintf(stderr, "Error: CBC ciphertext length must be a multiple of 16.\n");
        return 0;
    }
    if (key == NULL || iv == NULL || ciphertext == NULL || plaintext == NULL) {
        return 0;
    }

    size_t num_blocks = length / 16;
    const unsigned char *current_iv = iv;

    for (size_t i = 0; i < num_blocks; i++) {
        unsigned char decrypt_temp[16];
        const unsigned char *current_cipher_block = ciphertext + (i * 16);
        
        // 1. Decrypt the raw ciphertext block using your block function
        if (aes_decrypt_block(key, current_cipher_block, decrypt_temp) != 1) {
            fprintf(stderr, "Error: Block decryption failed at block %zu.\n", i);
            return 0;
        }
        
        // 2. XOR the decrypted intermediate state with the previous block's ciphertext (or IV)
        xor_block(decrypt_temp, current_iv, plaintext + (i * 16));
        
        // 3. The current ciphertext block becomes the IV context for the next block
        current_iv = current_cipher_block;
    }

    return 1; // Success
}

/*
 * Encrypt a file using AES-256-CBC.
 *
 * Output file format:
 * [16-byte salt][16-byte IV][ciphertext]
 */
/* ==========================================
 * 1. ENCRYPT FILE (Encrypt-then-MAC via OpenSSL 3.0 EVP_MAC)
 * ========================================== */
int encrypt_file(const char *input_filename, const char *output_filename, const char *password) {
    FILE *input = NULL, *output = NULL;
    unsigned char salt[SALT_LEN], iv[IV_LEN];
    unsigned char enc_key[KEY_LEN], mac_key[MAC_KEY_LEN];
    unsigned char inbuf[BUFFER_SIZE + 16], outbuf[BUFFER_SIZE + 16];
    unsigned char hmac_tag[HMAC_LEN];
    
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *hmac_ctx = NULL;
    size_t bytes_read;
    size_t hmac_out_len = 0;
    int success = 0;
    
     OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 7),
        OSSL_PARAM_END
    };

    input = fopen(input_filename, "rb");
    output = fopen(output_filename, "wb");
    if (!input || !output) { perror("File opening failed"); goto cleanup; }

    if (!generate_salt(salt, sizeof(salt)) || !generate_iv(iv, sizeof(iv))) goto cleanup;
    if (!derive_key(password, salt, enc_key, mac_key)) goto cleanup;

    // Write Salt and IV headers (Metadata)
    if (fwrite(salt, 1, SALT_LEN, output) != SALT_LEN || fwrite(iv, 1, IV_LEN, output) != IV_LEN) goto cleanup;

        // OpenSSL 3.0 EVP_MAC Context Initialization
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) goto cleanup;
    hmac_ctx = EVP_MAC_CTX_new(mac);
    if (!hmac_ctx) goto cleanup;

    // structure the OSSL_PARAM array parameters
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(hmac_ctx, mac_key, MAC_KEY_LEN, params) != 1) goto cleanup;


    // Authenticate Metadata (Salt + IV)
    EVP_MAC_update(hmac_ctx, salt, SALT_LEN);
    EVP_MAC_update(hmac_ctx, iv, IV_LEN);

    unsigned char current_iv[IV_LEN];
    memcpy(current_iv, iv, IV_LEN);

    while ((bytes_read = fread(inbuf, 1, BUFFER_SIZE, input)) > 0) {
        size_t block_aligned_len;
        int next_char = fgetc(input);

        if (next_char == EOF) { // Final Block: Apply PKCS#7 Padding
            size_t padding_needed = 16 - (bytes_read % 16);
            for (size_t i = 0; i < padding_needed; i++) inbuf[bytes_read + i] = (unsigned char)padding_needed;
            block_aligned_len = bytes_read + padding_needed;
        } else {
            ungetc(next_char, input);
            block_aligned_len = bytes_read;
        }

        // Encrypt with custom CBC function
        if (!cbc_encrypt(enc_key, current_iv, inbuf, block_aligned_len, outbuf)) goto cleanup;

        // Authenticate the Ciphertext (Encrypt-then-MAC)
        EVP_MAC_update(hmac_ctx, outbuf, block_aligned_len);

        if (fwrite(outbuf, 1, block_aligned_len, output) != block_aligned_len) goto cleanup;
        memcpy(current_iv, outbuf + block_aligned_len - 16, 16);
    }

    // Finalize HMAC Tag calculations and write tag to the tail of file
    if (EVP_MAC_final(hmac_ctx, hmac_tag, &hmac_out_len, sizeof(hmac_tag)) != 1) goto cleanup;
    if (fwrite(hmac_tag, 1, HMAC_LEN, output) != HMAC_LEN) goto cleanup;

    success = 1;

cleanup:
    if (input) fclose(input);
    if (output) fclose(output);
    if (hmac_ctx) EVP_MAC_CTX_free(hmac_ctx);
    if (mac) EVP_MAC_free(mac);
    OPENSSL_cleanse(enc_key, KEY_LEN);
    OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
    return success;
}

/* ==========================================
 * 2. DECRYPT FILE (Verify-then-Decrypt via OpenSSL 3.0 EVP_MAC)
 * ========================================== */
int decrypt_file(const char *input_filename, const char *output_filename, const char *password) {
    FILE *input = NULL, *output = NULL;
    unsigned char salt[SALT_LEN], iv[IV_LEN];
    unsigned char enc_key[KEY_LEN], mac_key[MAC_KEY_LEN];
    unsigned char computed_tag[HMAC_LEN], file_tag[HMAC_LEN];
    
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *hmac_ctx = NULL;
    size_t hmac_out_len = 0;
    int success = 0;
    
     OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", "SHA256", 7),
        OSSL_PARAM_END
    };

    input = fopen(input_filename, "rb");
    if (!input) { perror("Error opening ciphertext file"); return 0; }

    // Read metadata headers
    if (fread(salt, 1, SALT_LEN, input) != SALT_LEN || fread(iv, 1, IV_LEN, input) != IV_LEN) goto cleanup;
    if (!derive_key(password, salt, enc_key, mac_key)) goto cleanup;

    // Determine ciphertext length dynamically to exclude trailing 32-byte MAC tag
    fseek(input, 0, SEEK_END);
    long file_size = ftell(input);
    long ciphertext_len = file_size - SALT_LEN - IV_LEN - HMAC_LEN;

    if (ciphertext_len <= 0 || ciphertext_len % 16 != 0) {
        fprintf(stderr, "Error: Invalid file format alignment. Tampered or corrupted file.\n");
        goto cleanup;
    }

    // Extract file tag
    fseek(input, file_size - HMAC_LEN, SEEK_SET);
    if (fread(file_tag, 1, HMAC_LEN, input) != HMAC_LEN) goto cleanup;

    // Reset stream to start of ciphertext payload for signature evaluation loop
    fseek(input, SALT_LEN + IV_LEN, SEEK_SET);

        // Initialize modern OpenSSL 3.0 EVP_MAC Engine
    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) goto cleanup;
    hmac_ctx = EVP_MAC_CTX_new(mac);
    if (!hmac_ctx) goto cleanup;

    // FIX: Correctly structure the OSSL_PARAM array parameters
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(hmac_ctx, mac_key, MAC_KEY_LEN, params) != 1) goto cleanup;
    EVP_MAC_update(hmac_ctx, salt, SALT_LEN);
    EVP_MAC_update(hmac_ctx, iv, IV_LEN);

    // Read and verify the entire ciphertext signature into the digest engine
    unsigned char *cipher_buffer = malloc(ciphertext_len);
    if (!cipher_buffer) goto cleanup;
    if (fread(cipher_buffer, 1, ciphertext_len, input) != (size_t)ciphertext_len) { free(cipher_buffer); goto cleanup; }
    
    EVP_MAC_update(hmac_ctx, cipher_buffer, ciphertext_len);
    if (EVP_MAC_final(hmac_ctx, computed_tag, &hmac_out_len, sizeof(computed_tag)) != 1) { free(cipher_buffer); goto cleanup; }

    // Constant-time check to prevent timing attacks
    if (CRYPTO_memcmp(computed_tag, file_tag, HMAC_LEN) != 0) {
        fprintf(stderr, "Error: Integrity validation failed. Wrong password or tampered file.\n");
        free(cipher_buffer);
        goto cleanup;
    }

    // Now that the file signature is verified, it is safe to decrypt and create plaintext output
    output = fopen(output_filename, "wb");
    if (!output) { perror("Error creating output file"); free(cipher_buffer); goto cleanup; }

    unsigned char *plain_buffer = malloc(ciphertext_len);
    if (!plain_buffer) { free(cipher_buffer); goto cleanup; }

    // Run your custom CBC decryption
    if (!cbc_decrypt(enc_key, iv, cipher_buffer, ciphertext_len, plain_buffer)) {
        free(cipher_buffer); free(plain_buffer); goto cleanup;
    }

    // Process manual PKCS#7 unpadding boundaries
    unsigned char pad_value = plain_buffer[ciphertext_len - 1];
    if (pad_value < 1 || pad_value > 16) {
        fprintf(stderr, "Error: Invalid internal block boundaries.\n");
        free(cipher_buffer); free(plain_buffer); goto cleanup;
    }
    for (size_t i = 0; i < pad_value; i++) {
        if (plain_buffer[ciphertext_len - 1 - i] != pad_value) {
            fprintf(stderr, "Error: Padding tracking verification array corruption.\n");
            free(cipher_buffer); free(plain_buffer); goto cleanup;
        }
    }

    size_t clean_plaintext_len = ciphertext_len - pad_value;
    if (clean_plaintext_len > 0) {
        if (fwrite(plain_buffer, 1, clean_plaintext_len, output) != clean_plaintext_len) {
            free(cipher_buffer); free(plain_buffer); goto cleanup;
        }
    }

    free(cipher_buffer);
    free(plain_buffer);
    success = 1;

cleanup:
    if (input) fclose(input);
    if (output) fclose(output);
    if (hmac_ctx) EVP_MAC_CTX_free(hmac_ctx);
    if (mac) EVP_MAC_free(mac);
    OPENSSL_cleanse(enc_key, KEY_LEN);
    OPENSSL_cleanse(mac_key, MAC_KEY_LEN);
    return success;
}