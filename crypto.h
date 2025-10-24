#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

/* Global AES key/IV (defined in crypto.c) */
extern unsigned char AES_KEY[AES_KEY_SIZE];
extern unsigned char AES_IV[AES_IV_SIZE];

/* Generate random AES key + IV */
void generate_aes_key_iv(unsigned char *key, unsigned char *iv);

/* Encrypt a file into output_path using AES-256-CBC (returns 1 on success, 0 on failure) */
int encrypt_file(const char *input_path, const char *output_path,
                 const unsigned char *key, const unsigned char *iv);

/* Decrypt a file into output_path using AES-256-CBC (returns 1 on success, 0 on failure) */
int decrypt_file(const char *input_path, const char *output_path,
                 const unsigned char *key, const unsigned char *iv);

/* Derive a key from a password (optional helper) - returns 1 on success */
int derive_key_from_password(const char *password, unsigned char *out_key);

int init_aes_key_iv();

#endif /* CRYPTO_H */




