#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

int encrypt_file(const char *input_path, const char *output_path,
                 const unsigned char *key, const unsigned char *iv);

int decrypt_file(const char *input_path, const char *output_path,
                 const unsigned char *key, const unsigned char *iv);

int derive_key_from_password(const char *password, unsigned char *key);

void generate_aes_key_iv(unsigned char *key, unsigned char *iv);

#endif




