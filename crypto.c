// compile with: gcc -c crypto.c -o crypto.o -lcrypto
#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* global storage (single definition) */
unsigned char AES_KEY[AES_KEY_SIZE];
unsigned char AES_IV[AES_IV_SIZE];
static int aes_initialized = 0;
#define AES_CONFIG_FILE "aes_config.bin"

/* helper: print OpenSSL errors and return 0 */
static int _openssl_err(const char *msg) {
    fprintf(stderr, "[crypto] %s\n", msg);
    ERR_print_errors_fp(stderr);
    return 0;
}

/* Save AES key and IV to a file */
static int save_aes_key_iv() {
    FILE *fp = fopen(AES_CONFIG_FILE, "wb");
    if (!fp) {
        perror("[crypto] fopen save_aes_key_iv");
        return 0;
    }
    if (fwrite(AES_KEY, 1, AES_KEY_SIZE, fp) != AES_KEY_SIZE) {
        perror("[crypto] fwrite key");
        fclose(fp);
        return 0;
    }
    if (fwrite(AES_IV, 1, AES_IV_SIZE, fp) != AES_IV_SIZE) {
        perror("[crypto] fwrite iv");
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

/* Load AES key and IV from file if exists */
static int load_aes_key_iv() {
    FILE *fp = fopen(AES_CONFIG_FILE, "rb");
    if (!fp) return 0; // file doesn’t exist
    if (fread(AES_KEY, 1, AES_KEY_SIZE, fp) != AES_KEY_SIZE) {
        fclose(fp);
        return 0;
    }
    if (fread(AES_IV, 1, AES_IV_SIZE, fp) != AES_IV_SIZE) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

/* Initialize AES key and IV — persistent version */
int init_aes_key_iv() {
    if (aes_initialized) return 1;
    if (load_aes_key_iv()) {
        aes_initialized = 1;
        fprintf(stderr, "[crypto] AES key/IV loaded from %s\n", AES_CONFIG_FILE);
        return 1;
    }

    // Generate new key and IV
    if (RAND_bytes(AES_KEY, AES_KEY_SIZE) != 1) {
        _openssl_err("RAND_bytes(key) failed");
        return 0;
    }
    if (RAND_bytes(AES_IV, AES_IV_SIZE) != 1) {
        _openssl_err("RAND_bytes(iv) failed");
        return 0;
    }
    if (!save_aes_key_iv()) {
        fprintf(stderr, "[crypto] Failed to save AES key/IV to file\n");
        return 0;
    }

    aes_initialized = 1;
    fprintf(stderr, "[crypto] AES key/IV generated and saved to %s\n", AES_CONFIG_FILE);
    return 1;
}

/* Encrypt file */
int encrypt_file(const char *input_path, const char *output_path,
                 const unsigned char *key, const unsigned char *iv) {
    FILE *in = NULL, *out = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    int success = 0;

    if (!input_path || !output_path || !key || !iv) return 0;
    in = fopen(input_path, "rb");
    if (!in) { perror("[crypto] fopen input"); goto cleanup; }
    out = fopen(output_path, "wb");
    if (!out) { perror("[crypto] fopen output"); goto cleanup; }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { _openssl_err("EVP_CIPHER_CTX_new failed"); goto cleanup; }

    fprintf(stderr, "[DEBUG] Encrypting '%s' with AES_KEY=%p AES_IV=%p\n", input_path, key, iv);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        goto err;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) goto err;
        fwrite(outbuf, 1, outlen, out);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) goto err;
    fwrite(outbuf, 1, outlen, out);
    success = 1;
    goto cleanup;

err:
    _openssl_err("encrypt_file failed");
cleanup:
    if (in) fclose(in);
    if (out) fclose(out);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return success;
}

/* Decrypt file */
int decrypt_file(const char *input_path, const char *output_path,
                 const unsigned char *key, const unsigned char *iv) {
    FILE *in = NULL, *out = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    int success = 0;

    if (!input_path || !output_path || !key || !iv) return 0;
    in = fopen(input_path, "rb");
    if (!in) { perror("[crypto] fopen input"); goto cleanup; }
    out = fopen(output_path, "wb");
    if (!out) { perror("[crypto] fopen output"); goto cleanup; }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { _openssl_err("EVP_CIPHER_CTX_new failed"); goto cleanup; }

    fprintf(stderr, "[DEBUG] Decrypting '%s' with AES_KEY=%p AES_IV=%p\n", input_path, key, iv);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        goto err;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) goto err;
        fwrite(outbuf, 1, outlen, out);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        _openssl_err("EVP_DecryptFinal_ex failed (bad key/iv or corrupted file)");
        goto cleanup;
    }

    fwrite(outbuf, 1, outlen, out);
    success = 1;
    goto cleanup;

err:
    _openssl_err("decrypt_file failed");
cleanup:
    if (in) fclose(in);
    if (out) fclose(out);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return success;
}

/* Derive a 32-byte key from password (optional helper) */
int derive_key_from_password(const char *password, unsigned char *out_key) {
    if (!password || !out_key) return 0;
    const unsigned char salt[] = "os_security_salt";
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                          salt, sizeof(salt),
                          100000, EVP_sha256(), AES_KEY_SIZE, out_key) != 1) {
        _openssl_err("PKCS5_PBKDF2_HMAC failed");
        return 0;
    }
    return 1;
}

