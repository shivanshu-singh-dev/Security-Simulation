#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int derive_key_from_password(const char *password, unsigned char *key) {
    // Simple key derivation using SHA256 (for demo purposes)
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;

    if (!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) return 0;
    EVP_DigestUpdate(mdctx, password, strlen(password));
    unsigned int len = 0;
    EVP_DigestFinal_ex(mdctx, key, &len);
    EVP_MD_CTX_free(mdctx);
    return 1;
}

void generate_aes_key_iv(unsigned char *key, unsigned char *iv) {
    if (!RAND_bytes(key, 32)) { // 256-bit key
        fprintf(stderr, "[ERROR] AES key generation failed\n");
        exit(1);
    }
    if (!RAND_bytes(iv, 16)) {  // 128-bit IV
        fprintf(stderr, "[ERROR] AES IV generation failed\n");
        exit(1);
    }
}

int encrypt_file(const char *input_path, const char *output_path,
                 const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "wb");
    if (!in || !out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}

int decrypt_file(const char *input_path, const char *output_path,
                 const unsigned char *key, const unsigned char *iv) {
    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "wb");
    if (!in || !out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024], outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}


