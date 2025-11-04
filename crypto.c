#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>

#include "crypto.h"

#define KEY_FILE "key.bin"
#define KEY_SIZE 32
#define IV_SIZE 16

// Generate key file once
void generate_key_file() {
    FILE *fp = fopen(KEY_FILE, "rb");
    if (fp) { fclose(fp); return; } // already exists

    unsigned char key[KEY_SIZE];
    if (!RAND_bytes(key, KEY_SIZE)) {
        fprintf(stderr, "Key generation failed.\n");
        return;
    }

    fp = fopen(KEY_FILE, "wb");
    fwrite(key, 1, KEY_SIZE, fp);
    fclose(fp);
    chmod(KEY_FILE, 0400);
}

// Load key from file
int load_key(unsigned char *key) {
    FILE *fp = fopen(KEY_FILE, "rb");
    if (!fp) {
        fprintf(stderr, "Key file not found. Run generate_key_file() first.\n");
        return 1;
    }
    fread(key, 1, KEY_SIZE, fp);
    fclose(fp);
    return 0;
}

// Encrypt file
int encrypt_file(const char *infile, const char *outfile) {
    generate_key_file();

    FILE *in = fopen(infile, "rb");
    if (!in) { perror("Input open"); return 1; }

    FILE *out = fopen(outfile, "wb");
    if (!out) { perror("Output open"); fclose(in); return 1; }

    unsigned char key[KEY_SIZE];
    if (load_key(key)) { fclose(in); fclose(out); return 1; }

    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);
    fwrite(iv, 1, IV_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[4096], outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
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
    memset(key, 0, KEY_SIZE);
    memset(iv, 0, IV_SIZE);
    return 0;
}

// Decrypt file
int decrypt_file(const char *infile, const char *outfile) {
    FILE *in = fopen(infile, "rb");
    if (!in) { perror("Input open"); return 1; }

    FILE *out = fopen(outfile, "wb");
    if (!out) { perror("Output open"); fclose(in); return 1; }

    unsigned char key[KEY_SIZE], iv[IV_SIZE];
    if (load_key(key)) { fclose(in); fclose(out); return 1; }

    fread(iv, 1, IV_SIZE, in);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[4096], outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
    }

    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        fprintf(stderr, "❌ Decryption failed (wrong key or corrupted file).\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        remove(outfile);
        return 1;
    }

    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    memset(key, 0, KEY_SIZE);
    memset(iv, 0, IV_SIZE);
    return 0;
}

int ensure_decrypted(const char *logfile, const char *encfile) {
    struct stat s_plain, s_enc;
    if (stat(encfile, &s_enc) == 0) {
        // Encrypted version exists, decrypt it
        if (decrypt_file(encfile, logfile) == 0) {
            remove(encfile);
            return 0;
        } else {
            fprintf(stderr, "Decryption failed for %s\n", encfile);
            return -1;
        }
    }
    return 0; // Already plaintext
}

int ensure_encrypted(const char *logfile, const char *encfile) {
    struct stat s_plain;
    if (stat(logfile, &s_plain) == 0) {
        // Plain exists, encrypt and remove
        if (encrypt_file(logfile, encfile) == 0) {
            remove(logfile);
            return 0;
        } else {
            fprintf(stderr, "Encryption failed for %s\n", logfile);
            return -1;
        }
    }
    return 0;
}
