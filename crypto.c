#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "sha256.h"
#include <time.h>
#include <sys/stat.h>

#include "crypto.h"

#define KEY_FILE "key.bin"
#define KEY_SIZE 32
#define IV_SIZE 16

static void get_random_bytes(unsigned char *buf, size_t len) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)(time(NULL)));
        seeded = 1;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() & 0xFF;
    }
}

// Generate key file once
void generate_key_file() {
    FILE *fp = fopen(KEY_FILE, "rb");
    if (fp) { fclose(fp); return; } // already exists

    unsigned char key[KEY_SIZE];
    get_random_bytes(key, KEY_SIZE);

    fp = fopen(KEY_FILE, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to create key file.\n");
        return;
    }
    fwrite(key, 1, KEY_SIZE, fp);
    fclose(fp);
#ifdef _WIN32
    chmod(KEY_FILE, S_IREAD);
#else
    chmod(KEY_FILE, 0400);
#endif
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
    get_random_bytes(iv, IV_SIZE);
    fwrite(iv, 1, IV_SIZE, out);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    unsigned char inbuf[4096];
    size_t nread;

    while ((nread = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (feof(in) || nread < sizeof(inbuf)) {
            size_t pad_len = 16 - (nread % 16);
            for (size_t i = 0; i < pad_len; i++) {
                inbuf[nread + i] = (unsigned char)pad_len;
            }
            size_t total_len = nread + pad_len;
            AES_CBC_encrypt_buffer(&ctx, inbuf, total_len);
            fwrite(inbuf, 1, total_len, out);
            nread = 0; // mark done
            break;
        } else {
            int next_ch = fgetc(in);
            if (next_ch == EOF) {
                AES_CBC_encrypt_buffer(&ctx, inbuf, nread);
                fwrite(inbuf, 1, nread, out);

                unsigned char pad_block[16];
                memset(pad_block, 16, 16);
                AES_CBC_encrypt_buffer(&ctx, pad_block, 16);
                fwrite(pad_block, 1, 16, out);
                break;
            } else {
                ungetc(next_ch, in);
                AES_CBC_encrypt_buffer(&ctx, inbuf, nread);
                fwrite(inbuf, 1, nread, out);
            }
        }
    }

    if (nread == 0 && !feof(in)) {
        // Handle empty file padding
        unsigned char pad_block[16];
        memset(pad_block, 16, 16);
        AES_CBC_encrypt_buffer(&ctx, pad_block, 16);
        fwrite(pad_block, 1, 16, out);
    }

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

    if (fread(iv, 1, IV_SIZE, in) != IV_SIZE) {
        fprintf(stderr, "Invalid encrypted file (missing IV).\n");
        fclose(in); fclose(out); return 1;
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);

    unsigned char buffer[4096];
    size_t buffered_len = fread(buffer, 1, sizeof(buffer), in);

    if (buffered_len > 0) {
        if (buffered_len % 16 != 0) {
            fprintf(stderr, "Ciphertext size is not a multiple of 16.\n");
            fclose(in); fclose(out); remove(outfile); return 1;
        }
        AES_CBC_decrypt_buffer(&ctx, buffer, buffered_len);

        while (1) {
            unsigned char next_buf[4096];
            size_t next_len = fread(next_buf, 1, sizeof(next_buf), in);
            if (next_len == 0) {
                unsigned char pad_val = buffer[buffered_len - 1];
                if (pad_val < 1 || pad_val > 16 || pad_val > buffered_len) {
                    fprintf(stderr, "Decryption failed (bad padding).\n");
                    fclose(in); fclose(out); remove(outfile); return 1;
                }
                for (size_t i = 1; i <= pad_val; i++) {
                    if (buffer[buffered_len - i] != pad_val) {
                        fprintf(stderr, "Decryption failed (bad padding bytes).\n");
                        fclose(in); fclose(out); remove(outfile); return 1;
                    }
                }
                fwrite(buffer, 1, buffered_len - pad_val, out);
                break;
            } else {
                if (next_len % 16 != 0) {
                    fprintf(stderr, "Ciphertext size is not a multiple of 16.\n");
                    fclose(in); fclose(out); remove(outfile); return 1;
                }
                fwrite(buffer, 1, buffered_len, out);
                AES_CBC_decrypt_buffer(&ctx, next_buf, next_len);
                memcpy(buffer, next_buf, next_len);
                buffered_len = next_len;
            }
        }
    } else {
        fprintf(stderr, "Empty encrypted file.\n");
        fclose(in); fclose(out); remove(outfile); return 1;
    }

    fclose(in);
    fclose(out);
    memset(key, 0, KEY_SIZE);
    memset(iv, 0, IV_SIZE);
    return 0;
}

int ensure_decrypted(const char *logfile, const char *encfile) {
    struct stat s_enc;
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
    return 0;
}

int ensure_encrypted(const char *logfile, const char *encfile) {
    struct stat s_plain;
    if (stat(logfile, &s_plain) == 0) {
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
