#ifndef CRYPTO_H
#define CRYPTO_H

int encrypt_file(const char *infile, const char *outfile);
int decrypt_file(const char *infile, const char *outfile);
void generate_key_file();
int load_key(unsigned char *key);
int ensure_decrypted(const char *logfile, const char *encfile);
int ensure_encrypted(const char *logfile, const char *encfile);

#endif

