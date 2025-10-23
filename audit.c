#include <time.h>
#include <string.h>
#include <unistd.h> 
#include <stdio.h>
#include "audit.h"
#include "crypto.h"

#define AUDIT_LOG "audit.log"
#define AUDIT_ENC "audit.enc"

// Use the runtime-generated AES key and IV from session.c
extern unsigned char AES_KEY[32];
extern unsigned char AES_IV[16];

void log_event(const char *username, const char *role,
               const char *action, const char *status,
               const char *token) {
    // Step 1: Write plaintext log (temporary)
    FILE *fp = fopen(AUDIT_LOG, "a");
    if (!fp) return;

    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strcspn(ts, "\n")] = 0; // remove newline

    fprintf(fp, "[%s] User: %s | Role: %s | Token: %s | Action: %s | Status: %s\n",
            ts, username, role, token ? token : "N/A", action, status);
    fclose(fp);

    // Step 2: Encrypt audit.log → audit.enc using runtime AES key/IV
    if (encrypt_file(AUDIT_LOG, AUDIT_ENC, AES_KEY, AES_IV)) {
        // Step 3: Delete plaintext log for security
        unlink(AUDIT_LOG);
    } else {
        fprintf(stderr, "Warning: Failed to encrypt audit log\n");
    }
}


