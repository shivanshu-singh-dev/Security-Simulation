#include <stdio.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "session.h"
#include "audit.h"

#define SESSION "session.log"

static time_t session_start;
static char current_user[50];
static char current_role[20];
static char current_token[TOKEN_SIZE];   // secure session token

// Utility: Convert raw bytes to hex string
static void to_hex_string(const unsigned char *hash, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[len * 2] = '\0';
}

// Generate a secure session token (username + time + rand + SHA256)
void generate_session_token(const char *username, char *token) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s-%ld-%d",
             username, time(NULL), rand());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buffer, strlen(buffer), hash);

    to_hex_string(hash, SHA256_DIGEST_LENGTH, token);
}

// Validate token against current active token
int validate_session_token(const char *username, const char *token) {
    (void)username; // suppress unused warning
    if (strlen(current_token) == 0) return 0;  // no active session
    return (strcmp(current_token, token) == 0);
}

// Return current session token
const char* get_session_token(void) {
    return current_token;
}

// Start session: log + generate token
void start_session(const char *username, const char *role) {
    session_start = time(NULL);

    // Save for timeout handler
    strncpy(current_user, username, sizeof(current_user));
    strncpy(current_role, role, sizeof(current_role));
    current_user[sizeof(current_user)-1] = '\0';
    current_role[sizeof(current_role)-1] = '\0';

    // Generate session token
    generate_session_token(username, current_token);

    FILE *fp = fopen(SESSION, "a");
    if (!fp) return;

    char *ts = ctime(&session_start);
    ts[strcspn(ts, "\n")] = 0;

    fprintf(fp, "[%s] Session START | User: %s | Role: %s | Token: %s\n",
        ts, username, role, current_token);

    fclose(fp);

    printf("\n[INFO] Secure session started. Token: %s\n", current_token);
}

// End session: log + clear token
void end_session(const char *username, const char *role) {
    time_t session_end = time(NULL);
    double duration = difftime(session_end, session_start);

    FILE *fp = fopen(SESSION, "a");
    if (!fp) return;

    char *ts = ctime(&session_end);
    ts[strcspn(ts, "\n")] = 0;

    fprintf(fp, "[%s] Session END   | User: %s | Role: %s | Token: %s | Duration: %.0f sec\n",
        ts, username, role, current_token, duration);

    fclose(fp);

    memset(current_token, 0, sizeof(current_token)); // clear token
}

// Timeout handler → force logout
static void timeout_handler(int sig) {
    time_t session_end = time(NULL);
    double duration = difftime(session_end, session_start);

    printf("\n[SESSION TIMEOUT] (signal %d) Auto-logout due to inactivity.\n", sig);

    // Audit log
    log_event(current_user, current_role, "Auto Logout", "Session Timeout", current_token);

    // Session log
    FILE *fp = fopen(SESSION, "a");
    if (fp) {
        char *ts = ctime(&session_end);
        ts[strcspn(ts, "\n")] = 0;

        fprintf(fp, "[%s] Session TIMEOUT | User: %s | Role: %s | Token: %s | Duration: %.0f sec\n",
            ts, current_user, current_role, current_token, duration);

        fclose(fp);
    }

    memset(current_token, 0, sizeof(current_token)); // clear token
    exit(0);
}

// Auto logout setup
void auto_logout(const char *username, const char *role, int timeout) {
    strncpy(current_user, username, sizeof(current_user));
    strncpy(current_role, role, sizeof(current_role));
    current_user[sizeof(current_user)-1] = '\0';
    current_role[sizeof(current_role)-1] = '\0';

    signal(SIGALRM, timeout_handler);
    alarm(timeout);
}

