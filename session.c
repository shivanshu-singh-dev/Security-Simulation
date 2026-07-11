#include <stdlib.h>
#include "sha256.h"
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <time.h>
#include "session.h"
#include "audit.h"
#include "crypto.h"

#define SESSION "session.log"
#define SESSION_ENC "session.enc"

static time_t session_start;
static char current_user[50];
static char current_role[20];
static char current_token[TOKEN_SIZE];

static void to_hex_string(const unsigned char *hash, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) sprintf(out + (i * 2), "%02x", hash[i]);
    out[len * 2] = '\0';
}

void generate_session_token(const char *username, char *token) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "%s-%ld-%d", username, (long)time(NULL), rand());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buffer, strlen(buffer), hash);
    to_hex_string(hash, SHA256_DIGEST_LENGTH, token);
}

int validate_session_token(const char *username, const char *token) {
    (void)username;
    if (strlen(current_token) == 0) return 0;
    return (strcmp(current_token, token) == 0);
}

const char* get_session_token(void) {
    return current_token;
}


// Start session
void start_session(const char *username, const char *role) {
				
    ensure_decrypted(SESSION, SESSION_ENC);    
    session_start = time(NULL);
    
    strncpy(current_user, username, sizeof(current_user)-1);
    strncpy(current_role, role, sizeof(current_role)-1);
    current_user[sizeof(current_user)-1] = '\0';
    current_role[sizeof(current_role)-1] = '\0';

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

void end_session(const char *username, const char *role) {
    ensure_decrypted(SESSION, SESSION_ENC);
    time_t session_end = time(NULL);
    double duration = difftime(session_end, session_start);

    FILE *fp = fopen(SESSION, "a");
    if (!fp) return;

    char *ts = ctime(&session_end); //readable time
    ts[strcspn(ts, "\n")] = 0;
    fprintf(fp, "[%s] Session END | User: %s | Role: %s | Token: %s | Duration: %.0f sec\n",
            ts, username, role, current_token, duration);
    fclose(fp);

    memset(current_token, 0, sizeof(current_token));
    ensure_encrypted(SESSION, SESSION_ENC);
}

static void timeout_handler(int sig) {
    ensure_decrypted(SESSION, SESSION_ENC);
    time_t session_end = time(NULL);
    double duration = difftime(session_end, session_start);

    printf("\n[SESSION TIMEOUT] Auto-logout (signal %d)\n", sig);
    log_event(current_user, current_role, "Auto Logout", "Session Timeout", current_token);

    FILE *fp = fopen(SESSION, "a");
    if (fp) {
        char *ts = ctime(&session_end);
        ts[strcspn(ts, "\n")] = 0;
        fprintf(fp, "[%s] Session TIMEOUT | User: %s | Role: %s | Token: %s | Duration: %.0f sec\n",
                ts, current_user, current_role, current_token, duration);
        fclose(fp);
    }

    memset(current_token, 0, sizeof(current_token));
    ensure_encrypted(SESSION, SESSION_ENC);
    exit(0);
}

#ifdef _WIN32
static DWORD WINAPI win_timeout_thread(LPVOID lpParam) {
    int timeout = *(int*)lpParam;
    free(lpParam);
    Sleep(timeout * 1000);
    timeout_handler(0);
    return 0;
}

void auto_logout(const char *username, const char *role, int timeout) {
    strncpy(current_user, username, sizeof(current_user)-1);
    strncpy(current_role, role, sizeof(current_role)-1);
    current_user[sizeof(current_user)-1] = '\0';
    current_role[sizeof(current_role)-1] = '\0';

    int *timeout_val = malloc(sizeof(int));
    if (timeout_val) {
        *timeout_val = timeout;
        CreateThread(NULL, 0, win_timeout_thread, timeout_val, 0, NULL);
    }
}
#else
void auto_logout(const char *username, const char *role, int timeout) {
    strncpy(current_user, username, sizeof(current_user)-1);
    strncpy(current_role, role, sizeof(current_role)-1);
    current_user[sizeof(current_user)-1] = '\0';
    current_role[sizeof(current_role)-1] = '\0';

    signal(SIGALRM, timeout_handler);
    alarm(timeout);
}
#endif

