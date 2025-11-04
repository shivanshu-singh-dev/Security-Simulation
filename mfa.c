#define _POSIX_C_SOURCE 200809L

#include "mfa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MFA_DIR "MFA"                 
#define MFA_FILE_FMT MFA_DIR "/mfa_%s.txt"
#define MAX_USERS 64
#define DEFAULT_EXPIRY 120            
#define MAX_ATTEMPTS 3

typedef struct {
    int used;                
    char username[64];
    int code;              
    time_t expires_at;
    int attempts_left;
} mfa_entry_t;

static mfa_entry_t mfa_table[MAX_USERS];
static int mfa_inited = 0;

static void mfa_init_if_needed(void) {
    if (mfa_inited) return;

    // Seed rand with variability
    srand((unsigned int)(time(NULL) ^ getpid()));
    memset(mfa_table, 0, sizeof(mfa_table));

    // Ensure MFA directory exists
    if (access(MFA_DIR, F_OK) != 0) {
        mkdir(MFA_DIR, 0755);
    }

    mfa_inited = 1;
}
/* whats F_OK

explain
    if (access(MFA_DIR, F_OK) != 0) {
        mkdir(MFA_DIR, 0755);
    }

*/

static mfa_entry_t *find_entry(const char *username) {
    for (int i = 0; i < MAX_USERS; ++i) {
        if (mfa_table[i].used && strcmp(mfa_table[i].username, username) == 0)
            return &mfa_table[i];
    }
    return NULL;
}

static mfa_entry_t *allocate_entry(void) {
    for (int i = 0; i < MAX_USERS; ++i) {
        if (!mfa_table[i].used) {
            mfa_table[i].used = 1;
            mfa_table[i].username[0] = '\0';
            mfa_table[i].code = 0;
            mfa_table[i].expires_at = 0;
            mfa_table[i].attempts_left = 0;
            return &mfa_table[i];
        }
    }
    return NULL;
}

static void write_code_to_file(const char *username, int code, time_t expires_at) {
    char path[512];
    snprintf(path, sizeof(path), MFA_FILE_FMT, username);

    FILE *f = fopen(path, "w");
    if (!f) return;

    char tsbuf[64];
    struct tm *tm = localtime(&expires_at);
    if (tm) strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", tm);
    else tsbuf[0] = '\0';

    fprintf(f, "MFA code for user: %s\n", username);
    fprintf(f, "Code: %06d\n", code);
    fprintf(f, "Expires at: %s\n", tsbuf);

    fclose(f);
}

static void remove_code_file(const char *username) {
    char path[512];
    snprintf(path, sizeof(path), MFA_FILE_FMT, username);
    unlink(path);
}

int mfa_generate(const char *username, int expiry_seconds) {
    if (!username || username[0] == '\0') return -1;
    mfa_init_if_needed();

    if (expiry_seconds <= 0) expiry_seconds = DEFAULT_EXPIRY;

    mfa_entry_t *e = find_entry(username);
    if (!e) {
        e = allocate_entry();
        if (!e) return -1; // table full
    }

    strncpy(e->username, username, sizeof(e->username)-1);
    e->username[sizeof(e->username)-1] = '\0';

    int code = 100000 + (rand() % 900000);
    e->code = code;
    e->expires_at = time(NULL) + expiry_seconds;
    e->attempts_left = MAX_ATTEMPTS;

    write_code_to_file(username, code, e->expires_at);

    return 0;
}

int mfa_verify(const char *username, int code) {
    if (!username || username[0] == '\0') return -1;
    mfa_init_if_needed();

    mfa_entry_t *e = find_entry(username);
    if (!e) return -1; // no entry

    time_t now = time(NULL);
    if (now > e->expires_at) {
        remove_code_file(username);
        e->used = 0;
        return -1; // expired
    }

    if (e->attempts_left <= 0) {
        remove_code_file(username);
        e->used = 0;
        return -2; // locked
    }

    if (e->code == code) {
        remove_code_file(username);
        e->used = 0;
        return 1; // success
    } else {
        e->attempts_left--;
        if (e->attempts_left <= 0) {
            remove_code_file(username);
            e->used = 0;
            return -2; // locked
        }
        return 0; // wrong code
    }
}

void mfa_cleanup(const char *username) {
    if (!username || username[0] == '\0') return;
    mfa_init_if_needed();

    mfa_entry_t *e = find_entry(username);
    if (!e) return;

    remove_code_file(username);
    e->used = 0;
}

int mfa_get_attempts(const char *username) {
    if (!username || username[0] == '\0') return -1;
    mfa_init_if_needed();

    mfa_entry_t *e = find_entry(username);
    if (!e) return -1;
    return e->attempts_left;
}

int mfa_get_time_left(const char *username) {
    if (!username || username[0] == '\0') return -1;
    mfa_init_if_needed();

    mfa_entry_t *e = find_entry(username);
    if (!e) return -1;
    time_t now = time(NULL);
    if (now > e->expires_at) return 0;
    return (int)(e->expires_at - now);
}
