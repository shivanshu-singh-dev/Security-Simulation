#include <time.h>
#include <string.h>
#include <unistd.h> 
#include <stdio.h>
#include "audit.h"
#include "crypto.h"
#include "session.h"

#define AUDIT_LOG "audit.log"
#define AUDIT_ENC "audit.enc"

void log_event(const char *username, const char *role,
               const char *action, const char *status,
               const char *token) {

    ensure_decrypted(AUDIT_LOG, AUDIT_ENC);

    FILE *fp = fopen(AUDIT_LOG, "a");
    if (!fp) return;

    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strcspn(ts, "\n")] = 0;

    fprintf(fp, "[%s] User: %s | Role: %s | Token: %s | Action: %s | Status: %s\n",
            ts, username, role, token ? token : get_session_token() , action, status);
    fclose(fp);
}

