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

    const char *token_to_print;
    if (token && strlen(token) > 0) {
        token_to_print = token;
    }
    
    else {
        const char *session_token = get_session_token();
        token_to_print = (session_token && strlen(session_token) > 0) ? session_token : "N/A";
    }

    fprintf(fp, "[%s] User: %s | Role: %s | Token: %s | Action: %s | Status: %s\n",
            ts, username, role, token_to_print, action, status);
    fclose(fp);
}
