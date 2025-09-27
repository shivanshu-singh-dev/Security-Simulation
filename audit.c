#include <stdio.h>
#include <string.h>
#include <time.h>
#include "audit.h"

#define AUDIT_LOG "audit.log"

void log_event(const char *username, const char *role,
               const char *action, const char *status,
               const char *token) {
    FILE *fp = fopen(AUDIT_LOG, "a");
    if (!fp) return;

    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strcspn(ts, "\n")] = 0; // remove newline

    fprintf(fp, "[%s] User: %s | Role: %s | Token: %s | Action: %s | Status: %s\n",
            ts, username, role, token ? token : "N/A", action, status);

    fclose(fp);
}

