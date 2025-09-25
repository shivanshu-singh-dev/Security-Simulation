#include <stdio.h>
#include <time.h>
#include <string.h>
#include "audit.h"

#define LOGFILE "audit.log"

void log_event(const char *username, const char *role, const char *action, const char *result) {
    FILE *fp = fopen(LOGFILE, "a");
    if (!fp) return;

    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strcspn(ts, "\n")] = 0;

    fprintf(fp, "[%s] User: %s | Role: %s | Action: %s | Result: %s\n",
            ts, username, role, action, result);

    fclose(fp);
}

