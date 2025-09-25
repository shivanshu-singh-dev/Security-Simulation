#include <stdio.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#include "session.h"
#include "audit.h"

#define SESSION "session.log"

static time_t session_start;
static char current_user[50];
static char current_role[20];

void start_session(const char *username, const char *role) {
    session_start = time(NULL);

    FILE *fp = fopen(SESSION, "a");
    if (!fp) return;

    char *ts = ctime(&session_start);
    ts[strcspn(ts, "\n")] = 0;

    fprintf(fp, "[%s] Session START | User: %s | Role: %s\n",
            ts, username, role);

    fclose(fp);
}

void end_session(const char *username, const char *role) {
    time_t session_end = time(NULL);
    double duration = difftime(session_end, session_start);

    FILE *fp = fopen(SESSION, "a");
    if (!fp) return;

    char *ts = ctime(&session_end);
    ts[strcspn(ts, "\n")] = 0;

    fprintf(fp, "[%s] Session END   | User: %s | Role: %s | Duration: %.0f sec\n",
            ts, username, role, duration);

    fclose(fp);
}

static void timeout_handler(int sig) {
    time_t session_end = time(NULL);
    
    double duration = difftime(session_end, session_start);

    printf("\n[SESSION TIMEOUT] (signal %d) Auto-logout due to inactivity.\n", sig);

    //in audit.log
    log_event(current_user, current_role, "Auto Logout", "Session Timeout");

    //in session.log
    FILE *fp = fopen(SESSION, "a");
    if (fp) {
        char *ts = ctime(&session_end);
        ts[strcspn(ts, "\n")] = 0;

        fprintf(fp, "[%s] Session TIMEOUT | User: %s | Role: %s | Duration: %.0f sec\n",
                ts, current_user, current_role, duration);

        fclose(fp);
    }

    exit(0);
}

void auto_logout(const char *username, const char *role, int timeout) {
    strncpy(current_user, username, sizeof(current_user));
    strncpy(current_role, role, sizeof(current_role));
    current_user[sizeof(current_user)-1] = '\0';
    current_role[sizeof(current_role)-1] = '\0';

    signal(SIGALRM, timeout_handler);  
    alarm(timeout);                     
}

