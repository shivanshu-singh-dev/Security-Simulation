#ifndef AUDIT_H
#define AUDIT_H

void log_event(const char *username, const char *role,
               const char *action, const char *status,
               const char *token);

#endif
