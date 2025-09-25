#ifndef SESSION_H
#define SESSION_H

void start_session(const char *username, const char *role);
void end_session(const char *username, const char *role);
void auto_logout(const char *username, const char *role, int timeout);

#endif

