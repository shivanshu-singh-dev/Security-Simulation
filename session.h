#ifndef SESSION_H
#define SESSION_H

#define TOKEN_SIZE 65

void start_session(const char *username, const char *role);
void end_session(const char *username, const char *role);
void auto_logout(const char *username, const char *role, int timeout_seconds);

void generate_session_token(const char *username, char *token);
int validate_session_token(const char *username, const char *token);
const char *get_session_token(void);

#endif


