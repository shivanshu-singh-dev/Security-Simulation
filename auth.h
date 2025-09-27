#ifndef AUTH_H
#define AUTH_H

int register_user();  
int login_user(char *username, char *role);
void hash_password(const char *password, char *output);
void flush_input();

const char *get_session_token(void);


#endif

