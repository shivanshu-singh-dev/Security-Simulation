#ifndef SHELL_H
#define SHELL_H

// Core shell interface after login
void virtual_shell(const char *username, const char *role);

// Helper functions for internal shell commands
int shell_cd(const char *path);
int shell_ls(const char *path);
int shell_read(const char *filename, const char *role, const char *username);
int shell_write(const char *filename, const char *role, const char *username);
int shell_exec(const char *filename, const char *role, const char *username);

// Utility to flush stdin buffer
void flush_input(void);

#endif // SHELL_H

