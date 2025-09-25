#ifndef FILESYSTEM_H
#define FILESYSTEM_H

void filesystem_read(const char *role, const char *username);
void filesystem_write(const char *role, const char *username);
void filesystem_exec(const char *role, const char *username);

int can_read(const char *role);
int can_write(const char *role);
int can_execute(const char *role);

int list_all_files(char *files[], int max_files);

#endif
