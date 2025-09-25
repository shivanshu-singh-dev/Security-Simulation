#ifndef FILESYSTEM_H
#define FILESYSTEM_H

void filesystem_read(const char *role, const char *username);
void filesystem_write(const char *role, const char *username);
void filesystem_exec(const char *role, const char *username);

#endif
