#ifndef ACL_H
#define ACL_H

int check_permission(const char *role, const char *action);
int superuser(const char *username);
int acl_allowed(const char *username, const char *filename);

#endif

