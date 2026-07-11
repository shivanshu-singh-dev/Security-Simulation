#include <string.h>
#include <stdio.h>
#include "acl.h"

#define SUPER_FILE "superusers.txt"

int check_permission(const char *role, const char *action) {
    if (strcmp(role, "admin") == 0) return 1;
    if (strcmp(role, "super") == 0) return 1;

    if (strcmp(role, "user") == 0) {
        if (strcmp(action, "read") == 0) return 1;
        if (strcmp(action, "write") == 0) return 1;
        if (strcmp(action, "execute") == 0) return 1;
        return 0;
    }

    if (strcmp(role, "guest") == 0) {
        if (strcmp(action, "execute") == 0) return 1;
        if (strcmp(action, "read") == 0) return 1;
        return 0;
    }

    return 0;
}

int superuser(const char *username) {
    FILE *fp = fopen(SUPER_FILE, "r");
    if (!fp) return 0;

    char name[50];
    int found = 0;

    while (fscanf(fp, "%49s", name) == 1) {
        if (strcmp(name, username) == 0) {
            found = 1;
            break;
        }
    }

    fclose(fp);
    return found;
}

int acl_allowed(const char *username, const char *filename) {
    if (strcmp(filename, "session.log") == 0 ||
        strcmp(filename, "audit.log") == 0 ||
        strcmp(filename, "users.txt") == 0 ||
        strcmp(filename, "superusers.txt") == 0) {
        return superuser(username);
    }
    return 1;
}

