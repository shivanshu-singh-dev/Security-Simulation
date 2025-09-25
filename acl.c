#include <string.h>
#include "acl.h"

int check_permission(const char *role, const char *action) {
    if (strcmp(role, "admin") == 0) return 1;

    if (strcmp(role, "user") == 0) {
        if (strcmp(action, "read") == 0) return 1;
        if (strcmp(action, "write") == 0) return 1;
        return 0;
    }

    if (strcmp(role, "guest") == 0) {
        if (strcmp(action, "read") == 0) return 1;
        return 0;
    }

    return 0; 
}

