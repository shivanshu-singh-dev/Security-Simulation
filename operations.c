#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>


#include "operations.h"
#include "auth.h"
#include "acl.h"
#include "audit.h"
#include "session.h"
#include "filesystem.h"



/*
void operations_window(const char *username, const char *role) {
    printf("\nWelcome to the virtual shell, %s! Type 'help' for commands, 'exit' to leave.\n", username);

    auto_logout(username, role, 300);

    virtual_shell(username, role);
    
    end_session(username, role);
    printf("Exited virtual shell.\n");
}
*/
