#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shell.h"
#include "auth.h"
#include "session.h"
#include "crypto.h"

#define BUF 100

int main() {
    char buffer[BUF];
    int choice;

    while (1) {
        printf("\n----------Login Window----------\n");
        printf("1. Register\n2. Login\n3. Exit\nEnter choice: ");
        
        if (!fgets(buffer, sizeof(buffer), stdin)) continue;
        
        if (sscanf(buffer, "%d", &choice) != 1) {
            printf("Invalid input.\n");
            continue;
        }

        if (choice == 1) {
            register_user();
        } else if (choice == 2) {
            char username[50], role[10];
            if (login_user(username, role)) {
                start_session(username, role);
                auto_logout(username, role, 250);
                virtual_shell(username, role);
                end_session(username, role);
                ensure_encrypted("audit.log", "audit.enc");
		ensure_encrypted("session.log", "session.enc");
            } else {
                printf("Login failed.\n");
            }
        } else if (choice == 3) {
            printf("Exiting\n");
            break;
        } else {
            printf("Invalid choice.\n");
        }
    }
    
    return 0;
}

