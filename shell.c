#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "filesystem.h"   
#include "auth.h"         
#include "audit.h"         

#define CMD_BUF 256

void operations_interface(const char *role) {
    printf("\n----------Permissions for %s----------\n", role);

    if (strcmp(role, "admin") == 0) {
        printf("Permissions: Read ✅, Write ✅, Execute ✅\n");
    }
    else if (strcmp(role, "user") == 0) {
        printf("Permissions: Read ✅, Write ✅, Execute ❌\n");
    }
    else if (strcmp(role, "guest") == 0) {
        printf("Permissions: Read ✅, Write ❌, Execute ❌\n");
    }
    else {
        printf("Unknown role. No permissions assigned.\n");
    }
}

void virtual_shell(const char *username, const char *role) {
    char command[CMD_BUF];
    char *files[100];
    int count;

    printf("\nWelcome to the virtual shell, %s!\nType 'help' for commands, 'exit' to leave.\n", username);

    while (1) {
        printf("\033[34m%s@shell$ \033[0m", username);
        if (!fgets(command, sizeof(command), stdin)) continue;

        
        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "exit") == 0) {
            printf("Exiting shell.\n");
            log_event(username, role, "Shell Exit", "Success");
            break;
        } else if (strcmp(command, "help") == 0) {
            printf("Available commands:\n");
            printf("  auth    : Show your permissions\n");
            printf("  ls      : List all files\n");
            printf("  read    : Read a file\n");
            printf("  write   : Write to a file\n");
            printf("  execute : Execute a file\n");
            printf("  exit    : Exit the shell\n");
        }
         else if (strcmp(command, "auth") == 0) {
            operations_interface(role);
        }
        else if (strcmp(command, "ls") == 0) {
            printf("Listing all accessible files:\n");
            
		count = list_all_files(files, 100);
		for (int i = 0; i < count; i++) {
		    printf("%d. %s\n", i + 1, files[i]);
		}
        } else if (strcmp(command, "read") == 0) {
            if (can_read(role)) {
                printf("[SUCCESS] You can READ files.\n");
                log_event(username, role, "Read", "Allowed");
                filesystem_read(role, username);
            } else {
                printf("[DENIED] Permission denied.\n");
                log_event(username, role, "Read", "Denied");
            }
        } else if (strcmp(command, "write") == 0) {
            if (can_write(role)) {
                printf("[SUCCESS] You can WRITE files.\n");
                log_event(username, role, "Write", "Allowed");
                filesystem_write(role, username);
            } else {
                printf("[DENIED] Permission denied.\n");
                log_event(username, role, "Write", "Denied");
            }
        } else if (strcmp(command, "execute") == 0) {
            if (can_execute(role)) {
                printf("[SUCCESS] You can EXECUTE files.\n");
                log_event(username, role, "Execute", "Allowed");
                filesystem_exec(role, username);
            } else {
                printf("[DENIED] Permission denied.\n");
                log_event(username, role, "Execute", "Denied");
            }
        } else {
            printf("Unknown command: '%s'.\nType 'help' for available commands.\n", command);
        }
    }
}


