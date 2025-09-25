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

void operations_window(const char *username, const char *role) {
    int choice;
    
    auto_logout(username, role, 300);
    alarm(300); //Set

    while (1) {
        printf("\n----------Operations Window----------\n");
        printf("1. View Permissions\n");
        printf("2. File Read\n");
        printf("3. File Write\n");
        printf("4. File Execute\n");
        printf("5. Logout\n");
        printf("Enter choice: ");
        scanf("%d", &choice);
        flush_input();
        alarm(300); //Reset

        if (choice == 1) {
            operations_interface(role);
        }
		else if (choice == 2) { // File Read
	    if(check_permission(role, "read")) {
		printf("[SUCCESS] You can READ files.\n");
		log_event(username, role, "Read", "Allowed");
		filesystem_read(role, username);
	    } else {
		printf("[DENIED] Permission denied.\n");
		log_event(username, role, "Read", "Denied");
	    }
	}
	else if (choice == 3) { // File Write
	    if(check_permission(role, "write")) {
		printf("[SUCCESS] You can WRITE files.\n");
		log_event(username, role, "Write", "Allowed");
		filesystem_write(role, username);
	    } else {
		printf("[DENIED] Permission denied.\n");
		log_event(username, role, "Write", "Denied");
	    }
	}
	else if (choice == 4) { // File Execute
	    if(check_permission(role, "execute")) {
		printf("[SUCCESS] You can EXECUTE commands.\n");
		log_event(username, role, "Execute", "Allowed");
		filesystem_exec(role, username);
	    } else {
		printf("[DENIED] Permission denied.\n");
		log_event(username, role, "Execute", "Denied");
	    }
	}

        else if (choice == 5) {
            printf("Exiting Operations Window.\n");
            log_event(username, role, "Log Out", "Success");
            break;
        }
        else {
            printf("Invalid choice.\n");
        }
    }
}

