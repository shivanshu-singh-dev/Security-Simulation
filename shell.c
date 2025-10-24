#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "filesystem.h"
#include "session.h"
#include "crypto.h"

#define DEMO "Demo/"

#define BLUE "\033[1;34m"
#define RESET "\033[0m"

extern unsigned char AES_KEY[32];
extern unsigned char AES_IV[16];

void operations_interface(const char *role) {
    printf("\n----------Permissions for %s----------\n", role);

    if (strcmp(role, "admin") == 0) {
        printf("Permissions: Read ✅, Write ✅, Execute ✅, Delete ✅, Create ✅\n");
    }
    else if (strcmp(role, "user") == 0) {
        printf("Permissions: Read ✅, Write ✅, Execute ❌, Delete ❌, Create ❌\n");
    }
    else if (strcmp(role, "guest") == 0) {
        printf("Permissions: Read ✅, Write ❌, Execute ❌, Delete ❌, Create ❌\n");
    }
    else {
        printf("Unknown role. No permissions assigned.\n");
    }
}

void virtual_shell(const char *username, const char *role) {
    char cmd[256];
    
    if (!validate_session_token(username, get_session_token())) {
        printf("Invalid or expired session. Please login again.\n");
        return;
    }
    
    printf("Welcome to the virtual shell, %s!\nType 'help' for commands, 'exit' to leave.\n", username);

    while (1) {
        printf(BLUE "%s@shell$ " RESET, username);
        if (!fgets(cmd, sizeof(cmd), stdin)) continue;

        cmd[strcspn(cmd, "\n")] = 0;

        if (strcmp(cmd, "exit") == 0) {
            printf("Exiting shell...\n");
            break;
        }
        else if (strcmp(cmd, "help") == 0) {
            printf("Available commands:\n");
            printf("  auth     : View your permissions based on your role\n");
            printf("  read     : Read available files\n");
            printf("  write    : Write to files\n");
            printf("  execute  : Execute files\n");
            printf("  delete   : Delete a file\n");
            printf("  create   : Create a file\n");
            if (strcmp(role, "admin") == 0) {
                printf("  encrypt  : Encrypt a file\n");
                printf("  decrypt  : Decrypt a file\n");
            }
            printf("  help     : Show this help message\n");
            printf("  exit     : Exit the virtual shell\n");
        }
        else if (strcmp(cmd, "auth") == 0) {
            operations_interface(role);
        }
        else if (strcmp(cmd, "read") == 0) {
            if (can_read(role)) {
                printf("[SUCCESS] You can READ files.\n");
                filesystem_read(role, username);
            } else {
                printf("[DENIED] Permission denied.\n");
            }
        }
        else if (strcmp(cmd, "write") == 0) {
            if (can_write(role)) {
                printf("[SUCCESS] You can WRITE files.\n");
                filesystem_write(role, username);
            } else {
                printf("[DENIED] Permission denied.\n");
            }
        }
        else if (strcmp(cmd, "execute") == 0) {
            if (can_execute(role)) {
                printf("[SUCCESS] You can EXECUTE files.\n");
                filesystem_exec(role, username);
            } else {
                printf("[DENIED] Permission denied.\n");
            }
        }
        else if (strcmp(cmd, "delete") == 0) {
            if (!validate_session_token(username, get_session_token())) {
                printf("Invalid or expired session. Please login again.\n");
                return;
            }
            if (strcmp(role, "admin") != 0) {
                printf("[DENIED] Only admins can delete files.\n");
                continue;
            }

            char *files[100];
            int count = list_all_files(files, 100);
            if (count == 0) { printf("No files to delete.\n"); continue; }

            printf("Available files:\n");
            for (int i = 0; i < count; i++) printf("%d. %s\n", i + 1, files[i]);

            int choice;
            printf("Enter file number to delete: ");
            scanf("%d", &choice); while(getchar() != '\n');
            if (choice < 1 || choice > count) { printf("Invalid choice.\n"); continue; }

            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s%s", DEMO, files[choice-1]);
            if (remove(filepath) == 0) printf("File '%s' deleted successfully.\n", files[choice-1]);
            else perror("Failed to delete file");
        }
        else if (strcmp(cmd, "create") == 0) {
            if (!validate_session_token(username, get_session_token())) {
                printf("Invalid or expired session. Please login again.\n");
                return;
            }
            if (strcmp(role, "admin") != 0) { printf("[DENIED] Only admins can create files.\n"); continue; }

            char filename[100];
            printf("Enter filename to create: ");
            if (!fgets(filename, sizeof(filename), stdin)) continue;
            filename[strcspn(filename, "\n")] = 0;

            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s%s", DEMO, filename);

            FILE *fp = fopen(filepath, "w");
            if (!fp) { perror("Failed to create file"); continue; }
            fclose(fp);
            printf("File '%s' created successfully.\n", filename);
        }
        else if (strcmp(cmd, "encrypt") == 0 || strcmp(cmd, "decrypt") == 0) {
        	

            if (!validate_session_token(username, get_session_token())) {
                printf("Invalid or expired session. Please login again.\n");
                return;
            }
            if (strcmp(role, "admin") != 0) { 
                printf("[DENIED] Only admins can %s files.\n", cmd); 
                continue; 
            }

            char *files[100];
            int count = list_all_files(files, 100);
            if (count == 0) { printf("No files available.\n"); continue; }

            printf("Available files:\n");
            for (int i = 0; i < count; i++) printf("%d. %s\n", i + 1, files[i]);

            int choice;
            printf("Enter file number to %s: ", cmd);
            scanf("%d", &choice);
            while(getchar() != '\n'); // flush

            if (choice < 1 || choice > count) { printf("Invalid choice.\n"); continue; }

            char filepath[512], tmp[512];
            snprintf(filepath, sizeof(filepath), "%s%s", DEMO, files[choice-1]);
            
            printf("[DEBUG] Encrypting '%s' with AES_KEY=%p AES_IV=%p\n", filepath, AES_KEY, AES_IV);

            if (strcmp(cmd, "encrypt") == 0) {
                snprintf(tmp, sizeof(tmp), "%s.enc", filepath);
                if (encrypt_file(filepath, tmp, AES_KEY, AES_IV)) {
                    printf("File '%s' encrypted successfully → '%s'\n", files[choice-1], tmp);
                    remove(filepath); // delete plaintext
                } else {
                    printf("[ERROR] Failed to encrypt '%s'\n", files[choice-1]);
                }
            } else { // decrypt
                snprintf(tmp, sizeof(tmp), "%s.tmp", filepath);
                if (decrypt_file(filepath, tmp, AES_KEY, AES_IV)) {
                    printf("File '%s' decrypted temporarily → '%s'\n", files[choice-1], tmp);
                    printf("Remember: This is a temporary decrypted file.\n");
                } else {
                    printf("[ERROR] Failed to decrypt '%s'\n", files[choice-1]);
                }
            }

            // free file list
            for (int i = 0; i < count; i++) free(files[i]);
        }
        else {
        //printf("[DEBUG] Encrypting '%s' with AES_KEY=%p AES_IV=%p\n", filepath, AES_KEY, AES_IV);
            printf("Unknown command: '%s'.\nType 'help' for available commands.\n", cmd);
        }
    }
}

