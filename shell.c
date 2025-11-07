#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "filesystem.h"
#include "session.h"
#include "crypto.h"
#include "acl.h"

#define DEMO "Demo/"
#define BLUE "\033[1;34m"
#define RESET "\033[0m"

void operations_interface(const char *role) {
    printf("\n----------Permissions for %s----------\n", role);

    if (strcmp(role, "admin") == 0) {
        printf("Permissions: Read ✅, Write ✅, Execute ✅, Delete ✅, Create ✅, Encrypt ✅, Decrypt ✅\n");
    }
    else if (strcmp(role, "user") == 0) {
        printf("Permissions: Read ✅, Write ✅, Execute ✅, Delete ❌, Create ❌, Encrypt ❌, Decrypt ❌\n");
    }
    else if (strcmp(role, "guest") == 0) {
        printf("Permissions: Read ✅, Write ❌, Execute ✅, Delete ❌, Create ❌\n");
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

    printf("Welcome to the Security Model, %s!\nType 'help' for commands, 'exit' to leave.\n", username);

    while (1) {
        printf(BLUE "%s@shell$ " RESET, username);
        if (!fgets(cmd, sizeof(cmd), stdin)) continue;
        cmd[strcspn(cmd, "\n")] = 0;

        if (strcmp(cmd, "exit") == 0) break;

        else if (strcmp(cmd, "help") == 0) {
            printf("Available commands:\n");
            printf("  auth     → Show your permissions\n");
            printf("  read     → Read file\n");
            printf("  write    → Write to file\n");
            printf("  execute  → Execute operation\n");
            printf("  delete   → Delete file\n");
            printf("  create   → Create new file\n");
            if(strcmp(role, "admin") == 0){ 
		    printf("  super    → Add a new superuser\n");
		    printf("  encrypt  → Encrypt a file \n");
		    printf("  decrypt  → Decrypt a file \n");
            }
            printf("  help     → Show this help menu\n");
            printf("  exit     → Logout shell\n");
        }

        else if (strcmp(cmd, "auth") == 0) {
            operations_interface(role);
        }

        else if (strcmp(cmd, "super") == 0) {
            if (!superuser(username)) {
                printf("[DENIED] Only a superuser can add another superuser.\n");
                continue;
            }

            char new_super[50];
            printf("Enter username to add as superuser: ");
            if (!fgets(new_super, sizeof(new_super), stdin)) continue;
            new_super[strcspn(new_super, "\n")] = 0;

            if (strlen(new_super) == 0) {
                printf("Invalid username.\n");
                continue;
            }

            chmod("superusers.txt", 0644);
            FILE *fp = fopen("superusers.txt", "a+");
            if (!fp) {
                perror("Failed to open superusers.txt");
                chmod("superusers.txt", 0444);
                continue;
            }

            char name[50];
            int exists = 0;
            rewind(fp);
            while (fscanf(fp, "%49s", name) == 1) {
                if (strcmp(name, new_super) == 0) {
                    exists = 1;
                    break;
                }
            }

            if (exists) {
                printf("User '%s' is already a superuser.\n", new_super);
                fclose(fp);
                chmod("superusers.txt", 0444);
                continue;
            }

            fprintf(fp, "%s\n", new_super);
            fclose(fp);
            chmod("superusers.txt", 0444);
            printf("Superuser '%s' added successfully.\n", new_super);

            printf("\n--- Superuser List ---\n");
            fp = fopen("superusers.txt", "r");
            if (!fp) {
                printf("Error reading superusers.txt\n");
                continue;
            }
            while (fscanf(fp, "%49s", name) == 1) {
                printf("  • %s\n", name);
            }
            fclose(fp);
        }


	else if (strcmp(cmd, "encrypt") == 0) {
	    if (strcmp(role, "admin") != 0 && !superuser(username)) {
		printf("[DENIED] Only admins or superusers can encrypt files.\n");
		continue;
	    }

	    char *files[100];
	    int count = list_all_files(files, 100);
	    if (count == 0) {
		printf("No files available to encrypt.\n");
		continue;
	    }

	    int map_idx[100];
	    int shown = 0;
	    printf("Available files to encrypt:\n");
	    for (int i = 0; i < count; ++i) {
		// Skip already encrypted files
		if (strstr(files[i], ".enc") != NULL) continue;
		
		// Skip system files that shouldn't be encrypted via this command
		if (strcmp(files[i], "users.txt") == 0 ||
		    strcmp(files[i], "superusers.txt") == 0) continue;


		char encver[512];
		if (strcmp(files[i], "session.log") == 0) {
		    snprintf(encver, sizeof(encver), "session.enc");
		} else if (strcmp(files[i], "audit.log") == 0) {
		    snprintf(encver, sizeof(encver), "audit.enc");
		} else {
		    snprintf(encver, sizeof(encver), "%s%s.enc", DEMO, files[i]);
		}
		
		FILE *chk = fopen(encver, "r");
		if (chk) { fclose(chk); continue; }

		shown++;
		map_idx[shown - 1] = i;
		printf("%d. %s\n", shown, files[i]);
	    }

	    if (shown == 0) {
		printf("No encryptable files found.\n");
		for (int i = 0; i < count; ++i) free(files[i]);
		continue;
	    }

	    int choice;
	    printf("Choose a file number to encrypt: ");
	    if (scanf("%d", &choice) != 1) {
		printf("Invalid input.\n");
		while (getchar() != '\n');
		for (int i = 0; i < count; ++i) free(files[i]);
		continue;
	    }
	    while (getchar() != '\n');

	    if (choice < 1 || choice > shown) {
		printf("Invalid choice.\n");
		for (int i = 0; i < count; ++i) free(files[i]);
		continue;
	    }

	    char *filename = files[ map_idx[choice - 1] ];
	    char infile[512], outfile[512];
	    
	    // Special files are in root directory with .enc extension (not .log.enc)
	    if (strcmp(filename, "session.log") == 0) {
		snprintf(infile, sizeof(infile), "session.log");
		snprintf(outfile, sizeof(outfile), "session.enc");
	    } else if (strcmp(filename, "audit.log") == 0) {
		snprintf(infile, sizeof(infile), "audit.log");
		snprintf(outfile, sizeof(outfile), "audit.enc");
	    } else {
		snprintf(infile, sizeof(infile), "%s%s", DEMO, filename);
		snprintf(outfile, sizeof(outfile), "%s%s.enc", DEMO, filename);
	    }

	    if (access(infile, F_OK) != 0) {
		printf("[WARN] File '%s' not found. It might already be encrypted.\n", infile);
		for (int i = 0; i < count; ++i) free(files[i]);
		continue;
	    }

	    char tmpfile[512];
	    snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", infile);
	    if (encrypt_file(infile, tmpfile) == 0) {
		remove(infile);
		rename(tmpfile, outfile);
		printf("File '%s' encrypted successfully -> %s\n", filename, outfile);
	    } else {
		printf("Encryption failed for '%s'.\n", filename);
		remove(tmpfile);
	    }

	    for (int i = 0; i < count; ++i) free(files[i]);
	}

	else if (strcmp(cmd, "decrypt") == 0) {
	    if (strcmp(role, "admin") != 0 && !superuser(username)) {
		printf("[DENIED] Only admins or superusers can decrypt files.\n");
		continue;
	    }

	    char *files[100];
	    int count = list_all_files(files, 100);
	    if (count == 0) {
		printf("No files present.\n");
		continue;
	    }

	    int map_idx[100];
	    int shown = 0;
	    printf("Available encrypted files:\n");
	    for (int i = 0; i < count; ++i) {
		// Look for both .enc and .log.enc patterns
		int is_encrypted = 0;
		char base[512];
		strncpy(base, files[i], sizeof(base));
		
		// Check for .enc extension (session.enc, audit.enc)
		if (strstr(files[i], ".enc") != NULL) {
		    char *dot = strstr(base, ".enc");
		    if (dot) *dot = '\0';
		    is_encrypted = 1;
		}
		// Check for .log.enc extension (session.log.enc, audit.log.enc)  
		else if (strstr(files[i], ".log.enc") != NULL) {
		    char *dot = strstr(base, ".log.enc");
		    if (dot) *dot = '\0';
		    strcat(base, ".log");
		    is_encrypted = 1;
		}

		if (!is_encrypted) continue;

		// Skip if plain version already exists
		char plainfile[512];
		if (strcmp(base, "session.log") == 0 || 
		    strcmp(base, "audit.log") == 0 ||
		    strcmp(base, "users.txt") == 0 ||
		    strcmp(base, "superusers.txt") == 0) {
		    snprintf(plainfile, sizeof(plainfile), "%s", base);
		} else {
		    snprintf(plainfile, sizeof(plainfile), "%s%s", DEMO, base);
		}
		
		FILE *chk = fopen(plainfile, "r");
		if (chk) { fclose(chk); continue; }

		shown++;
		map_idx[shown - 1] = i;
		printf("%d. %s\n", shown, files[i]);
	    }

	    if (shown == 0) {
		printf("No encrypted files found.\n");
		for (int i = 0; i < count; ++i) free(files[i]);
		continue;
	    }

	    int choice;
	    printf("Choose a file number to decrypt: ");
	    if (scanf("%d", &choice) != 1) {
		printf("Invalid input.\n");
		while (getchar() != '\n');
		for (int i = 0; i < count; ++i) free(files[i]);
		continue;
	    }
	    while (getchar() != '\n');

	    if (choice < 1 || choice > shown) {
		printf("Invalid choice.\n");
		for (int i = 0; i < count; ++i) free(files[i]);
		continue;
	    }

	    char *encname = files[ map_idx[choice - 1] ];
	    char infile[512], tmpfile[512];
	    
	    if (strcmp(encname, "session.enc") == 0 || 
		strcmp(encname, "audit.enc") == 0 ||
		strcmp(encname, "session.log.enc") == 0 || 
		strcmp(encname, "audit.log.enc") == 0 ||
		strcmp(encname, "users.txt.enc") == 0 ||
		strcmp(encname, "superusers.txt.enc") == 0) {
		snprintf(infile, sizeof(infile), "%s", encname);
	    } else {
		snprintf(infile, sizeof(infile), "%s%s", DEMO, encname);
	    }

	    char base[512];
	    strncpy(base, encname, sizeof(base));
	    
	    if (strcmp(encname, "session.enc") == 0) {
		strcpy(base, "session.log");
	    } else if (strcmp(encname, "audit.enc") == 0) {
		strcpy(base, "audit.log");
	    } else if (strstr(encname, ".log.enc") != NULL) {
		char *dot = strstr(base, ".log.enc");
		if (dot) *dot = '\0';
		strcat(base, ".log");
	    } else if (strstr(encname, ".enc") != NULL) {
		char *dot = strstr(base, ".enc");
		if (dot) *dot = '\0';
	    }
	    
	    if (strcmp(base, "session.log") == 0 || 
		strcmp(base, "audit.log") == 0 ||
		strcmp(base, "users.txt") == 0 ||
		strcmp(base, "superusers.txt") == 0) {
		snprintf(tmpfile, sizeof(tmpfile), "%s.tmp", base);
	    } else {
		snprintf(tmpfile, sizeof(tmpfile), "%s%s.tmp", DEMO, base);
	    }

	    if (decrypt_file(infile, tmpfile) == 0) {
		remove(infile);
		char outfile[512];

		if (strcmp(base, "session.log") == 0 || 
		    strcmp(base, "audit.log") == 0 ||
		    strcmp(base, "users.txt") == 0 ||
		    strcmp(base, "superusers.txt") == 0) {
		    snprintf(outfile, sizeof(outfile), "%s", base);
		} else {
		    snprintf(outfile, sizeof(outfile), "%s%s", DEMO, base);
		}
		rename(tmpfile, outfile);
		printf("File '%s' decrypted successfully -> %s\n", encname, base);
	    } else {
		printf("Decryption failed for '%s'.\n", encname);
		remove(tmpfile);
	    }

    for (int i = 0; i < count; ++i) free(files[i]);
}



        else if (strcmp(cmd, "write") == 0) {
            if (can_write(role) || superuser(username))
                filesystem_write(role, username);
            else
                printf("[DENIED] Permission denied.\n");
        }

        else if (strcmp(cmd, "execute") == 0) {
            if (can_execute(role) || superuser(username))
                filesystem_exec(role, username);
            else
                printf("[DENIED] Permission denied.\n");
        }

        else if (strcmp(cmd, "delete") == 0) {
            if (strcmp(role, "admin") != 0 && !superuser(username)) {
                printf("[DENIED] Only admins or superusers can delete files.\n");
                continue;
            }

            char *files[100];
            int count = list_all_files(files, 100);
            if (count == 0) { printf("No files to delete.\n"); continue; }

            printf("Available files:\n");
            for (int i = 0; i < count; i++) printf("%d. %s\n", i + 1, files[i]);

            int choice;
            printf("Enter file number to delete: ");
            scanf("%d", &choice); while (getchar() != '\n');
            if (choice < 1 || choice > count) { printf("Invalid choice.\n"); continue; }

            char filepath[512];

            if (strcmp(files[choice - 1], "session.log") == 0 || 
                strcmp(files[choice - 1], "audit.log") == 0 ||
                strcmp(files[choice - 1], "users.txt") == 0 ||
                strcmp(files[choice - 1], "superusers.txt") == 0) {
                snprintf(filepath, sizeof(filepath), "%s", files[choice - 1]);
            } else {
                snprintf(filepath, sizeof(filepath), "%s%s", DEMO, files[choice - 1]);
            }
            if (remove(filepath) == 0)
                printf("File '%s' deleted successfully.\n", files[choice - 1]);
            else
                perror("Failed to delete file");
        }

        else if (strcmp(cmd, "create") == 0) {
            if (strcmp(role, "admin") != 0 && !superuser(username)) {
                printf("[DENIED] Only admins or superusers can create files.\n");
                continue;
            }

            char filename[100];
            printf("Enter filename to create: ");
            fgets(filename, sizeof(filename), stdin);
            filename[strcspn(filename, "\n")] = 0;

            char filepath[512];

            snprintf(filepath, sizeof(filepath), "%s%s", DEMO, filename);
            FILE *fp = fopen(filepath, "w");
            if (!fp) { perror("Failed to create file"); continue; }
            fclose(fp);
            printf("File '%s' created successfully.\n", filename);
        }
        
         else if (strcmp(cmd, "read") == 0) {
            if (can_read(role) || superuser(username))
                filesystem_read(role, username);
            else
                printf("[DENIED] Permission denied.\n");
        }

        else {
            printf("Unknown command: '%s'. Type 'help' for available commands.\n", cmd);
        }
    }
}
