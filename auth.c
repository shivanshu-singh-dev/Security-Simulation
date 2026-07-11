#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include <sys/types.h>

#include "auth.h"
#include "audit.h"
#include "mfa.h"

#define USERS "users.txt"

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif


// Password Masking
void get_password(char *password, int max_len) {
    int i = 0;
#ifdef _WIN32
    char ch;
    while (i < max_len - 1) {
        ch = _getch();
        if (ch == '\r' || ch == '\n') {
            break;
        } else if (ch == '\b') {
            if (i > 0) {
                i--;
            }
        } else {
            password[i++] = ch;
        }
    }
#else
    struct termios oldt, newt;
    char ch;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while (i < max_len - 1 && read(STDIN_FILENO, &ch, 1) == 1 && ch != '\n') {
        if (ch == 127 || ch == '\b') {
            if (i > 0) {
                i--;
            }
        } else {
            password[i++] = ch;
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    password[i] = '\0';
    printf("\n");
}

void flush_input() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

//Bypass Buffer for enter password
/*
static void prompt_now(const char *s) {
    write(STDOUT_FILENO, s, strlen(s));
    tcdrain(STDOUT_FILENO);
}
*/

void hash_password(const char *password, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

static int is_valid_username(const char *username) {
    size_t len = strlen(username);
    if (len == 0 || len >= 25) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = username[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

int register_user() {
    char username[25], password[25], hashed[100];
    char role[10];
    FILE *fp;

    printf("Enter username: ");
    scanf("%24s", username);
    flush_input();

    if (!is_valid_username(username)) {
        printf("Invalid username. Only alphanumeric characters, underscores, and hyphens are allowed.\n");
        return 0;
    }

    printf("Enter password: ");
    fflush(stdout);
    get_password(password, sizeof(password));

    hash_password(password, hashed);

    int choice;
    printf("Select role (0=Admin, 1=User, 2=Guest): ");
    scanf("%d", &choice);
    flush_input();

    if (choice == 0) strcpy(role, "admin");
    else if (choice == 1) strcpy(role, "user");
    else if (choice == 2) strcpy(role, "guest");
    else strcpy(role, "guest");

    fp = fopen(USERS, "a");
    if (!fp) {
        perror("Error opening user file");
        return 0;
    }
    fprintf(fp, "%s:%s:%s:0:0\n", username, hashed, role);
    fclose(fp);

    printf("User registered successfully with role %s!\n", role);
    return 1;
}

int login_user(char *username, char *role) {
    char password[100], hashed[65];
    char file_user[50], file_pass[65], file_role[10];
    int failed_attempts, locked;

    printf("Enter username: ");
    scanf("%49s", username);
    int c; while ((c = getchar()) != '\n' && c != EOF) {}

    if (!is_valid_username(username)) {
        printf("Invalid username.\n");
        return 0;
    }

    while (1) {
        printf("Enter password: ");
        fflush(stdout);
        get_password(password, sizeof(password));
        hash_password(password, hashed);

        FILE *fp = fopen(USERS, "r+");
        if (!fp) { perror("Error opening user file"); return 0; }

        FILE *temp = fopen("users.tmp", "w+");
        if (!temp) {
            perror("Error opening temporary user file");
            fclose(fp);
            return 0;
        }
        int found = 0, success = 0;

        while (fscanf(fp, "%49[^:]:%64[^:]:%9[^:]:%d:%d\n",
                      file_user, file_pass, file_role,
                      &failed_attempts, &locked) == 5) {

            if (strcmp(username, file_user) == 0) {
                found = 1;
                if (locked) {
                    printf("Account locked!\n");
                    fclose(fp); fclose(temp);
                    return 0;
                }
                else if (strcmp(hashed, file_pass) == 0) {      
                    if (strcmp(file_role, "admin") == 0) {
                        if (mfa_generate(username, 120) != 0) {
                            printf("Unable to generate MFA code. Login denied.\n");
                            fprintf(temp, "%s:%s:%s:%d:%d\n",
                                    file_user, file_pass, file_role, failed_attempts, locked);
                            fclose(fp); fclose(temp);
                            return 0;
                        }
                        
                        //MFA only for admin, the rest goes simply in later code

                        printf("An MFA code has been generated for user '%s'.\n", username);
                        printf("Check ./mfa_%s.txt for the code (expires in 120 seconds).\n", username);

                        int verified = 0;
                        while (1) {
                            int entered = -1;
                            printf("Enter MFA code: ");
                            if (scanf("%d", &entered) != 1) {
                                int cc; while ((cc = getchar()) != '\n' && cc != EOF);
                                printf("Invalid input. Try again.\n");
                                continue;
                            }
                            flush_input();

                            int res = mfa_verify(username, entered);
                            if (res == 1) {
                                printf("MFA verified.\n");
                                log_event(username, file_role, "MFA", "Success", NULL);
                                mfa_cleanup(username);
                                verified = 1;
                                break;
                            }
                            
                            else if (res == 0) {
                                int attempts_left = mfa_get_attempts(username);
                                printf("Incorrect code. Attempts left: %d\n", attempts_left);
                                log_event(username, file_role, "MFA", "FailedAttempt", NULL);
                                if (attempts_left <= 0) {
                                    printf("MFA locked due to too many failed attempts.\n");
                                    mfa_cleanup(username);
                                    failed_attempts++;
                                    if (failed_attempts >= 5) {
                                        locked = 1;
                                        printf("Account is now locked.\n");
                                        log_event(username, file_role, "Locked Account", "DONE", NULL);
                                    }
                                    break;
                                }
                                continue;
                            }
                            
                            else if (res == -1) {
                                printf("MFA code expired or not found. Login denied.\n");
                                log_event(username, file_role, "MFA", "Expired", NULL);
                                mfa_cleanup(username);
                                failed_attempts++;
                                if (failed_attempts >= 5) {
                                    locked = 1;
                                    printf("Account is now locked.\n");
                                    log_event(username, file_role, "Locked Account", "DONE", NULL);
                                }
                                break;
                            } else if (res == -2) {
                                printf("MFA locked due to too many failed attempts. Login denied.\n");
                                log_event(username, file_role, "MFA", "Locked", NULL);
                                mfa_cleanup(username);
                                failed_attempts++;
                                if (failed_attempts >= 5) {
                                    locked = 1;
                                    printf("Account is now locked.\n");
                                    log_event(username, file_role, "Locked Account", "DONE", NULL);
                                }
                                break;
                            } else {
                                printf("MFA verification error. Login denied.\n");
                                mfa_cleanup(username);
                                failed_attempts++;
                                if (failed_attempts >= 5) {
                                    locked = 1;
                                    printf("Account is now locked.\n");
                                    log_event(username, file_role, "Locked Account", "DONE", NULL);
                                }
                                break;
                            }
                        } // end MFA

                        if (verified) {
                            failed_attempts = 0;
                            success = 1;
                            strcpy(role, file_role);
                        }
                        else {
                          //Nothing
                        }
                    }
                    else {
                        // Non-admin: no MFA required
                        failed_attempts = 0;
                        success = 1;
                        strcpy(role, file_role);
                    }
                }
                else {
                    failed_attempts++;
                    printf("Login failed! Attempts: %d\n", failed_attempts);
                    if (failed_attempts >= 5) {
                        locked = 1;
                        printf("Account is now locked.\n");
                        log_event(username, file_role, "Locked Account", "DONE", NULL);
                    }
                }
            }
            fprintf(temp, "%s:%s:%s:%d:%d\n",
                    file_user, file_pass, file_role, failed_attempts, locked);
        }


        freopen(USERS, "w", fp);
        rewind(temp);
        int ch; while ((ch = fgetc(temp)) != EOF) fputc(ch, fp);

        fclose(fp); fclose(temp);
        remove("users.tmp");

        if (!found) {
            printf("User not found.\n");
            return 0;
        }

        if (success) {
            printf("Login successful! Role: %s\n", role);
            
            log_event(username, role, "Login", "Success", NULL);
            return 1;
        }
        if (locked) return 0;
    }
}

