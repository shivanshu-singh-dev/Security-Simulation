#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <sys/types.h>

#include "auth.h"
#include "audit.h"

#define USERS "users.txt"

#include <termios.h>
#include <unistd.h>

// Password Masking
void get_password(char *password, int max_len) {
    struct termios oldt, newt;
    int i = 0;
    char ch;


    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;


    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while (i < max_len - 1 && read(STDIN_FILENO, &ch, 1) == 1 && ch != '\n') {
        password[i++] = ch;
    }
    password[i] = '\0';

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

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

int register_user() {
    char username[50], password[50], hashed[100];
    char role[10];
    FILE *fp;

    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    fflush(stdout);
    get_password(password, sizeof(password));
    flush_input();

    hash_password(password, hashed);

    int choice;
    printf("Select role (0=Admin, 1=User, 2=Guest): ");
    scanf("%d", &choice);
    flush_input();

    if (choice == 0) strcpy(role, "admin");
    else if (choice == 1) strcpy(role, "user");
    else if (choice == 2) strcpy(role, "guest");
    else strcpy(role, "guest");  //else condition other than 0 1 2

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

    while (1) {
        printf("Enter password: ");
        fflush(stdout);
        get_password(password, sizeof(password));
        hash_password(password, hashed);

        FILE *fp = fopen(USERS, "r+");
        if (!fp) { perror("Error opening user file"); return 0; }

        FILE *temp = tmpfile();
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
                    failed_attempts = 0;
                    success = 1;
                    strcpy(role, file_role); 
                }
                else {
                    failed_attempts++;
                    printf("Login failed! Attempts: %d\n", failed_attempts);
                    if (failed_attempts >= 5) {
                        locked = 1;
                        printf("Account is now locked.\n");
                        log_event(username, role, "Locked Account", "DONE");
                    }
                }
            }
            fprintf(temp, "%s:%s:%s:%d:%d\n",
                    file_user, file_pass, file_role, failed_attempts, locked); 
        }

        //log_event(username, "Login", success ? "Success" : "Failure");
	//Dicarded
	
        freopen(USERS, "w", fp);  
        rewind(temp);
        int ch; while ((ch = fgetc(temp)) != EOF) fputc(ch, fp);

        fclose(fp); fclose(temp);

        if (!found) {
            printf("User not found.\n");
            return 0;
        }

        if (success) {
            printf("Login successful! Role: %s\n", role);
            log_event(username, role, "Login", success ? "Success" : "Failure");
            return 1;
        }
        if (locked) return 0;
    }
}

