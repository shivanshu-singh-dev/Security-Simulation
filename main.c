#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shell.h"
#include "auth.h"
#include "operations.h"
#include "session.h"
#include "crypto.h"

#define BUF 100

extern unsigned char AES_KEY[32];
extern unsigned char AES_IV[16];

void decrypt_logs_if_authorized(const char *username, const char *password) {
    if (strcmp(username, "admin") != 0) {
        printf("You are not authorized to decrypt logs.\n");
        return;
    }

	    extern unsigned char AES_KEY[32];
	extern unsigned char AES_IV[16];

	if (decrypt_file("audit.enc", "audit_decrypted.log", AES_KEY, AES_IV)) {
	    printf("Audit log decrypted successfully\n");
	}
	if (decrypt_file("session.enc", "session_decrypted.log", AES_KEY, AES_IV)) {
	    printf("Session log decrypted successfully\n");
	}

}

int main() {
    char buffer[BUF];
    int choice;
    //generate_aes_key_iv(AES_KEY, AES_IV);
    init_aes_key_iv();

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

