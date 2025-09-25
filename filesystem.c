#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#define DEMO "Demo/"
#define ROOT "./" 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

#include "auth.h"
#include "filesystem.h"

// ---------- Role Permissions ----------
int can_read(const char *role) {
    return strcmp(role, "admin") == 0 || strcmp(role, "user") == 0 || strcmp(role, "guest") == 0;
}

int can_write(const char *role) {
    return strcmp(role, "admin") == 0 || strcmp(role, "user") == 0;
}

int can_execute(const char *role) {
    return strcmp(role, "admin") == 0;
}

// ---------- ACL Check ----------
int acl_allowed(const char *username, const char *filename) {
    if (strcmp(filename, "session.log") == 0 ||
        strcmp(filename, "audit.log") == 0 ||
        strcmp(filename, "users.txt") == 0) {
        return strcmp(username, "Shivanshu") == 0;
    }
    return 1; // all other files allowed
}

// ---------- Unified File Listing ----------
int list_all_files(char *files[], int max_files) {
    int count = 0;
    DIR *d;
    struct dirent *dir;

    // List Demo/ files
    d = opendir(DEMO);
    if (d) {
        while ((dir = readdir(d)) != NULL && count < max_files) {
            if (dir->d_type == DT_REG) {
                files[count++] = strdup(dir->d_name); // just filename
            }
        }
        closedir(d);
    }

    // Add special ACL files (in ROOT)
    const char *special[] = {"session.log", "audit.log", "users.txt"};
    for (int i = 0; i < 3 && count < max_files; i++) {
        files[count++] = strdup(special[i]);
    }

    return count;
}

// ---------- Read ----------
void filesystem_read(const char *role, const char *username) {
    if (!can_read(role)) {
        printf("Permission Denied: You cannot read files.\n");
        return;
    }

    char *files[100];
    int count = list_all_files(files, 100);

    if (count == 0) {
        printf("No files available to read.\n");
        return;
    }

    printf("Available files to read:\n");
    for (int i = 0; i < count; i++) {
        printf("%d. %s\n", i + 1, files[i]);
    }

    printf("Choose a file number to read: ");
    int choice;
    scanf("%d", &choice);
    flush_input();

    if (choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        goto cleanup;
    }

    const char *fname = files[choice - 1];

    if (!acl_allowed(username, fname)) {
        printf("[ACCESS DENIED] %s cannot access %s\n", username, fname);
        goto cleanup;
    }

    char filepath[1024];
	if ((strcmp(files[choice-1], "session.log") == 0 ||
	     strcmp(files[choice-1], "audit.log") == 0 ||
	     strcmp(files[choice-1], "users.txt") == 0) &&
	     strcmp(username, "Shivanshu") == 0) 
	{
	    snprintf(filepath, sizeof(filepath), "%s", files[choice-1]);
	} else {
	    snprintf(filepath, sizeof(filepath), "%s%s", DEMO, files[choice-1]); 
	}


    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        printf("Failed to open %s\n", filepath);
        goto cleanup;
    }

    printf("Contents of %s:\n", fname);
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }
    fclose(fp);
    printf("\n");

cleanup:
    for (int i = 0; i < count; i++) free(files[i]);
}

// ---------- Write ----------
void filesystem_write(const char *role, const char *username) {
    if (!can_write(role)) {
        printf("Permission Denied: You cannot write files.\n");
        return;
    }

    char *files[100];
    int count = list_all_files(files, 100);

    if (count == 0) {
        printf("No files available to write.\n");
        return;
    }

    printf("Available files to write:\n");
    for (int i = 0; i < count; i++) {
        printf("%d. %s\n", i + 1, files[i]);
    }

    printf("Choose a file number to write: ");
    int choice;
    scanf("%d", &choice);
    flush_input();

    if (choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        goto cleanup;
    }

    const char *fname = files[choice - 1];

    if (!acl_allowed(username, fname)) {
        printf("[ACCESS DENIED] %s cannot access %s\n", username, fname);
        goto cleanup;
    }

    char filepath[1024];
	if ((strcmp(files[choice-1], "session.log") == 0 ||
	     strcmp(files[choice-1], "audit.log") == 0 ||
	     strcmp(files[choice-1], "users.txt") == 0) &&
	     strcmp(username, "Shivanshu") == 0) 
	{
	    snprintf(filepath, sizeof(filepath), "%s", files[choice-1]);
	} else {
	    snprintf(filepath, sizeof(filepath), "%s%s", DEMO, files[choice-1]); 
	}


    FILE *fp = fopen(filepath, "a");
    if (!fp) {
        printf("Failed to open %s\n", filepath);
        goto cleanup;
    }

    char input[200];
    printf("Enter text to append: ");
    getchar();
    fgets(input, sizeof(input), stdin);

    time_t t = time(NULL);
    fprintf(fp, "[%s] %s", ctime(&t), input);
    fclose(fp);

    printf("Successfully appended to %s\n", fname);

cleanup:
    for (int i = 0; i < count; i++) free(files[i]);
}

// ---------- Execute ----------
void filesystem_exec(const char *role, const char *username) {
    if (!can_execute(role)) {
        printf("Permission Denied: You cannot execute files.\n");
        return;
    }

    char *files[100];
    int count = list_all_files(files, 100);

    if (count == 0) {
        printf("No files available to execute.\n");
        return;
    }

    printf("Available files to execute:\n");
    for (int i = 0; i < count; i++) {
        printf("%d. %s\n", i + 1, files[i]);
    }

    printf("Choose a file number to execute: ");
    int choice;
    scanf("%d", &choice);
    flush_input();

    if (choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        goto cleanup;
    }

    const char *fname = files[choice - 1];

    if (!acl_allowed(username, fname)) {
        printf("[ACCESS DENIED] %s cannot execute %s\n", username, fname);
        goto cleanup;
    }

    if (strcmp(fname, "session.log") == 0 || strcmp(fname, "audit.log") == 0 || strcmp(fname, "users.txt") == 0) {
        printf("These files cannot be executed.\n");
        goto cleanup;
    }

    char filepath[1024];
	if ((strcmp(files[choice-1], "session.log") == 0 ||
	     strcmp(files[choice-1], "audit.log") == 0 ||
	     strcmp(files[choice-1], "users.txt") == 0) &&
	     strcmp(username, "Shivanshu") == 0) 
	{
	    snprintf(filepath, sizeof(filepath), "%s", files[choice-1]);
	} else {
	    snprintf(filepath, sizeof(filepath), "%s%s", DEMO, files[choice-1]); 
	}


    const char *ext = strrchr(fname, '.');
    if (ext) {
        char *cmd = NULL, *exe = NULL;

        if (strcmp(ext, ".sh") == 0) {
            asprintf(&cmd, "bash %s", filepath);
        } else if (strcmp(ext, ".py") == 0) {
            asprintf(&cmd, "python3 %s", filepath);
        } else if (strcmp(ext, ".c") == 0) {
            asprintf(&exe, "%s_exec", fname);
            asprintf(&cmd, "gcc %s -o %s && ./%s", filepath, exe, exe);
        }

        if (cmd) {
            system(cmd);
            free(cmd);
        }
        free(exe);
    } else {
        printf("Cannot execute file with no extension safely.\n");
    }

cleanup:
    for (int i = 0; i < count; i++) free(files[i]);
}

