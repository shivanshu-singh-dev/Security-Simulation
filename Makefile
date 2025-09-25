# 1. Variables
CC = gcc
CFLAGS = -Wall -Wextra -std=c11
OBJ = main.o auth.o acl.o crypto.o shell.o audit.o utils.o operations.o session.o filesystem.o

# 2. Final build rule
os_security: $(OBJ)
	$(CC) $(CFLAGS) -o os_security $(OBJ) -lcrypto

# 3. Compilation rule (pattern rule)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 4. Cleanup rule
clean:
	rm -f *.o os_security

