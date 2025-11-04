CC = gcc
CFLAGS = -Wall -Wextra -std=c11

# 2. Object Files
OBJ = main.o auth.o acl.o crypto.o shell.o audit.o session.o filesystem.o mfa.o

# 3. Output Binary
TARGET = run

# 4. Build Rule
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) -lcrypto

# 5. Pattern Rule for Object Files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 6. Cleanup Rule
clean:
	rm -f *.o $(TARGET)

# 7. Rebuild Everything
rebuild: clean $(TARGET)
