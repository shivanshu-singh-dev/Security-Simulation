CC = gcc
CFLAGS = -Wall -Wextra -std=c11

# 2. Object Files
OBJ = main.o auth.o acl.o crypto.o shell.o audit.o session.o filesystem.o mfa.o sha256.o aes.o

# 3. Output Binary
ifeq ($(OS),Windows_NT)
    TARGET = run.exe
    CLEAN_CMD = del /Q /F *.o $(TARGET) 2>nul || exit 0
else
    TARGET = run
    CLEAN_CMD = rm -f *.o $(TARGET)
endif

# 4. Build Rule
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

# 5. Pattern Rule for Object Files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 6. Cleanup Rule
clean:
	$(CLEAN_CMD)

# 7. Rebuild Everything
rebuild: clean $(TARGET)
