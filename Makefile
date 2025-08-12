# !!! IMPORTANT !!!
# Change this path to where you installed OpenSSL.
OPENSSL_DIR = C:/Program Files/OpenSSL-Win64

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g -O2 -I"$(OPENSSL_DIR)/include"

# Linker flags
LDFLAGS = -L"$(OPENSSL_DIR)/lib" -lssl -lcrypto

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
# Object files
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
# Executable name
TARGET = $(BIN_DIR)/secure_file_manager.exe

# The final executable file name
TARGET = $(BIN_DIR)/secure_file_manager

# The default goal of the Makefile. 'all' depends on the target executable.
all: $(TARGET)

# Rule to link the object files into the final executable
$(TARGET): $(OBJS)
	@echo "Linking..."
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "Build finished: $(TARGET)"

# Rule to compile a .c source file into a .o object file
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean up the project directory
clean:
	@echo "Cleaning up build artifacts..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Cleanup complete."

# Declare targets that are not actual files
.PHONY: all clean
