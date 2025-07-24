# Makefile for the Secure C File Manager

# Compiler and flags
CC = gcc
# -Wall: Show all warnings.
# -g: Include debugging information.
# -O2: Optimization level 2 for release builds.
# -I.: Include the current directory for header files (e.g., crypto.h).
CFLAGS = -Wall -g -O2 -I.

# Linker flags
# -lssl -lcrypto: Link against the OpenSSL libraries.
LDFLAGS = -lssl -lcrypto

# Directories
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# Automatically find all .c files in the source directory
SRCS = $(wildcard $(SRC_DIR)/*.c)

# Generate object file names from source file names
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

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
