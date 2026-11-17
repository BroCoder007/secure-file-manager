CC ?= cc
PKG_CONFIG ?= pkg-config
PYTHON ?= python3

CPPFLAGS += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -MMD -MP
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo -lssl -lcrypto)
GTK_CFLAGS = $(shell $(PKG_CONFIG) --cflags gtk+-3.0)
GTK_LIBS = $(shell $(PKG_CONFIG) --libs gtk+-3.0)

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
COMMON_OBJS := $(BUILD_DIR)/crypto.o $(BUILD_DIR)/file_manager.o
CLI_OBJS := $(COMMON_OBJS) $(BUILD_DIR)/main.o
GUI_OBJS := $(COMMON_OBJS) $(BUILD_DIR)/gui_gtk.o
GUI_TEST_OBJS := $(COMMON_OBJS) $(BUILD_DIR)/test_gui.o
CLI_BIN := $(BIN_DIR)/secure_file_manager
GUI_BIN := $(BIN_DIR)/secure_gui
GUI_TEST_BIN := $(BIN_DIR)/secure_gui_tests

.PHONY: all cli gui test gui-test check sanitize clean
all: cli gui
cli: $(CLI_BIN)
gui: $(GUI_BIN)

$(CLI_BIN): $(CLI_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(OPENSSL_LIBS) $(LDLIBS) -o $@

$(GUI_BIN): $(GUI_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(GTK_LIBS) $(OPENSSL_LIBS) $(LDLIBS) -o $@

$(GUI_TEST_BIN): $(GUI_TEST_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(GTK_LIBS) $(OPENSSL_LIBS) $(LDLIBS) -o $@

$(BUILD_DIR)/test_gui.o: tests/test_gui.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_CFLAGS) $(GTK_CFLAGS) -c $< -o $@

$(BUILD_DIR)/gui_gtk.o: gui_gtk.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_CFLAGS) $(GTK_CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(OPENSSL_CFLAGS) -c $< -o $@

$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

test: cli
	SFM_CLI="$(abspath $(CLI_BIN))" $(PYTHON) tests/test_cli.py

gui-test: $(GUI_TEST_BIN)
	SFM_GUI_TEST="$(abspath $(GUI_TEST_BIN))" $(PYTHON) tests/run_gui_test.py

check: all test

# Use separate directories so normal optimized objects are never reused.
sanitize:
	$(MAKE) BUILD_DIR=build-sanitize BIN_DIR=bin-sanitize CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -MMD -MP -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined' test

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) build-sanitize bin-sanitize

-include $(wildcard $(BUILD_DIR)/*.d)
