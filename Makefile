CC = gcc
CFLAGS = -Wall -g -O2
LDFLAGS = -lssl -lcrypto
GTKFLAGS = `pkg-config --cflags --libs gtk+-3.0`

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

CLI_OBJS = $(BUILD_DIR)/crypto.o $(BUILD_DIR)/file_manager.o $(BUILD_DIR)/main.o
GUI_OBJS = $(BUILD_DIR)/crypto.o $(BUILD_DIR)/file_manager.o $(BUILD_DIR)/gui_gtk.o

CLI_BIN = $(BIN_DIR)/secure_file_manager
GUI_BIN = $(BIN_DIR)/secure_gui

.PHONY: all clean cli gui

all: $(CLI_BIN) $(GUI_BIN)

cli: $(CLI_BIN)

gui: $(GUI_BIN)

# --- CLI ---
$(CLI_BIN): $(CLI_OBJS) | $(BIN_DIR)
	$(CC) $(CLI_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# --- GUI ---
$(GUI_BIN): $(GUI_OBJS) | $(BIN_DIR)
	$(CC) $(GUI_OBJS) -o $@ $(LDFLAGS) $(GTKFLAGS)

$(BUILD_DIR)/gui_gtk.o: gui_gtk.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(GTKFLAGS)

# --- Shared sources ---
$(BUILD_DIR)/crypto.o: $(SRC_DIR)/crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/file_manager.o: $(SRC_DIR)/file_manager.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# --- Dirs ---
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
