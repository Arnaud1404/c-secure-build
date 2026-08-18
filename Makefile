
CFLAGS = -std=c17 -O2 -g -Wall -Wextra -Werror -pedantic
CFLAGS += -fPIE -fstack-protector-strong -Wformat -Wformat-security
CPPFLAGS = -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=3

LDFLAGS = -pie -Wl,-z,relro,-z,now

SANITIZE ?= 1
ifeq ($(SANITIZE),1)
    CFLAGS  += -fsanitize=address,undefined
    LDFLAGS += -fsanitize=address,undefined
endif

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

TARGET = $(BIN_DIR)/c-secure-shell
SRC = $(SRC_DIR)/vuln_shell.c
OBJ = $(OBJ_DIR)/vuln_shell.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
