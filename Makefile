
CFLAGS = -std=c17 -O2 -g -Wall -Wextra -Werror -pedantic
CFLAGS += -fPIE -fstack-protector-strong -Wformat -Wformat-security
CPPFLAGS = -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=3

LDFLAGS = -pie -Wl,-z,relro,-z,now

ASAN ?= 1
VALGRIND ?= 0

ifeq ($(VALGRIND),1)
    ASAN := 0
endif

ifeq ($(ASAN),1)
    CFLAGS  += -fsanitize=address,undefined
    LDFLAGS += -fsanitize=address,undefined
endif

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
SEC_DIR = .security
HOOK_DIR = .githooks

TARGET = $(BIN_DIR)/c-secure-shell
SRC = $(SRC_DIR)/vuln_shell.c
OBJ = $(OBJ_DIR)/vuln_shell.o

.PHONY: all clean scan hooks

all: $(TARGET)

$(TARGET): $(OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@

scan:
	./scripts/scan.sh

hooks:
	git config core.hooksPath $(HOOK_DIR)
	@echo "pre-commit hook installed: core.hooksPath = $(HOOK_DIR)"

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(SEC_DIR)
