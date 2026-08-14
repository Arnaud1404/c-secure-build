CFLAGS = -std=c17 -O2 -Wall -Wextra -Werror -pedantic -g
SEC_FLAGS = -D_FORTIFY_SOURCE=3 -fPIE -pie -fstack-protector-strong -Wformat -Wformat-security

# Toggle ASan to prevent collisions with Valgrind during CI/CD dynamic testing.
# Default to 1 (local dev). CI/CD scripts will run: make SANITIZE=0
SANITIZE ?= 1
ifeq ($(SANITIZE),1)
	CFLAGS += -fsanitize=address
endif

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

TARGET = $(BIN_DIR)/c-secure-shell
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(SEC_FLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(SEC_FLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all dirs clean