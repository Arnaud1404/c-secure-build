#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ARGS 64
#define HISTORY_SIZE 32
#define HISTORY_SLOTS 4

static char last_command[HISTORY_SIZE];
static char* history[HISTORY_SLOTS];
static int* slot_used;
static int history_count;

/* calloc, not malloc: recall_slot reads flags for slots never written. */
static void history_init(void) {
  slot_used = calloc(HISTORY_SLOTS, sizeof(int));
  if (slot_used == NULL) {
    perror("calloc failed");
    exit(EXIT_FAILURE);
  }
}

/* Must run before parse_input, which tokenizes the buffer in place. */
static void record_history(const char* input) {
  snprintf(last_command, sizeof(last_command), "%s", input);

  int slot = history_count % HISTORY_SLOTS;
  /* The ring wraps, so this slot may already own a string. */
  free(history[slot]);
  history[slot] = strdup(input);
  slot_used[slot] = 1;
  history_count++;
}

/* The argument is user input, so it is never the format. */
static void show_history(void) { printf("%s\n", last_command); }

static void recall_slot(int slot) {
  if (slot < 0 || slot >= HISTORY_SLOTS) {
    printf("recall: slot out of range\n");
    return;
  }

  if (!slot_used[slot] || history[slot] == NULL) {
    printf("recall: empty slot\n");
  } else {
    printf("%s\n", history[slot]);
  }
}

/* strtol, not atoi: atoi has undefined behavior when the value does not fit
 * in an int, and returns 0 for text that is not a number at all. */
static bool parse_int(const char* text, int* out) {
  char* end;
  errno = 0;
  long value = strtol(text, &end, 10);

  if (end == text || *end != '\0' || errno == ERANGE || value < INT_MIN ||
      value > INT_MAX)
    return false;

  *out = (int)value;
  return true;
}

/* Tokenizes input in place. */
static void parse_input(char* input, char** args) {
  char* tokenizer_state;
  int arg_count = 0;
  char* current_token = strtok_r(input, " \t", &tokenizer_state);

  while (current_token != NULL && arg_count < MAX_ARGS - 1) {
    args[arg_count++] = current_token;
    current_token = strtok_r(NULL, " \t", &tokenizer_state);
  }

  args[arg_count] = NULL;
}

static void execute_command(char** args) {
  if (args[0] == NULL)
    return;

  pid_t pid = fork();

  if (pid == 0) {
    /* flawfinder:ignore */
    execvp(args[0], args);
    perror("execvp failed");
    exit(EXIT_FAILURE);
  } else if (pid == -1) {
    perror("fork failed");
    exit(EXIT_FAILURE);
  } else {
    waitpid(pid, NULL, 0);
  }
}

typedef enum {
  BUILTIN_NONE,
  BUILTIN_CONTINUE,
  BUILTIN_EXIT,
} builtin_result_t;

static builtin_result_t dispatch_builtin(char** args) {
  if (args[0] == NULL)
    return BUILTIN_NONE;

  if (strcmp(args[0], "exit") == 0)
    return BUILTIN_EXIT;

  if (strcmp(args[0], "history") == 0) {
    show_history();
    return BUILTIN_CONTINUE;
  }

  if (strcmp(args[0], "recall") == 0) {
    int slot = 0;
    if (args[1] != NULL && !parse_int(args[1], &slot))
      printf("recall: slot must be a number\n");
    else
      recall_slot(slot);
    return BUILTIN_CONTINUE;
  }

  return BUILTIN_NONE;
}

int main(void) {
  char* input_buffer = NULL;
  size_t buffer_size = 0;
  ssize_t bytes_read;
  int keep_running = 1;

  history_init();

  while (keep_running) {
    printf("c-sec> ");
    fflush(stdout);

    bytes_read = getline(&input_buffer, &buffer_size, stdin);

    if (bytes_read == -1) {
      printf("\nExiting...\n");
      break;
    }

    if (bytes_read > 0 && input_buffer[bytes_read - 1] == '\n') {
      input_buffer[bytes_read - 1] = '\0';
    }

    if (strlen(input_buffer) == 0)
      continue;

    record_history(input_buffer);

    char* parsed_args[MAX_ARGS];
    parse_input(input_buffer, parsed_args);

    switch (dispatch_builtin(parsed_args)) {
      case BUILTIN_EXIT:
        keep_running = 0;
        break;
      case BUILTIN_CONTINUE:
        continue;
      case BUILTIN_NONE:
        execute_command(parsed_args);
        break;
    }
  }

  if (input_buffer != NULL) {
    explicit_bzero(input_buffer, buffer_size);
  }

  free(input_buffer);
  for (int i = 0; i < HISTORY_SLOTS; i++) {
    free(history[i]);
  }

  free(slot_used);

  return 0;
}
