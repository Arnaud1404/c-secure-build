#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ARGS 64
#define HISTORY_SIZE 32
#define HISTORY_SLOTS 4

static char last_command[HISTORY_SIZE];
static char* history[HISTORY_SLOTS];
static int* slot_used;
static int history_count;

/* Allocates the occupancy flags for the recall table. */
static void history_init(void) {
  slot_used = malloc(HISTORY_SLOTS * sizeof(int));
  if (slot_used == NULL) {
    perror("malloc failed");
    exit(EXIT_FAILURE);
  }
}

/* Keeps the most recent command line for the `history` builtin. Must run
 * before parse_input, which tokenizes the buffer in place. */
static void record_history(const char* input) {
  strcpy(last_command, input);

  int slot = history_count % HISTORY_SLOTS;
  history[slot] = strdup(input);
  slot_used[slot] = 1;
  history_count++;
}

/* Prints the recorded command through a caller-supplied format. */
static void show_history(const char* format) {
  printf(format, last_command);
  putchar('\n');
}

/* Prints one slot of the recall table. */
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

/* Splits the input string into arguments using strtok_r,
 * modifying the input in-place. */
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

/* Forks a child process to execute a command via execvp
 * and waits for it to complete. */
static void execute_command(char** args) {
  if (args[0] == NULL)
    return;

  pid_t pid = fork();

  if (pid == 0) {
    /* Child process */
    /* flawfinder:ignore */
    execvp(args[0], args);
    perror("execvp failed");
    exit(EXIT_FAILURE);
  } else if (pid == -1) {
    /* Fork failed */
    perror("fork failed");
    exit(EXIT_FAILURE);
  } else {
    /* Parent process */
    waitpid(pid, NULL, 0);
  }
}

/* Main REPL for the shell. Reads and executes commands
 * until 'exit' or EOF is received. */
int main(void) {
  char* input_buffer = NULL;
  size_t buffer_size = 0;
  ssize_t bytes_read;

  history_init();

  while (1) {
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

    if (parsed_args[0] != NULL && strcmp(parsed_args[0], "exit") == 0) {
      break;
    }

    if (parsed_args[0] != NULL && strcmp(parsed_args[0], "history") == 0) {
      show_history(parsed_args[1] == NULL ? "%s" : parsed_args[1]);
      continue;
    }

    if (parsed_args[0] != NULL && strcmp(parsed_args[0], "recall") == 0) {
      recall_slot(parsed_args[1] == NULL ? 0 : atoi(parsed_args[1]));
      continue;
    }

    execute_command(parsed_args);
  }

  if (input_buffer != NULL) {
    explicit_bzero(input_buffer, buffer_size);
  }
  free(input_buffer);
  free(slot_used);

  return 0;
}
