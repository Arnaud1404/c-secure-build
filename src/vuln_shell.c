#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ARGS 64
#define LEAK_BUFFER_SIZE 128

/* File-scoped pointer to hold an intentional memory leak
 * for analysis tools to detect. */
static char* globally_leaked_ptr = NULL;

/* Intentionally leaks memory and uses an unsafe copy
 * to be caught by analysis tools. */
static void trigger_memory_leak(void) {
  globally_leaked_ptr = malloc(LEAK_BUFFER_SIZE);
  if (globally_leaked_ptr != NULL) {
    strncpy(globally_leaked_ptr, "trigger", LEAK_BUFFER_SIZE - 1);
    globally_leaked_ptr[LEAK_BUFFER_SIZE - 1] = '\0';
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
    // Child process
    execvp(args[0], args);
    perror("execvp failed");
    exit(EXIT_FAILURE);
  } else if (pid == -1) {
    // Fork failed
    perror("fork failed");
    exit(EXIT_FAILURE);
  } else {
    // Parent process
    waitpid(pid, NULL, 0);
  }
}

/* Main REPL for the shell. Reads and executes commands
 * until 'exit' or EOF is received. */
int main(void) {
  char* input_buffer = NULL;
  size_t buffer_size = 0;
  ssize_t bytes_read;

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

    trigger_memory_leak();

    char* parsed_args[MAX_ARGS];
    parse_input(input_buffer, parsed_args);

    if (parsed_args[0] != NULL && strcmp(parsed_args[0], "exit") == 0) {
      break;
    }

    execute_command(parsed_args);
  }

  if (input_buffer != NULL) {
    explicit_bzero(input_buffer, buffer_size);
  }
  free(input_buffer);

  fprintf(stderr, "Leaked pointer usage: %p\n", (void*)globally_leaked_ptr);

  return 0;
}