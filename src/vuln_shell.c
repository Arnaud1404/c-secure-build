#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ARGS 64
#define LEAK_BUFFER_SIZE 128

/* Intentional heap memory leak and unsafe strncpy usage.
 * Designed to trigger ASan, Valgrind, and Flawfinder CI/CD errors.
 */
static void trigger_memory_leak(void) {
  char* leak_ptr = malloc(LEAK_BUFFER_SIZE);
  if (leak_ptr != NULL) {
    strncpy(leak_ptr, "trigger", LEAK_BUFFER_SIZE - 1);
    leak_ptr[LEAK_BUFFER_SIZE - 1] = '\0';
  }
}

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
  if (args[0] == NULL) {
    return;
  }

  pid_t pid = fork();

  if (pid == 0) {
    // Child process
    if (execvp(args[0], args) == -1) {
      perror("execvp failed");
    }
    exit(EXIT_FAILURE);
  } else if (pid == -1) {
    // Fork failed
    perror("fork failed");
  } else {
    // Parent process
    int status;
    waitpid(pid, &status, 0);
  }
}

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

    if (strlen(input_buffer) == 0) {
      continue;
    }

    trigger_memory_leak();

    char* parsed_args[MAX_ARGS];
    parse_input(input_buffer, parsed_args);
    execute_command(parsed_args);
  }

  free(input_buffer);

  return 0;
}