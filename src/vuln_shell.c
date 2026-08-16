#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ARGS 64
#define LEAK_BUFFER_SIZE 128

// A file-scoped static pointer to hold the leaked memory. This prevents the
// compiler from optimizing away the allocation, as the pointer's lifetime
// now spans the entire program execution.
static char* globally_leaked_ptr = NULL;

/* Intentional heap memory leak and unsafe strncpy usage.
 * Designed to trigger ASan, Valgrind, and Flawfinder CI/CD errors.
 */
static void trigger_memory_leak(void) {
  globally_leaked_ptr = malloc(LEAK_BUFFER_SIZE);
  if (globally_leaked_ptr != NULL) {
    strncpy(globally_leaked_ptr, "trigger", LEAK_BUFFER_SIZE - 1);
    globally_leaked_ptr[LEAK_BUFFER_SIZE - 1] = '\0';
  }
}

/* Splits the input string into individual arguments based on whitespace.
 * Modifies the input string in-place by inserting null terminators.
 */
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

/* Creates a child process to execute the command specified in args.
 * The parent process waits for the child to complete before returning.
 */
static void execute_command(char** args) {
  if (args[0] == NULL) {
    return;
  }

  pid_t pid = fork();

  if (pid == 0) {
    // Child process
    int status = execvp(args[0], args);
    if (status == -1) {
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

/* Main REPL (Read-Eval-Print Loop) for the shell.
 * Continuously prompts for user input, parses it, and executes commands.
 */
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

    // Handle "exit" command
    if (parsed_args[0] != NULL && strcmp(parsed_args[0], "exit") == 0) {
      break;
    }

    execute_command(parsed_args);
  }

  free(input_buffer);

  // This is the crucial step to defeat compiler optimization. By "using" the
  // globally_leaked_ptr in a way that has an observable side effect (like
  // printing to stderr), we force the compiler to preserve the malloc() call.
  // Without this, aggressive -O2 optimization can detect that the allocated
  // memory is never read and optimize the allocation away entirely.
  fprintf(stderr, "Leaked pointer usage: %p\n", (void*)globally_leaked_ptr);

  return 0;
}