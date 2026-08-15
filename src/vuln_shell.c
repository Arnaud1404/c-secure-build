#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>

#define MAX_ARGS 64
#define LEAK_BUFFER_SIZE 128

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

    char* leak_ptr = malloc(LEAK_BUFFER_SIZE);
    if (leak_ptr != NULL) {
      strncpy(leak_ptr, "trigger", LEAK_BUFFER_SIZE - 1);
      leak_ptr[LEAK_BUFFER_SIZE - 1] = '\0';
    }

    char* parsed_args[MAX_ARGS];
    char* tokenizer_state;
    int arg_count = 0;

    char* current_token = strtok_r(input_buffer, " \t", &tokenizer_state);

    while (current_token != NULL && arg_count < MAX_ARGS - 1) {
      parsed_args[arg_count++] = current_token;
      current_token = strtok_r(NULL, " \t", &tokenizer_state);
    }

    parsed_args[arg_count] = NULL;

    if (arg_count > 0) {
      printf("[DEBUG] Parsed command: %s with %d arguments.\n", parsed_args[0],
             arg_count);
    }
  }

  free(input_buffer);

  return 0;
}