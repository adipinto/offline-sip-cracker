#include "globals.h"
#include "memory.h"

/*
 * This function calculate the actual time in special formatted string.
 * On error, will be returned NULL value.
 */
void print_actual_time() {
  time_t timer;
  char *buffer;
  struct tm* tm_info;

  // Allocate buffer
  buffer = allocate_memory(25);
  time(&timer);
  tm_info = localtime(&timer);
  // Get formatted time string
  if (strftime(buffer, 25, "%H:%M:%S - %d/%m/%Y", tm_info) != 0) {
    printf("%s\n", buffer);
    // Release resource allocated
    free(buffer);
  } else {
    printf("[time_calculation_error");
  }
}

/*
 * Convert each characters in 'str' into uppercase value.
 */
char* touppercase(char *str) {
  if (str == NULL)
    return "";
  while (*str != '\0')
    if (islower(*str))
      *str = toupper(*str);
  return str;
}

/*
 * The following two functions, print out formatted time
 */
void print_start_time() {
  printf("[*] Started at ");
  print_actual_time();
}

void print_end_time() {
  // Disable debug mode, prevent unformatted print of time.
  DEBUG = FALSE;
  printf("[*] Terminated at ");
  print_actual_time();
}

/*
 * This function before exit, print the actual time.
 */
void c_exit(int exit_code) {
  // Print actual time
  print_end_time();
  // Exit with specified code.
  exit(exit_code);
}
