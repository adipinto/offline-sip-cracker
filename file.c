/*
 * Copyright notice
 * ================
 *
 * Copyright (C) 2012
 *      Alessandro Di Pinto		<alessandro.dipinto@security.dico.unimi.it>
 *
 *  This program is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation, either version 3 of the License, or (at your option) any later
 *  version.
 *
 *  Offline SIP Cracker is distributed in the hope that it will be useful, but WITHOUT ANY
 *  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 *  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with
 *  this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "file.h"

/*
 * This function open in read-only mode a file specified by 'file' argument
 * and returns a file descriptor of open file.
 *
 * Note: if open operation fails, exit with a specific error code.
 */
FILE* open_file(const char* file) {
  FILE* fd = NULL;
  // Check if 'file' argument is a valid string, otherwise exits.
  if (file == NULL || strlen(file) <= 0) {
    printf("[!] Specified NULL filename.\n[!] Exit.\n");
    c_exit(DICT_FILENAME_ERROR);
  }
  // Try to open file in read-only mode
  fd = fopen(file, "r");
  // Check if file descriptor is correct, otherwise exits.
  if (fd == NULL) {
    printf("[!] Failed to open dictionary file '%s'\n[!] Exit.\n", file);
    c_exit(OPEN_FILE_ERROR);
  } else {
    if (VERBOSE)
      printf("[V] Dictionary file '%s' open successfully!\n", file);
    // Return file descritor of file open
    return fd;
  }
  // Dummy return
  return 0;
}

/*
 * This function read next string from already-open file specified by 'file' argument
 * and stores result string into pre-allocated string 'line'. It read only amout of bytes
 * specified by 'size' argument.
 *
 * Note: string read must be terminated by '\n' or '\r' caracter.
 * The function return FALSE on error, otherwise TRUE.
 */
int read_line(FILE *file, char* line, int size) {
  // Clear pre-existing values into 'line' string
  memset(line, 0x00, size);
  // Read 'size' bytes from 'file' file descriptor and stores result into 'line' string
  if (fgets ( line, size, file ) == NULL) {
    // Read failed, returns FALSE
    return FALSE;
  } else {
    // Remove trailing new line characters
    if (line[strlen(line) - 1] == '\n' || line[strlen(line) - 1] == '\r') {
      line[strlen(line) - 1] = '\0';
      if (line[strlen(line) - 2] == '\n' || line[strlen(line) - 1] == '\r') {
	line[strlen(line) - 2] = '\0';
      }
    }

    // Read successfully, returns TRUE
    return TRUE;
  }
}

/*
 * This function close a file descriptor specified by 'file' argument.
 */
void close_file(FILE *file) {
  // Check if 'file' argument is a valid file descriptor
  if (file == NULL)
    printf("[!] Close file failed! NULL file descriptor.\n");
  else
    // Release654 resource specified by file descritor
    fclose(file);
}
