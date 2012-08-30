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

#include "memory.h"

/*
 * This function allocates space in memory to store data. The size of allocation
 * is specified by 'size' argument. Return value is the pointer to allocated
 * memory address.
 */
char* allocate_memory(int size) {
  char *p_memory = NULL;
  if (size <= 0) {
    printf("[!] Size to allocation memory must be greater than 0\n[!] Exit.");
    c_exit(MALLOC_MEMORY_ERROR);
  } else {
    // Allocate and initialize sufficient memory-space
    p_memory = (char*)calloc(size, 1);
    // Handle allocation memory errors
    if (p_memory == NULL) {
      printf("[!] Allocation memory failed!\n[!] Exit.\n");
      c_exit(MALLOC_MEMORY_ERROR);
      // Dummy return
      return 0;
    } else {
      if (DEBUG)
	printf("[D] Allocated %d bytes into the memory.\n", size);
      // Return pointer to memory-allocated address
      return p_memory;
    }
  }
  // Dummy return
  return 0;
}

/*
 * This function re-allocates space in memory of 'ptr' specified. The size of re-allocation
 * is specified by 'size' argument. Return value is the pointer to re-allocated
 * memory address.
 *
 * Note: if 'ptr' specified in arguments is NULL, the function will allocate equally
 */
char* reallocate_memory(char* ptr, int size) {
  char *p_memory = NULL;
  if (size <= 0) {
    printf("[!] Size to re-allocation memory must be greater than 0\n[!] Exit.");
    c_exit(MALLOC_MEMORY_ERROR);
  } else {
    if (ptr == NULL) {
      if (DEBUG)
	printf("[D] Pointer to reallocate is NULL, will be allocated new space in memory.\n");
      // Allocate new requested memory-space
      p_memory = allocate_memory(size);
    }
    else {
      // Re-llocate requested memory-space
      p_memory = (char*)realloc(ptr, size);
    }

    // Handle allocation memory errors
    if (p_memory == NULL) {
      printf("[!] Re-allocation memory failed!\n[!] Exit.\n");
      c_exit(MALLOC_MEMORY_ERROR);
    } else {
      if (DEBUG)
	printf("[D] Re-allocated %d bytes into the memory.\n", size);
      // Initialize the new memory allocated
      memset(p_memory, 0x00, size);
    }
  }
  // Return pointer to memory-allocated address
  return p_memory;
}

/*
 * This function allocates memory-space to store string passed by
 * 'str' argument and returns pointer to allocated memory address.
 *
 *  * Note: if allocation operation fails, exit with a specific error code.
 */
char* create_string(const char* str) {
  char *sp = NULL;
  // Check if 'str' argument is a valid string, otherwise exits.
  if (str == NULL || strlen(str) == 0) {
    printf("[!] Failed to allocate memory for NULL string.\n[!] Exit.\n");
    c_exit(MALLOC_MEMORY_ERROR);
  }
  // Duplicate string
  sp = strdup(str);

  if (DEBUG)
    // Note: cast size_t into int
    printf("[D] Created string '%s', length: %d byte.\n", sp, (int)strlen(sp));
  // Return pointer to memory-allocated address
  return sp;
}

/*
 * This function releases memory resources allocated
 */
void free_memory(char* ptr) {
  if (ptr != NULL)
    free(ptr);
}
