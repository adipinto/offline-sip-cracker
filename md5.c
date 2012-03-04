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

#include "md5.h"

/*
 * This function calculates and return MD5 HASH of 'input_str' string specified.
 * In order to optimize performances, the result of MD5 computation will be stored
 * into variable pre-allocated and specified by argument (result).
 *
 * Note: if an error occurs it returns NULL, otherwise a memory pointer to MD5
 * HASH string allocated.
 */
void get_md5(const char* input_str, char* result) {
  // Checks input argument validity
  if (input_str == NULL || strlen(input_str) <= 0) {
    if (DEBUG)
      printf("[D] String argument specified to compute MD5 HASH is NULL and will be returned NULL!\n");
    result = NULL;
    return;
  }
  // Standard instructions to compute MD5 HASH
  EVP_MD_CTX mdctx;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  int i;
  
  EVP_DigestInit(&mdctx, EVP_md5());
  EVP_DigestUpdate(&mdctx, input_str, strlen(input_str));
  EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
  EVP_MD_CTX_cleanup(&mdctx);
  
  /* Convert MD5 digest's bytes in readable hexadecimal format and store the results
     directly into 'result' string. */
  for(i = 0; i < md_len; i++)
    sprintf(&result[i * 2], "%02x", md_value[i]);
  return;
}
