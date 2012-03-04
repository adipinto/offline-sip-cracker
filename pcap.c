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

#include "pcap.h"
#include "memory.h"

/*
 * This function parses pcap file specified by 'filename' and creates a list of
 * information extracted. This data structure is a concatenated list and it's returned
 * when parse operations are finished.
 */
sip_auth_info* get_register_list(const char* filename) {
  // Packet counter
  unsigned int pkt_counter = 0, cseq;
  // PCAP file handler
  pcap_t *pcap_handler;
  // String to save info from packets, token string to splitting
  char *str, *tok, *tmp;
  // Header extracted from packets
  struct pcap_pkthdr header;
  // The actual packet
  const u_char *packet;
  // PCAP filter compiled
  struct bpf_program fp;
  // Concatenated list of SIP Authorization info (initialized to NULL)
  sip_auth_info *list = NULL;
  // SIP single header info
  sip_auth_info *sip_info = NULL;
  // Flag to save if actual packet is REGISTER message or "200 OK" message
  short register_pkt, registered_pkt;
  
  // Check filename
  if (filename == NULL || strlen(filename) == 0) {
    printf("[!] PCAP file specified is NULL!\n[!] Exit.\n");
    c_exit(OPEN_FILE_ERROR);
  }
  // Open pcap file specified by filename string
  pcap_handler = pcap_open_offline(filename, errbuf);
  if (pcap_handler == NULL) {
    printf("[!] PCAP file '%s' cannot be open correctly!\n[!] Exit.\n", filename);
    c_exit(OPEN_FILE_ERROR);
  }
  // Compile filter to get interested packets
  if(pcap_compile(pcap_handler, &fp, "udp && port 5060", 0, 0) == -1) {
    printf("[!] Raised following pcap error: %s\n", pcap_geterr(pcap_handler));
    c_exit(PCAP_FILTER_ERROR);
  }
  // Apply compiled filter!
  if(pcap_setfilter(pcap_handler, &fp) == -1) {
    printf("[!] Raised following pcap error: %s\n", pcap_geterr(pcap_handler));
    c_exit(PCAP_FILTER_ERROR);
  }
  // Iterate packets filtered
  while ( (packet = pcap_next(pcap_handler,&header)) ) {
    // Cast a pointer to the packet data
    char *pkt_ptr = (char*)packet;

    // Clean the packet from non-printable chars
    str = clean_packet_info(pkt_ptr, header);
    // Split string cleaned using 0x0A delimiter
    tok = strtok(str, "\n");
    register_pkt = FALSE;
    registered_pkt = FALSE;
    do {
      // Look for REGISTER segnature
      if (strstr(tok, REGISTER_CONST) != NULL) {
        // Segnature FOUND!
    	register_pkt = TRUE;
    	break;
      } else if (strstr(tok, OK_CONST) != NULL) {
      	// Segnature FOUND!
      	registered_pkt = TRUE;
      	break;
      }

    } while ( (tok = strtok(NULL, "\n")) != NULL);

    // If packet's type isn't REGISTER, skip packet.
    if (register_pkt == TRUE) {
      // While packet contains info..
      while( (tok = strtok(NULL, "\n")) != NULL) {
    	// Check if obtained info contains Authorization info
    	if (strstr(tok, AUTH_CONST)) {
    	  // Allocate in memory a new structure to store info
    	  sip_info = allocate_new_structure();
    	  sip_info->client_username = extract_string("username", tok, TRUE);
    	  sip_info->server_realm = extract_string("realm", tok, TRUE);
    	  sip_info->client_uri = extract_string("uri", tok, TRUE);
    	  sip_info->server_nonce = extract_string("nonce", tok, TRUE);
    	  sip_info->client_md5_response = extract_string("response", tok, TRUE);
    	  sip_info->client_method = extract_string("method", tok, TRUE);
    	  sip_info->registered = FALSE;
    	  sip_info->algorithm = create_string(MD5_ALGO);

    	  if (sip_info->client_method == NULL)
    	    sip_info->client_method = create_string(REGISTER_CONST);
    	  sip_info->cseq = -1;

    	  // Extract cseq value
    	  // Clean the packet from non-printable chars
    	  str = clean_packet_info(pkt_ptr, header);
    	  tok = strtok(str, "\n");
    	  do {
    	    if (strstr(tok, CSEQ_CONST)) {
    	      tok = strtok(tok, " ");
    	      tok = strtok(NULL, " ");
    	      sip_info->cseq = atoi(tok);
    	    }
    	  } while ( (tok = strtok(NULL, "\n")) != NULL);

          // Extract QOP, CNONCE and NC values
          // Clean the packet from non-printable chars
          str = clean_packet_info(pkt_ptr, header);
          tok = strtok(str, "\n");
          do {
            if (strstr(tok, AUTH_CONST)) {
              tok = strtok(tok, ",");
              do {
                if (strstr(tok, CNONCE_CONST)) {
                  tmp = extract_string("cnonce", tok, TRUE);
                  if (tmp == NULL)
                    tmp = extract_string("cnonce", tok, FALSE);
                  if (tmp == NULL) {
                      printf("[!] CNonce found but not extracted. Is it RFC compliant?\n");
                      sip_info->qop = NULL;
                      sip_info->cnonce = NULL;
                      sip_info->nonce_count = NULL;
                  }
                  sip_info->cnonce = tmp;
                }
                if (strstr(tok, QOP_CONST)) {
                  tmp = extract_string("qop", tok, FALSE);
                  if (tmp == NULL)
                    tmp = extract_string("qop", tok, TRUE);
                  if (tmp == NULL) {
                      printf("[!] QOP (Quality of Protection) found but not extracted. Is it RFC compliant?\n");
                      sip_info->qop = NULL;
                      sip_info->cnonce = NULL;
                      sip_info->nonce_count = NULL;
                  }
                  sip_info->qop = tmp;
                }
                if (strstr(tok, NCOUNT_CONST)) {
                  tmp = extract_string("nc", tok, FALSE);
                  if (tmp == NULL)
                    tmp = extract_string("nc", tok, TRUE);
                  if (tmp == NULL) {
                      printf("[!] Nonce Count found but not extracted. Is it RFC compliant?\n");
                      sip_info->qop = NULL;
                      sip_info->cnonce = NULL;
                      sip_info->nonce_count = NULL;
                  }
                  sip_info->nonce_count = tmp;
                }
                // Check Algorithm
                if (strstr(tok, MD5_CONST)) {
                    tmp = extract_string("algorithm", tok, FALSE);
                    if (tmp == NULL)
                      tmp = extract_string("algorithm", tok, TRUE);
                    // Algorithm detected and not equal to default algorithm
                    if (tmp != NULL && strcmp(tmp, MD5_ALGO) != 0) {
                      // Delete default algorithm and store new value extracted.
                      if (sip_info->algorithm != NULL) free_memory(sip_info->algorithm);
                      sip_info->algorithm = create_string(tmp);
                      printf("[!] New algorithm extracted: '%s'\n", sip_info->algorithm);
                    } else if (DEBUG && tmp != NULL)
                      printf("[D] Algorithm detected equals to default algorithm '%s'\n", MD5_ALGO);
                    if (DEBUG && tmp == NULL)
                      printf("[D] No algorithm value detected, will be used default value '%s'\n", sip_info->algorithm);

                }
              } while ( (tok = strtok(NULL, ",")) != NULL);
              break;
            }
          } while ( (tok = strtok(NULL, "\n")) != NULL);

          // Add item only if algorithm is supported
          if (sip_info->algorithm != NULL)
            // Add new item at head of list
            if (list != NULL)
                  sip_info->next = list;
            list = sip_info;

    	  // Increment number of authentication packet
    	  pkt_counter++;
    	  break;
    	}
      }
    } else if (registered_pkt == TRUE) {
      cseq = -1;
      while( (tok = strtok(NULL, "\n")) != NULL) {
        if (strstr(tok, CSEQ_CONST) && strstr(tok, REGISTER_CONST)) {
    	  tok = strtok(tok, " ");
    	  tok = strtok(NULL, " ");
    	  cseq = atoi(tok);
    	  break;
    	}
      }
      // CSeq found
      if (cseq >= 0) {
    	sip_auth_info *tmp = list;
    	// Look for node with extracted cseq, and set it to "registered"
    	while(tmp != NULL) {
    	  if (tmp->cseq == cseq) {
    		  tmp->registered = TRUE;
    		  break;
    	  }
    	  tmp = tmp->next;
    	}
      }
    }
    if (str) free(str);
  }

  if (DEBUG) {
    print_register_list(sip_info);
    printf("[D] Filtered %d packets from pcap file '%s'\n", pkt_counter, filename);
  }
  
  // Close pcap file handler
  pcap_close(pcap_handler);

  // Return data structure
  return sip_info;
}

/*
 * This function performs a regular expression check into 'original_str' with
 * specified 'pattern'. Return a substring extracted or NULL if operation fails.
 *
 * Note: is needed only keyword to search, automatically will be append a correct pattern.
 * Note: if quoted = TRUE then look for "pattern", otherwise look for pattern
 *
 * Warning: the pattern to search is CASE-INSENSITIVE! (test == TeST)
 */
char* extract_string(const char* pattern, const char* original_str, short quoted) {
  regex_t filter;
  regmatch_t result[2];
  char *new_str = NULL;
  // Exclude " char
  char *FIXED_PATTERN;
  if (quoted == TRUE)
    FIXED_PATTERN =  create_string("=\"([\x20,\x21,\x23-\x7E]*)\"");
  else
    FIXED_PATTERN =  create_string("=([\x20,\x21,\x23-\x7E]*)");
  if (pattern == NULL || original_str == NULL) {
    if (DEBUG)
      printf("[D] Pattern or string NULL! (return NULL)\n");
    return NULL;
  } else {
    // Create complete pattern
    new_str = allocate_memory(strlen(pattern) + strlen(FIXED_PATTERN) + 1);
    strcat(new_str , pattern);
    strcat(new_str , FIXED_PATTERN);
  }
  // Note: search for case-insensitive pattern and allow Posix EXTENDED regular expressions
  if (regcomp(&filter, new_str, REG_EXTENDED|REG_ICASE) != 0) {
    printf("[!] RegExp compile error!\n[!] Exit.\n");
    c_exit(PCAP_REGEXP_ERROR);
  }
  // Check regular expression
  if (regexec(&filter, original_str, (size_t)2, result, 0) == 0) {
    if (result[1].rm_eo > 0 && result[1].rm_eo - result[1].rm_so > 0) {
      // Release allocated resources
      free(new_str);
      /* 
       * Allocate memory to store substring extracted with pattern
       * Allocate memory to store also null-byte
       */
      new_str = allocate_memory(result[1].rm_eo - result[1].rm_so + 1);
      // "Safe" copy of substring
      strncpy(new_str, &original_str[result[1].rm_so], result[1].rm_eo - result[1].rm_so);
      regfree(&filter);
      return new_str;
    
    // Manage error
    } else {
      if (DEBUG)
	printf("[D] RegExp '%s' doesn't match! (return NULL)\n", pattern);
    }

  // Regular expression don't match!
  } else {
    if (DEBUG)
      printf("[D] RegExp '%s' doesn't match! (return NULL)\n", pattern);
  }
  regfree(&filter);
  return NULL;
}

/*
 * This function copies 'src' structure to new-allocated structure. All fields are also copied.
 *
 * Note: new created structure is returned by function, otherwise NULL.
 */
sip_auth_info* copy_register_item(sip_auth_info* src) {
  sip_auth_info *new_item;
  if (src == NULL) {
    if (DEBUG)
      printf("[D] Critical, it's specified NULL struct to copy function.\n");
    return NULL;
  } else {
    new_item = allocate_new_structure();
    new_item->client_md5_response = src->client_md5_response;
    new_item->client_method = src->client_method;
    new_item->client_uri = src->client_uri;
    new_item->client_username = src->client_username;
    new_item->server_nonce = src->server_nonce;
    new_item->server_realm = src->server_realm;
    new_item->registered = src->registered;
    new_item->cseq = src->cseq;
    new_item->nonce_count = src->nonce_count;
    new_item->cnonce = src->cnonce;
    new_item->qop = src->qop;
    new_item->algorithm = src->algorithm;
    new_item->next = NULL;
  }
  
  return new_item;
}

/*
 * This function parses each string from SIP packet and return a clean rapresentation.
 * Note: it's used to remove non printable characters from SIP packet.
 */
char* clean_packet_info(const char *pkt_ptr, const struct pcap_pkthdr header) {
  int i, k = 0; char *str;
  str = allocate_memory(header.len);
  for (i = 0; i < header.len; i++) {
    if (isprint(pkt_ptr[i]) || pkt_ptr[i] == 0x0A)
       str[k++] = pkt_ptr[i];
  }
  str[k] = '\0';
  return str;
}

/*
 * This function return a new-allocated copy of structure search it by an index.
 *
 * Note: new created structure is returned by function, otherwise NULL.
 */
sip_auth_info* get_register_item_by_index(sip_auth_info* list, int index) {
  sip_auth_info *tmp = list;
  if (index <= 0) {
    if (DEBUG)
      printf("[D] Negative or invalid index, return NULL\n");
    return NULL;
  }
  if (tmp == NULL) {
    if (DEBUG)
      printf("[D] List of structures is NULL! (return NULL)\n");
    return NULL;
  } else {
    do {
      if (--index == 0)
	return copy_register_item(tmp);
      else if (index < 0) break;
      tmp = tmp->next;
    } while (tmp != NULL);
  }
  return NULL;
}

/*
 * This function releases all resources allocated by specified list.
 */
void destroy_register_list(sip_auth_info *list) {
  // Return if is specified an empty list
  if (list == NULL)
    return;
  do {
    if (list->client_md5_response != NULL) free(list->client_md5_response);
    if (list->client_method != NULL) free(list->client_method);
    if (list->client_uri != NULL) free(list->client_uri);
    if (list->client_username != NULL) free(list->client_username);
    if (list->server_nonce != NULL) free(list->server_nonce);
    if (list->server_realm != NULL)	free(list->server_realm);
    if (list->qop != NULL)     free(list->qop);
    if (list->cnonce != NULL)     free(list->cnonce);
    if (list->nonce_count != NULL)     free(list->nonce_count);
    if (list->algorithm != NULL)     free(list->algorithm);
    free(list);
    list = list->next;
  } while (list != NULL);
  return;
}

/*
 * This function allocates space in memory to store SIP info. The size of allocation
 * is fixed. Return value is the pointer to allocated memory address.
 */
sip_auth_info* allocate_new_structure() {
  sip_auth_info *p_memory = NULL;
  // Allocate and initialize sufficient memory-space
  p_memory = (sip_auth_info*)malloc(sizeof(sip_auth_info));
  // Handle allocation memory errors
  if (p_memory == NULL) {
    printf("[!] Allocation memory failed!\n[!] Exit.\n");
    c_exit(MALLOC_MEMORY_ERROR);
    // Dummy return
    return 0;
  } else {

    // Initialize fields
    p_memory->client_md5_response = p_memory->client_method = p_memory->client_uri = p_memory->client_username =
      p_memory->server_nonce = p_memory->server_realm = p_memory->qop = p_memory->nonce_count = p_memory->cnonce = NULL;
    p_memory->registered = FALSE;
    p_memory->cseq = -1;
    p_memory->next = NULL;
    
    if (DEBUG)
      printf("[D] Allocated %d bytes into the memory.\n", (int)sizeof(sip_auth_info));
    // Return pointer to memory-allocated address
    return p_memory;
  }
  // Dummy return
  return 0;
}

/*
 * This function counts number of items into data structure and return it.
 */
int count_register_items(sip_auth_info *list, short only_registered) {
  int count = 0;
  sip_auth_info *tmp = list;
  while(tmp != NULL) {
    // If required, will skip not registered messages
    if ( only_registered == FALSE || (only_registered == TRUE && tmp->registered == TRUE) )
      count++;
    tmp = tmp->next;
  }
  if (DEBUG)
    printf("[D] The data structure contains %d items.\n", count);
  return count;
}



/*
 * Debug function, print out all structure values.
 */
void print_register_list(sip_auth_info *list) {
  int count = 1;
  sip_auth_info *tmp = list;
  while(tmp != NULL) {
    printf("[D] Structure n. %d\n", count++);
    printf("[D]\tUsername: %s\n", tmp->client_username);
    printf("[D]\tRealm: %s\n", tmp->server_realm);
    printf("[D]\tURI: %s\n", tmp->client_uri);
    printf("[D]\tNonce: %s\n", tmp->server_nonce);
    printf("[D]\tRegister: %s\n", tmp->client_method);
    printf("[D]\tRegistered: %d\n", tmp->registered);
    printf("[D]\tCSeq: %d\n", tmp->cseq);
    printf("[D]\tQOP: %s\n", tmp->qop);
    printf("[D]\tCNonce: %s\n", tmp->cnonce);
    printf("[D]\tNonceCount: %s\n", tmp->nonce_count);
    printf("[D]\tAlgorithm: %s\n", tmp->algorithm);
    printf("[D]\tMD5 Response: %s\n", tmp->client_md5_response);
    tmp = tmp->next;
  }
}
