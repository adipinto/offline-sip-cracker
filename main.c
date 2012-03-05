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

#include "main.h"

/* PROGRAM ENTRY-POINT */
int main(int argc, char *argv[]) {
  // Integer used to read input from commandline
  int cmdline;
  // File descriptor used to open in read-only mode the wordlist file
  FILE *file_descriptor = NULL;
  // File descriptor used to open pcap
  char *pcap_filename = NULL;
  // Common purpose variables
  int int_var, int_final_len;
  // filename of dictionary file
  char *dict_filename = NULL;
  // command-line information about sip authentication info (and also temporary variable)
  char *info = NULL;
  // temporary var to store sip authentication info (by strtok)
  char *split_info = NULL;
  // First information block composed by USERNAME:REALM:[PASSWORD_BY_WORDLIST]
  char first_md5_block[MD5_LEN + 1]  = {0};
  // First information block TEMPLATE used to create a complete first block MD5 (USERNAME:REALM:)
  char *first_string_block;
  // Second information block composed by METHOD:URI
  char second_md5_block[MD5_LEN + 1] = {0};
  // Final information block based on QOp value of response server.
  char final_md5_block[MD5_LEN + 1]  = {0};
  // Final string used to compute the final MD5 (that will be compared with MD5 to crack)
  char *final_string_block;
  // String read from dictionary file
  char line [MAX_WORDLIST_STRING_LEN] = {0};
  // High-level struct definited to store sip authentication info
  sip_auth_info *sip_info, *head_sip_info;
  int num_items, count_cracking;
  // Format string used to handles command-line arguments
  const char params_allowed[] = "hdvsf:i:p:";
  // FALSE = password not found; TRUE = password found
  short found;
  // FALSE = try to crack all passwords, TRUE = stop on first password found
  short stop_on_success;
  // TRUE = show only registered messages, FALSE otherwise
  short only_registered = TRUE;
  
  // Print actual time
  print_start_time();
  
  // Store into a global variable the real name of file executed
  if (argc <= 0 || argv[0] == NULL || strlen(argv[0]) <= 0) {
    printf("[!] Filename used to execute the program is invalid! (NULL?)\n[!] Exit.");
    c_exit(CMD_LINE_ERROR);
  } else {
    REAL_FILE_NAME = create_string(argv[0]);
  }
  // If there are not arguments, shows usage()
  if (argc == 1)
    usage();

  // Set default settings
  DEBUG = VERBOSE = stop_on_success = FALSE;
  // Perform check of command-line argument to find special values (es., debug, verbose, help)
  while ((int_var = getopt (argc, argv, params_allowed)) != -1) {
    // Parse command-line's arguments
    switch (int_var) {
    // Help
    case 'h':
      usage();
      break;
    // Enable debug information
    case 'd':
      if (DEBUG) break;
      printf("[D] Debug mode enabled.\n");
      DEBUG = TRUE;
      break;
    // Enable verbose information
    case 'v':
      if (VERBOSE) break;
      printf("[V] Verbose mode enabled.\n");
      VERBOSE = TRUE;
      break;
    // Manage command-line's exceptions
    case '?':
      c_exit(UNKNOWN_OPTION);
      break;
    }
  }
  // Reset the index in order to re-check from the first argument
  optind = 1;
  // Initialize data structure
  sip_info = NULL;
  while ((int_var = getopt (argc, argv, params_allowed)) != -1) {
    // Parse command-line's arguments
    switch (int_var) {
    case 's':
      if (DEBUG)
        printf("Exit on first success enabled.\n");
      stop_on_success = TRUE;
      break;
    // Dictionary filename
    case 'f':
      if (dict_filename != NULL) break;
      // Checks if argument's parameter is not another argument (starts with '-')
      if (optarg != NULL && strlen(optarg) > 0 && optarg[0] == '-') {
	printf("[!] Dictionary file starts with '-', it is not allowed.\n[!] Exit.\n");
	c_exit(DICT_FILENAME_ERROR);
      }
      if (optarg == NULL || strlen(optarg) == 0) {
	printf("[!] Dictionary file is NULL!\n[!] Exit.\n");
	c_exit(DICT_FILENAME_ERROR);
      }
      // Read argument specified by command-line
      dict_filename = create_string(optarg);
      break;
    // PCAP filename
    case 'p':
      if (pcap_filename != NULL) break;
      // Checks if argument's parameter is not another argument (starts with '-')
      if (optarg != NULL && strlen(optarg) > 0 && optarg[0] == '-') {
	printf("[!] PCAP file starts with '-', it is not allowed.\n[!] Exit.\n");
	c_exit(PCAP_FILENAME_ERROR);
      }
      if (optarg == NULL || strlen(optarg) == 0) {
	printf("[!] PCAP file is NULL!\n[!] Exit.\n");
	c_exit(PCAP_FILENAME_ERROR);
      }
      // Read argument specified by command-line
      pcap_filename = create_string(optarg);
      break;
    // SIP authentication information
    case 'i':
      if (info != NULL) break;
      if (optarg == NULL || strlen(optarg) == 0) {
	printf("[!] Information string is NULL!\n[!] Exit.\n");
	c_exit(MANDATORY_OPTION_ERROR);
      }
      // Check if argument's parameter is not another argument (starts with '-')
      if (optarg != NULL && strlen(optarg) > 0 && optarg[0] == '-') {
	printf("[!] SIP Username starts with '-' it is not allowed.\n[!] Exit.\n");
	c_exit(MANDATORY_OPTION_ERROR);
      }
      // Read argument specified by command-line
      info = create_string(optarg);
      // Allocate memory to store data structure
      sip_info = allocate_new_structure();
      // Set as single-element list
      sip_info->next = NULL;
      
      if (DEBUG)
	printf("[D] SIP authentication information:\n");
      split_info = strtok(info, ",");
      // Check if argument is correctly specified
      if (split_info != NULL) {
	if (DEBUG)
	  printf("[D] Username: %s\n", split_info);
	// Store information
	sip_info->client_username = create_string(split_info);
      } else {
	printf("[!] Username not correctly specified!\n");
	usage();	// Usage and exits.
      }
      // Get next token!
      split_info = strtok(NULL, ",");
      // Check if argument is correctly specified
      if (split_info != NULL) {
	if (DEBUG)
	  printf("[D] Realm: %s\n", split_info);
	// Store information
	sip_info->server_realm = create_string(split_info);
      } else {
	printf("[!] Realm not correctly specified!\n");
	usage();	// Usage and exits.
      }
      // Get next token!
      split_info = strtok(NULL, ",");
      // Check if argument is correctly specified
      if (split_info != NULL) {
	if (DEBUG)
	  printf("[D] Method: %s\n", split_info);
	// Store information
	sip_info->client_method = create_string(split_info);
      } else {
	printf("[!] Method not correctly specified!\n");
	usage();	// Usage and exits.
      }
      // Get next token!
      split_info = strtok(NULL, ",");
      // Check if argument is correctly specified
      if (split_info != NULL) {
	if (DEBUG)
	  printf("[D] URI: %s\n", split_info);
	// Store information
	sip_info->client_uri = create_string(split_info);
      } else {
	printf("[!] URI not correctly specified!\n");
	usage();	// Usage and exits.
      }
      // Get next token!
      split_info = strtok(NULL, ",");
      // Check if argument is correctly specified
      if (split_info != NULL) {
	if (DEBUG)
	  printf("[D] Server nonce: %s\n", split_info);
	// Store information
	sip_info->server_nonce = create_string(split_info);
      } else {
	printf("[!] Server nonce not correctly specified!\n");
	// Usage and exits.
	usage();
      }
      // Get next token!
      split_info = strtok(NULL, ",");
      // Check if argument is correctly specified
      if (split_info != NULL) {
	if (DEBUG)
	  printf("[D] Client MD5 response: %s\n", split_info);
	// Store information
	sip_info->client_md5_response = create_string(split_info);
      } else {
	printf("[!] Client MD5 response not correctly specified!\n");
	// Usage and exits.
	usage();
      }

      // Default set optional values
      sip_info->qop = NULL;
      sip_info->cnonce = NULL;
      sip_info->nonce_count = NULL;
      // Get next token! [PARSE OPTIONAL VALUES]
      split_info = strtok(NULL, ",");
      // Check if argument is correctly specified
      if (split_info != NULL) {
        if (DEBUG)
          printf("[D] Client nonce: %s\n", split_info);
        // Store information
        sip_info->cnonce = create_string(split_info);

        // Get next token!
        split_info = strtok(NULL, ",");
        // Check if argument is correctly specified
        if (split_info != NULL) {
          if (DEBUG)
            printf("[D] Nonce count: %s\n", split_info);
          // Store information
          sip_info->nonce_count = create_string(split_info);
          sip_info->qop = create_string(QOP_AUTH);
        } else {
          printf("[!] Client nonce specified but nonce count not correctly specified!\n");
          // Usage and exits.
          usage();
        }
      } else if (DEBUG)
        printf("[D] QOp values not specified, basic cracking will be performed.\n");
      // Set additional options
      sip_info->registered = TRUE;
      sip_info->cseq = 1;
      sip_info->algorithm = create_string(MD5_ALGO);

      if (VERBOSE || DEBUG)
	printf("[%s] SIP session's information parsed successfully!\n", VERBOSE ? "V" : "D");
      break;
    // Manage command-line's exceptions
    case '?':
      c_exit(UNKNOWN_OPTION);
      break;
    }
  }
  
  if (info == NULL && pcap_filename == NULL) {
    printf("[!] It is needed provide at least SIP authentication information or PCAP file!\n[!] Exit.\n");
    c_exit(MANDATORY_OPTION_ERROR);
  }
  
  // Check if parse pcap file
  if (pcap_filename != NULL) {
    // Choose when store information
    if (sip_info == NULL) {
      if (DEBUG)
        printf("[D] No sessions, will be create from scratch!\n");
      // Nothing provided, parse pcap file!
      sip_info = get_register_list(pcap_filename);
    }
    else {
      if (DEBUG)
        printf("[D] Single SIP session already presents!\n");
      // Manual info already provided, append parse results
      sip_info->next = get_register_list(pcap_filename);
    }
  }
  // Store head of data structure to delete it when finish
  head_sip_info = sip_info;

  // Print out info about number of sessions to crack..
  num_items = count_register_items(sip_info, only_registered);
  if (num_items > 999) {
    printf("[!] There are too much SIP sessions!\n");
    c_exit(MAX_SESSION_TO_CRACK);
  }
  if (num_items == 0) {
    printf("[!] There are not session to crack!\n[!] Exit\n");
    c_exit(NO_SESSION_TO_CRACK);
  } else {
    printf("[*] There %s %d session%s to crack.\n", (num_items == 1 ? "is" : "are"),  num_items,
	   (num_items == 1 ? "" : "s"));
  }

  // Show SIP session's menu
  print_register_menu(sip_info, only_registered);
  
  // Check mandatory options
  if (dict_filename == NULL) {
    printf("[!] Dictionary file not specified!\n[!] Exit.\n");
    c_exit(DICT_FILENAME_NULL);
  } else {
    // By default, exit.
    cmdline = 2;
    // Get user's input
    printf("\n[*] Select SIP Sessions to crack\n");
    printf("         0] All sessions.\n");
    printf("         1] Specific session\n");
    printf("         2] Quit.\n\n");
    printf("         Choose: ");
    // Read integer from commandline
    scanf("%d", &cmdline);
    // Parse result
    switch (cmdline) {
    // Crack all SIP sessions
    case 0:
      printf("[*] All SIP sessions will be cracked.\n");
      break;
    case 1:
      printf("         Specific session to crack: ");
      // Force user to insert correct value.
      cmdline = 0;
      scanf("%d", &cmdline);
      if (cmdline <= 0 || cmdline > num_items) {
	printf("[!] Error! Invalid SIP session (out of range?).\n[!] Exit.\n");
	c_exit(OUT_OF_SESSION);
      } else {
	printf("\n[*] Selected SIP session n. %d\n", cmdline);
	sip_info = get_register_item_by_index(sip_info, cmdline);
	printf("\tUsername:\t%s\n", sip_info->client_username);
	printf("\tRealm:\t\t%s\n", sip_info->server_realm);
	printf("\tURI:\t\t%s\n", sip_info->client_uri);
	printf("\tMD5 Response:\t%s\n\n", sip_info->client_md5_response);
      }
      break;
    // Exit.
    default:
      printf("[*] Exit.\n");
      c_exit(EXIT_SUCCESS);
      break;
    }
  }

  // Open in read-only mode the specified wordlist file
  file_descriptor = open_file(dict_filename);
  
  count_cracking = 1;
  while (sip_info != NULL) {
    // Skip not registered sessions, in required.
    if (only_registered == TRUE && sip_info->registered == FALSE) {
      if (DEBUG) printf("[D] Session CSeq '%d' skipped\n", sip_info->cseq);
      sip_info = sip_info->next;
      continue;
    }

    // Validate algorithm used to compute HASH response
    if (strlen(sip_info->client_md5_response) != MD5_LEN || strcmp(sip_info->algorithm, MD5_ALGO) != 0) {
        printf("[!] Session CSeq '%d' uses not implemented algorithm! (verbose mode to see CSeq info)\n", sip_info->cseq);
        sip_info = sip_info->next;
        continue;
    }

    printf("[*] Trying to cracking SIP session %d/%d\n", count_cracking++, cmdline == 0 ? num_items : 1);
    // Check if server has required use of QOp mechanism
    if (sip_info->qop != NULL) {
        // Check if QOp used is supported.
      if (strcmp(sip_info->qop, QOP_AUTH) != 0) {
        printf("[!] QOp value '%s' not supported! SIP session CSeq '%d' will be skipped.\n", sip_info->qop, sip_info->cseq);
        sip_info = sip_info->next;
        continue;
      }
      if (VERBOSE || DEBUG)
        printf("[%s] Will be used QOP (Quality of Protection) values.\n", VERBOSE ? "V" : "D");
    }
    /* Create the first information block to crack MD5 Digest -> 'USERNAME:REALM:[PASSWORD_FROM_WORDLIST]'
       Notes: Adds 2 bytes to colon separator and 1 byte null-byte */
    int_var = strlen(sip_info->client_username) + strlen(sip_info->server_realm) + 3;
    // Allocates memory-space to store TEMPLATE of first block (without password value)
    first_string_block = allocate_memory(int_var);
    if (sprintf(first_string_block, "%s:%s:", sip_info->client_username, sip_info->server_realm) < 0) {
      printf("[!] Creation of first block failed!\n[!] Exit.\n");
      c_exit(CREATION_BLOCK_FAILED);
    } else if (DEBUG) printf("[D] First block string '%s' created successfully!\n", first_string_block);
    
    
    /* Create the second information block to crack MD5 Digest -> 'METHOD:URI'
       Notes: Adds 1 byte to colon separator and 1 byte to null-byte */
    int_var = strlen(sip_info->client_method) + strlen(sip_info->client_uri) + 2;
    // Re-allocate memory used to parse command-line arguments ;)
    info = reallocate_memory(info, int_var);
    if (sprintf(info, "%s:%s", sip_info->client_method, sip_info->client_uri) < 0) {
      printf("[!] Creation of second block failed!\n[!] Exit.\n");
      c_exit(CREATION_BLOCK_FAILED);
    } else if (DEBUG) printf("[D] Second block string '%s' created successfully!\n", info);
    // Get MD5's string of second block (destination location initialized when has been declared)
    get_md5(info, second_md5_block);
    if (second_md5_block == NULL) {
      printf("[!] Creation of second block failed!\n[!] Exit.\n");
      c_exit(CREATION_BLOCK_FAILED);
    } else if (DEBUG) printf("[D] Second block MD5 '%s' computed successfully!\n", second_md5_block);
    
    /*
     * Value of maximum memory-space needed to store FIRST-BLOCK + PASSWORD-FROM-WORDLIST in worst case
     */
    int_var = (int)strlen(first_string_block) + MAX_WORDLIST_STRING_LEN + 1;
    if (DEBUG)
      printf("[D] First block length (worst case) before to compute MD5 HASH values %d bytes\n", int_var);
    // Allocate maximum memory-space needed to store FIRST-BLOCK + PASSWORD-FROM-WORDLIST in worst case
    info = reallocate_memory(info, int_var);
    
    if (sip_info->qop == NULL) {
      // Value of maximum length needed to store 'MD5-FIRST-BLOCK:nonce:MD5-SECOND-BLOCK' and the null-byte terminator character
      int_final_len = (MD5_LEN * 2) + (int)strlen(sip_info->server_nonce) + 2 + 1;
    } else {
      // Value of maximum length needed to store 'FIRST-BLOCK:SERVER-NONCE:NONCE_COUNT:CNONCE:QOP:SECOND-BLOCK'
      // and the null-byte terminator character
      int_final_len = (MD5_LEN * 2) + (int)(
                                              strlen(sip_info->server_nonce) +
                                              strlen(sip_info->qop) +
                                              strlen(sip_info->nonce_count) +
                                              strlen(sip_info->cnonce)
                                            ) + 2 + 1;
    }
    if (DEBUG)
      printf("[D] Final block length before to compute MD5 HASH values %d bytes\n", int_final_len);
    // Allocate maximum memory-space needed to store 'MD5-FIRST-BLOCK:nonce:MD5-SECOND-BLOCK' in worst case
    final_string_block = allocate_memory(int_final_len);
    // Reset stream
    fseek(file_descriptor, 0, SEEK_SET);
    
    /* Iterate the wordlist file and tries to crack the MD5 specified string by string */
    found = FALSE; // Set password not found, will be update if password will be found.
    while(read_line(file_descriptor, line, MAX_WORDLIST_STRING_LEN) == TRUE) {
      // Remove previous values from 'info'
      memset(info, 0x00, int_var);
      // Remove previous values from 'final_md5_block'
      memset(final_md5_block, 0x00, sizeof(final_md5_block));
      // Remove previous values from 'final_string_block'
      memset(final_string_block, 0x00, int_final_len);
      // Complete first block 'USERNAME:REALM:PASSWORD'
      sprintf(info, "%s%s", first_string_block, line);
      // Compute MD5 HASH for first complete block
      get_md5(info, first_md5_block);

      // Eval QOP (Quality of Protection)
      if (sip_info->qop == NULL)
        // Create complete final string FIRST-BLOCK:SERVER-NONCE:SECOND-BLOCK
        sprintf(final_string_block, "%s:%s:%s", first_md5_block, sip_info->server_nonce, second_md5_block);
      else
        // Create complete final string FIRST-BLOCK:SERVER-NONCE:NONCE_COUNT:CNONCE:QOP:SECOND-BLOCK
        sprintf(final_string_block, "%s:%s:%s:%s:%s:%s", first_md5_block, sip_info->server_nonce,
            sip_info->nonce_count, sip_info->cnonce,  sip_info->qop, second_md5_block);

      // Get MD5's string of final block
      get_md5(final_string_block, final_md5_block);
      if (VERBOSE)
	printf("[V] Testing password '%s' (MD5: %s)\n", line, final_md5_block);
      if (DEBUG) {
	printf("[D] MD5 of complete first block: %s -> %s\n", info, first_md5_block);
	printf("[D] MD5 of complete second block: %s -> %s\n", info, second_md5_block);
	printf("[D] MD5 of complete final block: %s -> %s\n", info, final_md5_block);
      }
      // Check if we found a clear-text password..
      if (strcmp(final_md5_block, sip_info->client_md5_response) == 0) {
	found = TRUE;
	printf("\tUsername:\t%s\n", sip_info->client_username);
	printf("\tRealm:\t\t%s\n", sip_info->server_realm);
	printf("\tURI:\t\t%s\n", sip_info->client_uri);
	printf("\tMD5 Response:\t%s\n", sip_info->client_md5_response);
	// Add time and data information about found password
	printf("\tFound at:\t");
	print_actual_time();
	// Password found!!! WE WON!
	printf("\t - Clear-text password found: [   %s   ]\n\n", line);
	if (stop_on_success == TRUE) {
	  printf("[*] First password found, exit forced.\n");
	  // Exit forced at next iteration
	  while (sip_info->next != NULL)
	    sip_info = sip_info->next;
	}
	break;
      }
    }
    
    // Print failed cracking :(
    if (found == FALSE)
      printf("[*] No valid password was found for this SIP session.\n");
    
    // Release memory allocated
    free_memory(first_string_block);
    free_memory(final_string_block);
    
    // Iterate structure's list, otherwise BREAK!
    if (sip_info->next != NULL)
      sip_info = sip_info->next;
    else
      break;
  }
  
  // Release resources used by file descriptor
  close_file(file_descriptor);
  
  // cmdline == 0 if all SIP sessions has been tried.
  if (cmdline != 0 && sip_info != NULL && head_sip_info != sip_info)
    destroy_register_list(sip_info);
  destroy_register_list(head_sip_info);
  
  // Release memory allocated
  free_memory(info);
  
  c_exit(EXIT_SUCCESS);
  return 0; // Dummy return
}

/*
 * This function print user's menu in order to choose session to crack
 */
void print_register_menu(sip_auth_info *list, short only_registered) {
  int count = 1;
  sip_auth_info *tmp = list;
  printf("[*] List of SIP sessions extracted:\n\n");
  while(tmp != NULL) {
    // If required, will skip not registered messages
    if ( only_registered == FALSE || (only_registered == TRUE && tmp->registered == TRUE) ) {
      printf("\t%2d] Username:\t\t%s\n", count++, tmp->client_username);
      printf("\t    Realm:\t\t%s\n", tmp->server_realm);
      printf("\t    URI:\t\t%s\n", tmp->client_uri);
      if (VERBOSE) {
        printf("\t[V] CSeq:\t\t%d\n", tmp->cseq);
        printf("\t[V] Registered:\t\t%s\n", tmp->registered == TRUE ? "TRUE" : "FALSE");
      }
      printf("\t    MD5 Response:\t%s\n", tmp->client_md5_response);
      printf("\t    -------------\n");
    }
    tmp = tmp->next;
  }
}

/*
 * This function simply print out software's information and usage
 */
void usage() {
  printf("\n%s v%s - Optimized SIP authentication cracking tool.\n", SOFT_NAME, VERSION);
  printf("     * Developed by %s\n", AUTHOR);
  printf("\nLegal Disclaimer:\n"
	 "\tUsage of '%s' for cracking target's aunthentication without\n"
	 "\tprior mutual consent is illegal. It is the end user's responsibility to obey\n"
	 "\tall applicable local, state and federal laws. The developer assumes no liabi-\n"
	 "\tlity and is not responsible for any crime or damage caused by this program.\n", SOFT_NAME);
  printf("\nUsage: %s [options]\n", REAL_FILE_NAME);
  printf("\nOptions:\n");
  
  printf("  Mandatory options:\n");
  
  printf("      -f DICTIONARY\tPath to dictionary file.\n");
  printf("      \t\t\t* Each string contained into dictionary file will be tested.\n"
	 "\t\t\t  The dictionary must contain one specific string for line.\n");
  
  printf("  Cracking options:\n");
  
  printf("      -p PCAP_FILE\tPath to PCAP file that contains dumped network traffic.\n");
  
  printf("      -i INFORMATION\tComma-separated information about SIP session to crack.\n");
  printf("      \t\t\t* INFORMATION will must be in order and comma-separated:\n"
	 "\t\t\t  USERNAME\tUsername used by SIP client.\n"
	 "\t\t\t  REALM\t\tRealm specified by registrar server.\n"
	 "\t\t\t  METHOD\tMethod used by client. (es., REGISTER)\n"
	 "\t\t\t  URI\t\tURI used by client. (es., sip:192.168.1.40)\n"
	 "\t\t\t  SERVER-NONCE\tChallenge nonce sent by server.\n"
	 "\t\t\t  CLIENT-MD5\tFinal MD5 sent by client.\n"
         "\t\t\t  [CNONCE,NC]\tOptional values, QOp will be set to 'auth' value.\n"
  );
  printf("      Note: at least one of above options will must be specified.\n\n");
  printf("  Optional options:\n");
  printf("      -s\t\tExit after the first password has been found.\n");
  printf("      -v\t\tVerbose mode. Show password for each attempt. (Slow)\n");
  printf("      -d\t\tDebug mode. Print debug info. (Very slow, for developers)\n");
  printf("      -h\t\tShow this summary help.\n");
  
  printf("\n  Usage examples:\n");
  printf("      - Advanced cracking of MD5 hash used by 'Lupus' user:\n");
  printf("          %s -f dict.txt -d -i Lupus,voip.com,REGISTER,sip:192.168.1.40,\n", REAL_FILE_NAME);
  printf("              350c0fec,098f6bcd4621d373cade4e832627b4f6\n");
  printf("\n");
  printf("      - Automatic cracking of MD5 hash extracted from traffic sniffed:\n");
  printf("          %s -f dict.txt -p sniffed_dump.pcap\n", REAL_FILE_NAME);
  printf("\n");
  print_end_time();
  exit(EXIT_USAGE);
}

