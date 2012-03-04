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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <string.h>
#include <openssl/evp.h>
#include <getopt.h>
#include <time.h>
#include <pcap.h>
#include <regex.h>
#include <ctype.h> // import 'isdigit' function

// Constant definitions
#define	TRUE 		1
#define FALSE 		0
#define MD5_LEN         32
#define MD5_ALGO        "MD5"

// Software Version
#define VERSION		"1.0"
#define	AUTHOR		"Alessandro Di Pinto <alessandro.dipinto@security.dico.unimi.it>"
#define SOFT_NAME	"Offline SIP Cracker"

// Global variables
short DEBUG;
short VERBOSE;
const char* REAL_FILE_NAME;

// RETURN ERROR CODE LIST
#define CMD_LINE_ERROR         -1
#define EXIT_SUCCESS		0
#define EXIT_USAGE		1
#define MANDATORY_OPTION_ERROR	2
#define UNKNOWN_OPTION		3
#define NO_SESSION_TO_CRACK	4
#define MAX_SESSION_TO_CRACK	5
#define OUT_OF_SESSION		6
#define MALLOC_MEMORY_ERROR	20
#define DICT_FILENAME_ERROR	30
#define DICT_FILENAME_NULL	31
#define SIP_INFO_ERROR		32
#define OPEN_FILE_ERROR		40
#define CREATION_BLOCK_FAILED	50
#define PCAP_FILTER_ERROR	60
#define PCAP_REGEXP_ERROR	61
#define PCAP_FILENAME_ERROR	62

// Function's prototype definitions
void c_exit(int); // custom_exit
char* touppercase(char*);
void print_actual_time();
void print_start_time();
void print_end_time();
