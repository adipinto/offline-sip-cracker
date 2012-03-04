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

#include "globals.h"
#include "md5.h"
#include "memory.h"
#include "file.h"
#include "pcap.h"

// Constant definitions
// Maximum string lenght of every single word into the wordlist file
#define MAX_WORDLIST_STRING_LEN	   100
#define MAX_COMMANDLINE_LEN	   10

// Supported QOp methods
#define QOP_AUTH                   "auth"

// Import variables from external source
// from getopt.h
extern char* optarg;
// from getopt.h
extern int optind;

// Function's prototype definitions
void usage();
void print_register_menu(sip_auth_info *, short);
