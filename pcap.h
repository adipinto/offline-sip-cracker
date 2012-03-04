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

char errbuf[PCAP_ERRBUF_SIZE];

// Raw struct contains information used to authenticate the client
struct _sip_auth_info {
  char *server_nonce;
  char *server_realm;
  char *client_username;
  char *client_method;
  char *client_uri;
  char *client_md5_response;
  struct _sip_auth_info *next;	// Pointer to next struct, NULL if it's last struct.
  short registered;				// TRUE when registered successfully, FALSE otherwise.
  short cseq;					// Packet sequence number, default -1
  char *qop;
  char *cnonce;
  char *nonce_count;
  char *algorithm;
};

// Declare new type that contains sip authentication information
typedef struct _sip_auth_info sip_auth_info;

#define AUTH_CONST		"Authorization"
#define REGISTER_CONST	        "REGISTER"
#define CSEQ_CONST		"CSeq"
#define OK_CONST		"200 OK"
#define QOP_CONST               "qop="
#define CNONCE_CONST            "cnonce="
#define NCOUNT_CONST            "nc="
#define MD5_CONST               "algorithm="

// Function's prototype definitions
sip_auth_info* get_register_list(const char* filename);
void destroy_register_list(sip_auth_info *);
sip_auth_info* allocate_new_structure();
char* clean_packet_info(const char *, const struct pcap_pkthdr);
char* extract_string(const char*, const char*, short);
void print_register_list(sip_auth_info *);
int count_register_items(sip_auth_info *, short);
sip_auth_info* copy_register_item(sip_auth_info*);
sip_auth_info* get_register_item_by_index(sip_auth_info* , int);
