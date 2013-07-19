/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* This routine search the syslog message and/or program for clues about
 * what protocol generated an event.  For more information,  see the
 * sagan-protocol-map.c and protocol.map files. 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#define _GNU_SOURCE           /* for strcasestr() */

#include <stdio.h> 
#include <string.h> 

#include "sagan-defs.h"
#include "sagan.h"
#include "version.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _Sagan_Protocol_Map_Message *map_message;
struct _Sagan_Protocol_Map_Program *map_program;

/****************************************************************************
 * parse_proto - Searches for simple clues from the message about what 
 * protocl might have generated this event
 ****************************************************************************/

int parse_proto( char *msg )  { 

int i; 

for (i = 0; i < counters->mapcount_message; i++) {

    if ( map_message[i].nocase == 1 ) { 
       if (strcasestr(msg, map_message[i].search)) return(map_message[i].proto); 
       } else { 
       if (strstr(msg, map_message[i].search)) return(map_message[i].proto);
       }
   }
return(0);
}

/****************************************************************************
 * parse_proto_program - Attempts to determine the protocol that generate 
 * the event by the program that generate it.  
 ****************************************************************************/

int parse_proto_program( char *program ) { 

int i;

for (i = 0; i < counters->mapcount_program; i++) { 

    if ( map_program[i].nocase == 1 ) {
       if (strcasestr(program, map_program[i].program)) return(map_program[i].proto);
       } else { 
       if (strstr(program, map_program[i].program)) return(map_program[i].proto);
       }
   }
return(0); 
}
