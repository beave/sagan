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

/* parse-proto.c
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


int parse_proto( char *msg )  { 

int i; 

for (i = 0; i < counters->mapcount_message; i++) {

    if ( map_message[i].nocase == 1 ) { 
       if (!strcasestr(msg, map_message[i].search)) return(map_message[i].proto); 
       } else { 
       if (!strstr(msg, map_message[i].search)) return(map_message[i].proto);
       }
}
//if ( strcasestr(msg, " tcp ")   || strcasestr(msg, " tcp,")) return(6);
//if (strcasestr(msg, " udp " )   || strcasestr(msg, " udp,")) return(17);
//if (strcasestr(msg, " icmp " )  || strcasestr(msg, " icmp,")) return(1);

return(config->sagan_proto);
}

