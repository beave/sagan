/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
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
 * protocol-map.c and protocol.map files.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "sagan-defs.h"
#include "sagan.h"
#include "version.h"
#include "parsers/parsers.h"

#include "protocol-map.h"

extern struct _SaganConfig *config;
extern struct _SaganCounters *counters;
struct _Sagan_Protocol_Map_Message *map_message;
struct _Sagan_Protocol_Map_Program *map_program;

/****************************************************************************
 * Parse_Proto - Searches for simple clues from the message about what
 * protocl might have generated this event
 ****************************************************************************/

/* DEPERCIATED:  Parse_IP now handles all of this

int Parse_Proto( char *msg )
{

    int i;

    for (i = 0; i < counters->mapcount_message; i++)
        {

            if ( map_message[i].nocase == 1 )
                {
                    if (Sagan_stristr(msg, map_message[i].search, true))
                        {
                            return(map_message[i].proto);
                        }
                }
            else
                {
                    if (Sagan_strstr(msg, map_message[i].search))
                        {
                            return(map_message[i].proto);
                        }
                }
        }
    return(0);
}
*/

/****************************************************************************
 * Parse_Proto_Program - Attempts to determine the protocol that generate
 * the event by the program that generate it.
 ****************************************************************************/

int Parse_Proto_Program( char *program )
{

    int i;

    for (i = 0; i < counters->mapcount_program; i++)
        {

            if ( map_program[i].nocase == 1 )
                {
                    if (Sagan_stristr(program, map_program[i].program, true))
                        {
                            return(map_program[i].proto);
                        }
                }
            else
                {
                    if (Sagan_strstr(program, map_program[i].program))
                        {
                            return(map_program[i].proto);
                        }
                }
        }
    return(0);
}
