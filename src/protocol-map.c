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

/* gen-msg.c
 *
 * Reads in the sagan-gen-msg.map.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "protocol-map.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _Sagan_Protocol_Map_Message *map_message;
struct _Sagan_Protocol_Map_Program *map_program;

void Load_Protocol_Map( const char *map )
{

    FILE *mapfile;
    char mapbuf[1024];

    char *saveptr=NULL;

    char *map1=NULL;
    char *map2=NULL;
    char *map3=NULL;
    char *map4=NULL;

    counters->mapcount_message = 0;
    counters->mapcount_program = 0;

    Sagan_Log(NORMAL, "Loading protocol map file. [%s]", map);


    if (( mapfile = fopen(map, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open protocol map file (%s)", __FILE__, __LINE__, map);
        }

    while(fgets(mapbuf, 1024, mapfile) != NULL)
        {

            /* Skip comments and blank linkes */

            if (mapbuf[0] == '#' || mapbuf[0] == 10 || mapbuf[0] == ';' || mapbuf[0] == 32)
                {
                    continue;
                }
            else
                {
                    /* Allocate memory for references,  not comments */

                    map1 = strtok_r(mapbuf, "|", &saveptr);

                    if ( map1 == NULL )
                        {
                            Sagan_Log(ERROR, "%s is incorrect or not correctly formated (map1)", map);
                        }

                    Remove_Return(map1);
                    Remove_Spaces(map1);

                    map2 = strtok_r(NULL, "|", &saveptr);

                    if ( map2 == NULL )
                        {
                            Sagan_Log(ERROR, "%s is incorrect or not correctly formated (map2)", map);
                        }

                    Remove_Return(map2);
                    Remove_Spaces(map2);

                    map3 = strtok_r(NULL, "|", &saveptr);

                    if ( map3 == NULL )
                        {
                            Sagan_Log(ERROR, "%s is incorrect or not correctly formated (map3)", map);
                        }

                    Remove_Return(map3);
                    Remove_Spaces(map3);

                    map4 = strtok_r(NULL, "|", &saveptr);

                    if ( map4 == NULL )
                        {
                            Sagan_Log(ERROR, "%s is incorrect or not correctly formated (map4)", map);
                        }

                    Remove_Return(map4);
                    Remove_Spaces(map4);


                    if (!strcmp(map1, "message"))
                        {
                            map_message = (_Sagan_Protocol_Map_Message *) realloc(map_message, (counters->mapcount_message+1) * sizeof(_Sagan_Protocol_Map_Message));

                            if ( map_message == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for map_message. Abort!", __FILE__, __LINE__);
                                }

                            memset(&map_message[counters->mapcount_message], 0, sizeof(struct _Sagan_Protocol_Map_Message));


                            map_message[counters->mapcount_message].proto = atoi(map2);
                            if (!strcmp(map3, "nocase")) map_message[counters->mapcount_message].nocase = 1;
                            strlcpy(map_message[counters->mapcount_message].search, map4, sizeof(map_message[counters->mapcount_message].search));
                            counters->mapcount_message++;
                        }

                    if (!strcmp(map1, "program"))
                        {
                            map_program = (_Sagan_Protocol_Map_Program *) realloc(map_program, (counters->mapcount_program+1) * sizeof(_Sagan_Protocol_Map_Program));

                            if ( map_program == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for map_program. Abort!", __FILE__, __LINE__);
                                }

                            map_program[counters->mapcount_program].proto = atoi(map2);
                            if (!strcmp(map3, "nocase")) map_program[counters->mapcount_program].nocase = 1;
                            strlcpy(map_program[counters->mapcount_program].program, map4, sizeof(map_program[counters->mapcount_program].program));
                            counters->mapcount_program++;
                        }

                }

        }

    fclose(mapfile);
    Sagan_Log(NORMAL, "%d protocols loaded [Message search: %d|Program search: %d]", counters->mapcount_message + counters->mapcount_program, counters->mapcount_message, counters->mapcount_program);

}

