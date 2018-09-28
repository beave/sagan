/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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

/* Read data from fifo in a JSON format */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifndef HAVE_LIBFASTJSON
libfastjson is required for Sagan to function!
#endif


#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <string.h>


#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "message-json-map.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;

struct _JSON_Message_Map *JSON_Message_Map;

void Load_Message_JSON_Map ( const char *json_map )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    FILE *json_message_map_file;
    char json_message_map_buf[10240] = { 0 };

    Sagan_Log(NORMAL, "Loading JSON 'message' mapping for '%s'", config->json_message_map_file);

    /* Zero out the array */

    memset(JSON_Message_Map, 0, sizeof(_JSON_Message_Map));

    if (( json_message_map_file = fopen(json_map, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open JSON map file (%s)", __FILE__, __LINE__, json_map);
        }

    while(fgets(json_message_map_buf, 10240, json_message_map_file) != NULL)
        {

            /* Skip comments and blank lines */

            if (json_message_map_buf[0] == '#' || json_message_map_buf[0] == 10 || json_message_map_buf[0] == ';' || json_message_map_buf[0] == 32)
                {
                    continue;
                }


            JSON_Message_Map = (_JSON_Message_Map *) realloc(JSON_Message_Map, (counters->json_message_map+1) * sizeof(_JSON_Message_Map));


            if ( JSON_Message_Map == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _JSON_Message_Map. Abort!", __FILE__, __LINE__);
                }

            memset(&JSON_Message_Map[counters->json_message_map], 0, sizeof(struct _JSON_Message_Map));


            /* Set all values to NULL or 0 */

            strlcpy(JSON_Message_Map[counters->json_message_map].software, "NONE", 5);

            JSON_Message_Map[counters->json_message_map].hostname[0] = '\0';
            JSON_Message_Map[counters->json_message_map].program[0] = '\0';
            JSON_Message_Map[counters->json_message_map].message[0] = '\0';
            JSON_Message_Map[counters->json_message_map].eventid = -1;

            json_obj = json_tokener_parse(json_message_map_buf);


            if ( json_object_object_get_ex(json_obj, "software", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].software,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].software));
                }

            if ( json_object_object_get_ex(json_obj, "hostname", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].hostname,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].hostname));
                }

            if ( json_object_object_get_ex(json_obj, "program", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].program,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].program));
                }

            if ( json_object_object_get_ex(json_obj, "username", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].username,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].username));
                }

            if ( json_object_object_get_ex(json_obj, "message", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].message,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].message));
                }

            if ( json_object_object_get_ex(json_obj, "eventid", &tmp))
                {
                    JSON_Message_Map[counters->json_message_map].eventid = atol(json_object_get_string(tmp));
                }

            counters->json_message_map++;

        }

    json_object_put(json_obj);

}

#endif
