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
#include "input-pipe.h"

struct _SaganConfig *config;
struct _Syslog_JSON_Map *Syslog_JSON_Map;

void Load_Input_JSON_Map ( const char *json_map )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    FILE *json_map_file;
    char json_map_buf[10240] = { 0 };
    char is_nested_tmp[8] = { 0 };


    Sagan_Log(NORMAL, "Loading JSON FIFO mapping file. [%s]", json_map );

    /* Zero out the array */

    memset(Syslog_JSON_Map, 0, sizeof(_Syslog_JSON_Map));

    if (( json_map_file = fopen(json_map, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open JSON map file (%s)", __FILE__, __LINE__, json_map);
        }

    while(fgets(json_map_buf, 10240, json_map_file) != NULL)
        {

            /* Skip comments and blank lines */

            if (json_map_buf[0] == '#' || json_map_buf[0] == 10 || json_map_buf[0] == ';' || json_map_buf[0] == 32)
                {
                    continue;
                }

            json_obj = json_tokener_parse(json_map_buf);

            if ( json_object_object_get_ex(json_obj, "software", &tmp))
                {

                    Sagan_Log(NORMAL, "Found JSON mapping for '%s'.  Loading values.", config->json_input_software);

                    if ( !strcmp(json_object_get_string(tmp), config->json_input_software ) )
                        {

			    /* Is the target nested or not?  Default to "no" */

                            Syslog_JSON_Map->is_nested = false;
                            
                             if ( json_object_object_get_ex(json_obj, "nested", &tmp))
                            {

                            strlcpy(is_nested_tmp, json_object_get_string(tmp), sizeof(is_nested_tmp));

                            	    if ( !strcmp(is_nested_tmp, "yes") || !strcmp(is_nested_tmp, "true") ||
                            	!strcpy(is_nested_tmp, "enabled") )
                                {

				Syslog_JSON_Map->is_nested = true;

                                }

			   }
                           

                            if ( json_object_object_get_ex(json_obj, "syslog-source-ip", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_host,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_host));
                                }

                            if ( json_object_object_get_ex(json_obj, "facility", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_facility,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_facility));
                                }

                            if ( json_object_object_get_ex(json_obj, "level", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_level,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_level));
                                }

                            if ( json_object_object_get_ex(json_obj, "priority", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_priority,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_priority));
                                }

                            if ( json_object_object_get_ex(json_obj, "tags", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_tags,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_tags));
                                }

                            if ( json_object_object_get_ex(json_obj, "time", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_time,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_time));
                                }

                            if ( json_object_object_get_ex(json_obj, "date", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_date,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_date));
                                }

                            if ( json_object_object_get_ex(json_obj, "program", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_program,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_program));
                                }

                            if ( json_object_object_get_ex(json_obj, "message", &tmp))
                                {
                                    strlcpy(Syslog_JSON_Map->syslog_map_message,  json_object_get_string(tmp), sizeof(Syslog_JSON_Map->syslog_map_message));
                                }


                            /* Sanity check */

                            if ( Syslog_JSON_Map->syslog_map_host[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'syslog-source-ip'. Abort!",  config->json_input_software );
                                }

                            else if ( Syslog_JSON_Map->syslog_map_facility[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'facility'. Abort!",  config->json_input_software );
                                }

                            else if ( Syslog_JSON_Map->syslog_map_level[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'level'. Abort!",  config->json_input_software );
                                }

                            else if ( Syslog_JSON_Map->syslog_map_priority[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'priority'. Abort!",  config->json_input_software );
                                }

                            /*
                                                        else if ( Syslog_JSON_Map->syslog_map_tags[0] == '\0' )
                                                            {
                                                                Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'tags'. Abort!",  config->json_input_software );
                                                            }
                            */

                            else if ( Syslog_JSON_Map->syslog_map_time[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'time'. Abort!",  config->json_input_software );
                                }

                            else if ( Syslog_JSON_Map->syslog_map_date[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'date'. Abort!",  config->json_input_software );
                                }

                            else if ( Syslog_JSON_Map->syslog_map_program[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'program'. Abort!",  config->json_input_software );
                                }

                            else if ( Syslog_JSON_Map->syslog_map_message[0] == '\0' )
                                {
                                    Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'message'. Abort!",  config->json_input_software );
                                }

                            json_object_put(json_obj);

                            return;

                        }

                }

        }

    json_object_put(json_obj);

    Sagan_Log(ERROR, "No JSON mappings found for '%s'.  Abort!", config->json_input_software);

}

#endif
