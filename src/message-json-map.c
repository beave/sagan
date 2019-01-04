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
#include <json.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "message-json-map.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _SaganDebug *debug;

struct _JSON_Message_Map *JSON_Message_Map;
struct _JSON_Message_Tmp *JSON_Message_Tmp;

/*************************
 * Load JSON mapping file
 *************************/

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

            JSON_Message_Map[counters->json_message_map].program[0] = '\0';
            JSON_Message_Map[counters->json_message_map].message[0] = '\0';
	    JSON_Message_Map[counters->json_message_map].src_ip[0] = '\0'; 

            json_obj = json_tokener_parse(json_message_map_buf);

            if ( json_obj == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] JSON message map is incorrect at: \"%s\"", __FILE__, __LINE__, json_message_map_buf);
                    return;
                }

            if ( json_object_object_get_ex(json_obj, "program", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].program,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].program));
                }

            if ( json_object_object_get_ex(json_obj, "message", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].message,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].message));
                }

            if ( json_object_object_get_ex(json_obj, "src_ip", &tmp))
                {

                    strlcpy(JSON_Message_Map[counters->json_message_map].src_ip,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].src_ip));
                }


            counters->json_message_map++;

        }

    json_object_put(json_obj);

}

/************************************************************************
 * Parse_JSON_Message - Parses mesage (or program+message) for JSON data
 ************************************************************************/

void Parse_JSON_Message ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    struct _JSON_Message_Map_Found *JSON_Message_Map_Found = NULL;
    JSON_Message_Map_Found = malloc(sizeof(struct _JSON_Message_Map_Found) * JSON_MAX_NEST);

    if ( JSON_Message_Map_Found == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for JSON_Message_Map_Found. Abort!", __FILE__, __LINE__);
        }

    memset(JSON_Message_Map_Found, 0, sizeof(_JSON_Message_Map_Found) * JSON_MAX_NEST);

    uint16_t i=0;
    uint16_t a=0;

    uint32_t score=0;
    uint32_t prev_score=0;
    uint32_t pos=0;

    /* We start at 1 because the SaganProcSyslog_LOCAL->message is considered the
       first JSON string */

    uint16_t json_str_count=1;

    const char *val_str = NULL;

    bool has_message;
    bool found = false;

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    struct json_object_iterator it;
    struct json_object_iterator itEnd;

    char json_str[JSON_MAX_NEST][JSON_MAX_SIZE] = { { 0 } };

    strlcpy(json_str[0], SaganProcSyslog_LOCAL->syslog_message, sizeof(json_str[0]));

    json_obj = json_tokener_parse(SaganProcSyslog_LOCAL->syslog_message);

    /* If JSON parsing fails, it wasn't JSON after all */

    if ( json_obj == NULL )
        {
            Sagan_Log(WARN, "[%s, line %d] Detected JSON but function was incorrect. The log line was: \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);
            return;
        }

    it = json_object_iter_begin(json_obj);
    itEnd = json_object_iter_end(json_obj);

    /* Go through all key/values. We do this find nested json */

    while (!json_object_iter_equal(&it, &itEnd))
        {

            struct json_object *const val = json_object_iter_peek_value(&it);
            val_str = json_object_get_string(val);

            if ( val_str[0] == '{' || val_str[1] == '{' )
                {

                    /* If object looks like JSON, add it to array to be parsed later */

                    if ( json_str_count < JSON_MAX_NEST )
                        {
                            strlcpy(json_str[json_str_count], val_str, sizeof(json_str[json_str_count]));
                            json_str_count++;
                        }
                    else
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Detected JSON past max nest of %d! Skipping extra JSON.", __FILE__, __LINE__, JSON_MAX_NEST);
                        }
                }

            json_object_iter_next(&it);
        }

    if ( debug->debugjson )
        {

            for ( a=0; a < json_str_count; a++ )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] %d. JSON found: \"%s\"",  __FILE__, __LINE__, a, json_str[a]);

                }
        }


    /* Search message maps and see which one's match our syslog message best */

    for (i = 0; i < counters->json_message_map; i++ )
        {
            score = 0;

            for ( a = 0; a < json_str_count; a++ )
                {

                    json_obj = json_tokener_parse(json_str[a]);

                    if ( json_obj == NULL )
                        {
                            Sagan_Log(WARN, "[%s, line %d] Detected JSON Nest but function was incorrect. The log line was: \"%s\"", __FILE__, __LINE__, json_str[a]);
                            return;
                        }


                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].message, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].message, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].message));
                            has_message = true;
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].program, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].program, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].program));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].src_ip, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].src_ip, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].src_ip));

//			    JSON_Message_Map_Found[i].json_src_flag = true; 

                            score++;
                        }


                }

            if ( score > prev_score && has_message == true )
                {

                    pos = i;
                    prev_score = score;
                    found = true;
                }

        }

    if ( debug->debugjson )
        {

            if ( found == true )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Best message mapping match is at postion %d (score of %d)", __FILE__, __LINE__, found, pos, prev_score );
                }
            else
                {
                    Sagan_Log(DEBUG, "[%s, line %d] No JSON mappings found", __FILE__, __LINE__);
                }

        }

    /* We have to have a "message!" */

    SaganProcSyslog_LOCAL->json_src_flag = false;

    if ( found == true )
        {

            /* Keep a copy of the original message before altering */

            // strlcpy(SaganProcSyslog_LOCAL->syslog_message_json, SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message_json));

            /* Put JSON values into place */

            strlcpy(SaganProcSyslog_LOCAL->syslog_message, JSON_Message_Map_Found[pos].message, sizeof(SaganProcSyslog_LOCAL->syslog_message));

	    if ( JSON_Message_Map_Found[pos].src_ip != '\0' ) 
		{
		SaganProcSyslog_LOCAL->json_src_flag = true; 
            strlcpy(SaganProcSyslog_LOCAL->src_ip, JSON_Message_Map_Found[pos].src_ip, sizeof(SaganProcSyslog_LOCAL->src_ip));
		}


	    /* Don't override syslog program if no program is present */

	    if ( JSON_Message_Map_Found[pos].program[0] != '\0' ) {

            strlcpy(SaganProcSyslog_LOCAL->syslog_program, JSON_Message_Map_Found[pos].program, sizeof(SaganProcSyslog_LOCAL->syslog_program));

	    }




            if ( debug->debugjson )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] New data extracted from JSON:", __FILE__, __LINE__);
                    Sagan_Log(DEBUG, "[%s, line %d] -------------------------------------------------------", __FILE__, __LINE__);
                    Sagan_Log(DEBUG, "[%s, line %d] Message: \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message );
                    Sagan_Log(DEBUG, "[%s, line %d] Program: \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_program );
                    Sagan_Log(DEBUG, "[%s, line %d] src_ip : \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->src_ip );


                }


        }

    json_object_put(json_obj);

}

#endif
