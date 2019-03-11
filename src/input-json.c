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

#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "input-pipe.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;

struct _Syslog_JSON_Map *Syslog_JSON_Map;

void SyslogInput_JSON( char *syslog_string, struct _SyslogInput *SyslogInput )
{

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    struct json_object_iterator it;
    struct json_object_iterator itEnd;

    const char *val_str = NULL;

    uint16_t json_str_count=1;
    uint16_t a;

    bool has_message = false;

    char json_str[JSON_MAX_NEST][JSON_MAX_SIZE] = { { 0 } };

    char syslog_host[MAX_SYSLOG_HOST] = { 0 };
    char syslog_facility[MAX_SYSLOG_FACILITY] = { 0 };
    char syslog_priority[MAX_SYSLOG_PRIORITY] = { 0 };
    char syslog_level[MAX_SYSLOG_LEVEL] = { 0 };
    char syslog_tag[MAX_SYSLOG_TAG] = { 0 };
    char syslog_date[MAX_SYSLOG_DATE] = { 0 };
    char syslog_time[MAX_SYSLOG_TIME] = { 0 };
    char syslog_program[MAX_SYSLOG_PROGRAM] = { 0 };
    char syslog_message[MAX_SYSLOGMSG] = { 0 };

    memset(SyslogInput, 0, sizeof(_SyslogInput));

    memcpy(SyslogInput->syslog_message, "UNDEFINED\0", sizeof(SyslogInput->syslog_message));
    memcpy(SyslogInput->syslog_program, "UNDEFINED\0", sizeof(SyslogInput->syslog_program));
    memcpy(SyslogInput->syslog_time, "UNDEFINED\0", sizeof(SyslogInput->syslog_time));
    memcpy(SyslogInput->syslog_date, "UNDEFINED\0", sizeof(SyslogInput->syslog_date));
    memcpy(SyslogInput->syslog_tag, "UNDEFINED\0", sizeof(SyslogInput->syslog_tag));
    memcpy(SyslogInput->syslog_level, "UNDEFINED\0", sizeof(SyslogInput->syslog_level));
    memcpy(SyslogInput->syslog_priority, "UNDEFINED\0", sizeof(SyslogInput->syslog_priority));
    memcpy(SyslogInput->syslog_facility, "UNDEFINED\0", sizeof(SyslogInput->syslog_facility));
    memcpy(SyslogInput->syslog_host, "UNDEFINED\0", sizeof(SyslogInput->syslog_host));

    /* If the json isn't nested,  we can do this the easy way */

    if ( Syslog_JSON_Map->is_nested == false )
        {

            json_obj = json_tokener_parse(syslog_string);

            if ( json_obj == NULL )
                {

                    if ( json_str[a][0] != '\0' )
                        {
                            Sagan_Log(WARN, "[%s, line %d] Libfastjson failed to decode JSON. The log line was: \"%s\"", __FILE__, __LINE__, json_str[a]);
                        }
                    else
                        {
                            Sagan_Log(WARN, "[%s, line %d] Libfastjson failed to decode JSON. The log line was NULL", __FILE__, __LINE__);
                        }

                    json_object_put(json_obj);
                    __atomic_add_fetch(&counters->malformed_json_input_count, 1, __ATOMIC_SEQ_CST);
                    return;
                }


            __atomic_add_fetch(&counters->json_input_count, 1, __ATOMIC_SEQ_CST);

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_host, &tmp))
                {
                    strlcpy(SyslogInput->syslog_host, json_object_get_string(tmp), sizeof(SyslogInput->syslog_host));
                }

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_facility, &tmp))
                {
                    strlcpy(SyslogInput->syslog_facility, json_object_get_string(tmp), sizeof(SyslogInput->syslog_facility));
                }

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_priority, &tmp))
                {
                    strlcpy(SyslogInput->syslog_priority, json_object_get_string(tmp), sizeof(SyslogInput->syslog_priority));
                }

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_level, &tmp))
                {
                    strlcpy(SyslogInput->syslog_level, json_object_get_string(tmp), sizeof(SyslogInput->syslog_level));
                }

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_tag, &tmp))
                {
                    strlcpy(SyslogInput->syslog_tag, json_object_get_string(tmp), sizeof(SyslogInput->syslog_tag));
                }

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_date, &tmp))
                {
                    strlcpy(SyslogInput->syslog_date, json_object_get_string(tmp), sizeof(SyslogInput->syslog_date));
                }

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_time, &tmp))
                {
                    strlcpy(SyslogInput->syslog_time, json_object_get_string(tmp), sizeof(SyslogInput->syslog_time));
                }

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_program, &tmp))
                {
                    strlcpy(SyslogInput->syslog_program, json_object_get_string(tmp), sizeof(SyslogInput->syslog_program));
                }

            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_message, &tmp))
                {
                    snprintf(SyslogInput->syslog_message, sizeof(SyslogInput->syslog_message)," %s", json_object_get_string(tmp));
                    SyslogInput->syslog_message[ (sizeof(SyslogInput->syslog_message) -1 ) ] = '\0';
                    has_message = true;
                }

        }
    else
        {

            /* The raw syslog is the first "nested" level".  Copy that */

            strlcpy(json_str[0], syslog_string, sizeof(json_str[0]));
            json_obj = json_tokener_parse(syslog_string);

            if ( json_obj == NULL )
                {

                    if ( debug->debugmalformed )
                        {
                            Sagan_Log(WARN, "[%s, line %d] Libfastjson failed to decode JSON input. The log line was: \"%s\"", __FILE__, __LINE__, syslog_string);
                        }

                    json_object_put(json_obj);
                    __atomic_add_fetch(&counters->malformed_json_input_count, 1, __ATOMIC_SEQ_CST);
                    return;
                }

            it = json_object_iter_begin(json_obj);
            itEnd = json_object_iter_end(json_obj);

            /* Search through all key/values looking for embedded JSON */

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

                    /* Search through the nest to see if we can find out values */

                    for ( a = 0; a < json_str_count; a++ )
                        {

                            struct json_object *json_obj = NULL;
                            json_obj = json_tokener_parse(json_str[a]);

                            if ( json_obj == NULL )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Detected JSON nest but Libfastjson errors. The log line was: \"%s\"", __FILE__, __LINE__, json_str[a]);
                                    json_object_put(json_obj);
                                    __atomic_add_fetch(&counters->malformed_json_input_count, 1, __ATOMIC_SEQ_CST);
                                    return;
                                }

                            __atomic_add_fetch(&counters->json_input_count, 1, __ATOMIC_SEQ_CST);

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_message, &tmp))
                                {
                                    snprintf(SyslogInput->syslog_message, sizeof(SyslogInput->syslog_message)," %s", json_object_get_string(tmp));
                                    SyslogInput->syslog_message[ (sizeof(SyslogInput->syslog_message) -1 ) ] = '\0';
                                    has_message = true;
                                }

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_host, &tmp))
                                {
                                    strlcpy(SyslogInput->syslog_host, json_object_get_string(tmp), sizeof(SyslogInput->syslog_host));
                                }

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_facility, &tmp))
                                {
                                    strlcpy(SyslogInput->syslog_facility, json_object_get_string(tmp), sizeof(SyslogInput->syslog_facility));
                                }

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_priority, &tmp))
                                {
                                    strlcpy(SyslogInput->syslog_priority, json_object_get_string(tmp), sizeof(SyslogInput->syslog_priority));
                                }

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_level, &tmp))
                                {
                                    strlcpy(SyslogInput->syslog_level, json_object_get_string(tmp), sizeof(SyslogInput->syslog_level));
                                }

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_tag, &tmp))
                                {
                                    strlcpy(SyslogInput->syslog_tag, json_object_get_string(tmp), sizeof(SyslogInput->syslog_tag));
                                }

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_date, &tmp))
                                {
                                    strlcpy(SyslogInput->syslog_date, json_object_get_string(tmp), sizeof(SyslogInput->syslog_date));
                                }

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_time, &tmp))
                                {
                                    strlcpy(SyslogInput->syslog_time, json_object_get_string(tmp), sizeof(SyslogInput->syslog_time));
                                }

                            if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_program, &tmp))
                                {
                                    strlcpy(SyslogInput->syslog_program, json_object_get_string(tmp), sizeof(SyslogInput->syslog_program));
                                }

                        }

                }
        }


    if ( has_message == false )
        {
            Sagan_Log(WARN, "[%s, line %d] Received JSON which has no decoded 'message' value. The log line was: \"%s\"", __FILE__, __LINE__, syslog_string);
        }

    json_object_put(json_obj);
}

#endif
