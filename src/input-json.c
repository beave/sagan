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
#include "debug.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;

struct _Syslog_JSON_Map *Syslog_JSON_Map;

typedef struct _JSON_Key_String _JSON_Key_String;
struct _JSON_Key_String
{
    char key[JSON_MAX_KEY_SIZE];
    char json[JSON_MAX_VALUE_SIZE];
};


void SyslogInput_JSON( char *syslog_string, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    struct json_object *json_obj = NULL;

    uint16_t i;
    uint16_t array_count = 1; 	/* Start at one! */

    int json_count = 1;
    int new_json_count = 0;

    struct json_object_iterator it;
    struct json_object_iterator itEnd;

    char new_key[JSON_MAX_KEY_SIZE] = { 0 };
    char tmp_key[JSON_MAX_KEY_SIZE] = { 0 };

    const char *key = NULL;
    const char *val_str = NULL;
    struct json_object *val;

    struct _JSON_Key_String *JSON_Key_String;
    JSON_Key_String = malloc(sizeof(_JSON_Key_String) * JSON_MAX_NEST );

    if ( JSON_Key_String == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _JSON_Key_String", __FILE__, __LINE__);
        }

    struct _JSON_Key_String *JSON_Key_String_J;
    JSON_Key_String_J = malloc(sizeof(_JSON_Key_String) * JSON_MAX_NEST );

    if ( JSON_Key_String_J == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _JSON_Key_String_J", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL, 0, sizeof(_Sagan_Proc_Syslog));

    memcpy(SaganProcSyslog_LOCAL->syslog_program, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_time, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_date, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_tag, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_level, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_priority, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_facility, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_host, "0.0.0.0\0", 8);

    SaganProcSyslog_LOCAL->md5[0] = '\0';
    SaganProcSyslog_LOCAL->event_id[0] = '\0';

    SaganProcSyslog_LOCAL->json_count = 0;

    /* The raw syslog is the first "nested" level".  Copy that.  This will be the
       first entry in the array  */

    JSON_Key_String[0].key[0] = '\0';
    JSON_Key_String_J[0].key[0] = '\0';

    memcpy(JSON_Key_String[0].json, syslog_string, JSON_MAX_VALUE_SIZE);
    memcpy(JSON_Key_String_J[0].json, syslog_string, JSON_MAX_VALUE_SIZE);

    __atomic_add_fetch(&counters->json_input_count, 1, __ATOMIC_SEQ_CST);

    /* Search through all key/values looking for embedded JSON */

    while ( json_count != 0 )
        {

            for ( i = 0; i < json_count; i++ )
                {

                    new_json_count = 0;

                    json_obj = json_tokener_parse(JSON_Key_String[i].json);

                    /* Did we parse the JSON okay? */

                    if ( json_obj == NULL )
                        {

                            if ( debug->debugmalformed )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Libfastjson failed to decode JSON input. The log line was: \"%s\"", __FILE__, __LINE__, JSON_Key_String[i].json);
                                }

                            json_object_put(json_obj);

                            __atomic_add_fetch(&counters->malformed_json_input_count, 1, __ATOMIC_SEQ_CST);
                            return;
                        }

                    it = json_object_iter_begin(json_obj);
                    itEnd = json_object_iter_end(json_obj);

                    while (!json_object_iter_equal(&it, &itEnd))
                        {

                            key = json_object_iter_peek_name(&it);
                            val = json_object_iter_peek_value(&it);
                            val_str = json_object_get_string(val);

                            /* New nest ? */

                            if ( val_str[0] == '{' )
                                {

                                    /* Is this a nest within a nest? */

                                    if ( new_json_count == 0 )
                                        {
                                            snprintf(tmp_key, JSON_MAX_KEY_SIZE, ".%s", key);
                                            tmp_key[JSON_MAX_KEY_SIZE - 1] = '\0';
                                            strlcpy(new_key, tmp_key, JSON_MAX_KEY_SIZE);
                                        }
                                    else
                                        {
                                            snprintf(new_key, JSON_MAX_KEY_SIZE, ".%s", key);
                                            new_key[JSON_MAX_KEY_SIZE - 1] = '\0';
                                        }


                                    /* Store found nested JSON */

                                    strlcpy(JSON_Key_String_J[array_count].key, new_key, JSON_MAX_KEY_SIZE);
                                    strlcpy(JSON_Key_String_J[array_count].json, val_str, JSON_MAX_VALUE_SIZE);

                                    /* Comitune searching array */

                                    strlcpy(JSON_Key_String[new_json_count].key, new_key, JSON_MAX_KEY_SIZE);
                                    strlcpy(JSON_Key_String[new_json_count].json, val_str, JSON_MAX_VALUE_SIZE);

                                    new_json_count++;           /* json found this loop */
                                    array_count++;              /* Total nested/json found */

                                }

                            json_object_iter_next(&it);

                        }
                }

            json_count = new_json_count;        /* Are we still finding json? */

        }  /* end of while */

    /* Copy objects into memory */

    for (i = 0; i < array_count; i++ )
        {
            json_obj = json_tokener_parse(JSON_Key_String_J[i].json);
            it = json_object_iter_begin(json_obj);
            itEnd = json_object_iter_end(json_obj);

            while (!json_object_iter_equal(&it, &itEnd))
                {

                    key = json_object_iter_peek_name(&it);
                    val = json_object_iter_peek_value(&it);
                    val_str = json_object_get_string(val);

                    if ( val_str[0] != '{' )
                        {

                            snprintf(new_key, JSON_MAX_KEY_SIZE, "%s.%s", JSON_Key_String_J[i].key, key);
                            new_key[ JSON_MAX_KEY_SIZE - 1] = '\0';

                            strlcpy( SaganProcSyslog_LOCAL->json_key[SaganProcSyslog_LOCAL->json_count], new_key, JSON_MAX_KEY_SIZE);
                            strlcpy( SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count], val_str, JSON_MAX_VALUE_SIZE);
                            SaganProcSyslog_LOCAL->json_count++;

                        }

                    json_object_iter_next(&it);
                }
        }

    json_object_put(json_obj);


    /* User wants the entire JSON to become the "message" */

    if ( !strcmp(Syslog_JSON_Map->syslog_map_message, "%JSON%" ) )
        {
            snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), "%s", syslog_string);
            SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';
        }


    for (i = 0; i < SaganProcSyslog_LOCAL->json_count; i++ )
        {

            /* Strings - Don't use else if, because all values need to be parsed */

            if ( !strcmp(Syslog_JSON_Map->syslog_map_message, SaganProcSyslog_LOCAL->json_key[i] ) )
                {

                    /* We add a "space" for things like normalization */

                    snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), " %s", SaganProcSyslog_LOCAL->json_value[i]);
                    SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';
                }

            if ( !strcmp(Syslog_JSON_Map->event_id, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->event_id, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->event_id));
                }

            if ( !strcmp(Syslog_JSON_Map->syslog_map_host, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_host));
                }

            if ( !strcmp(Syslog_JSON_Map->syslog_map_facility, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                }

            if ( !strcmp(Syslog_JSON_Map->syslog_map_priority, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                }

            if ( !strcmp(Syslog_JSON_Map->syslog_map_level, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_level));
                }

            if ( !strcmp(Syslog_JSON_Map->syslog_map_tag, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                }

            if ( !strcmp(Syslog_JSON_Map->syslog_map_date, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_date));
                }

            if ( !strcmp(Syslog_JSON_Map->syslog_map_time, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_time));
                }

            if ( !strcmp(Syslog_JSON_Map->syslog_map_program, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_program));
                }

            if ( !strcmp(Syslog_JSON_Map->src_ip, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->src_ip));
                }

            if ( !strcmp(Syslog_JSON_Map->dst_ip, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->dst_ip));
                }

            if ( !strcmp(Syslog_JSON_Map->md5, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->md5, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->md5));
                }

            if ( !strcmp(Syslog_JSON_Map->sha1, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->sha1, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->sha1));
                }

            if ( !strcmp(Syslog_JSON_Map->sha256, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->sha256, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->sha256));
                }

            if ( !strcmp(Syslog_JSON_Map->filename, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->filename, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->filename));
                }

            if ( !strcmp(Syslog_JSON_Map->hostname, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->hostname, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->hostname));
                }

            if ( !strcmp(Syslog_JSON_Map->url, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->url, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->url));
                }

            if ( !strcmp(Syslog_JSON_Map->ja3, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->ja3, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->ja3));
                }

            /* Math */

            if ( !strcmp(Syslog_JSON_Map->src_port, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->src_port = atoi(SaganProcSyslog_LOCAL->json_value[i]);
                }

            if ( !strcmp(Syslog_JSON_Map->dst_port, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->dst_port = atoi(SaganProcSyslog_LOCAL->json_value[i]);
                }

            if ( !strcmp(Syslog_JSON_Map->flow_id, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->flow_id = atol(SaganProcSyslog_LOCAL->json_value[i]);
                }


            /* Multi-function */

            if ( !strcmp(Syslog_JSON_Map->proto, SaganProcSyslog_LOCAL->json_key[i] ) )
                {

                    if ( !strcmp( SaganProcSyslog_LOCAL->json_value[i], "tcp" ) || !strcmp( SaganProcSyslog_LOCAL->json_value[i], "TCP" ) )
                        {
                            SaganProcSyslog_LOCAL->proto = 6;
                        }

                    else if ( !strcmp( SaganProcSyslog_LOCAL->json_value[i], "udp" ) || !strcmp( SaganProcSyslog_LOCAL->json_value[i], "UDP" ) )
                        {
                            SaganProcSyslog_LOCAL->proto = 17;
                        }

                    else if ( !strcmp( SaganProcSyslog_LOCAL->json_value[i], "icmp" ) || !strcmp( SaganProcSyslog_LOCAL->json_value[i], "ICMP" ) )
                        {
                            SaganProcSyslog_LOCAL->proto = 1;
                        }

                }

        }

    /* If debugging, dump data that was located */

    if ( debug->debugjson )
        {
            Debug_Sagan_Proc_Syslog( SaganProcSyslog_LOCAL );
        }

}

#endif
