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

void SyslogInput_JSON( char *syslog_string, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    struct json_object *json_obj = NULL;
    struct json_object *json_obj2 = NULL;
    struct json_object *json_obj3 = NULL;

    uint16_t json_str_count=0;
    uint16_t i;

    char json_str[JSON_MAX_NEST][JSON_MAX_SIZE] = { { 0 } };

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

    /* The raw syslog is the first "nested" level".  Copy that */

    strlcpy(json_str[0], syslog_string, sizeof(json_str[0]));
    json_str_count++;
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

    /* JSON was successfully parsed */

    __atomic_add_fetch(&counters->json_input_count, 1, __ATOMIC_SEQ_CST);

    struct json_object_iterator it = json_object_iter_begin(json_obj);
    struct json_object_iterator itEnd = json_object_iter_end(json_obj);

    /* Search through all key/values looking for embedded JSON */

    while (!json_object_iter_equal(&it, &itEnd))
        {

            const char *key = json_object_iter_peek_name(&it);
            struct json_object *const val = json_object_iter_peek_value(&it);

            const char *val_str = json_object_get_string(val);

            if ( debug->debugjson )
                {
                    Sagan_Log(DEBUG, "Key: \"%s\", Value: \"%s\"", key, val_str );

                }

            /* Is there nested JSON */

            if ( val_str != NULL && val_str[0] == '{' )
                {
                    /* Validate it before handing it to the parser to save CPU */

                    json_obj2 = json_tokener_parse(val_str);

                    if ( json_obj2 != NULL )
                        {

                            strlcpy(json_str[json_str_count], val_str, sizeof(json_str[json_str_count]));
                            json_str_count++;

                            struct json_object_iterator it2 = json_object_iter_begin(json_obj2);
                            struct json_object_iterator itEnd2 = json_object_iter_end(json_obj2);

                            /* Look for any second tier/third tier JSON */

                            while (!json_object_iter_equal(&it2, &itEnd2))
                                {

                                    const char *key2 = json_object_iter_peek_name(&it2);
                                    struct json_object *const val2 = json_object_iter_peek_value(&it2);

                                    const char *val_str2 = json_object_get_string(val2);

				    if ( val_str2 == NULL )
					{
					val_str2 = "NULL";
					}

                                    if ( debug->debugjson )
                                        {
                                            Sagan_Log(DEBUG, "Key2: \"%s\", Value: \"%s\"", key2, val_str );

                                        }

                                    /* Grab nests */

                                    if ( val_str2[0] == '{' )
                                        {

                                            strlcpy(json_str[json_str_count], val_str2, sizeof(json_str[json_str_count]));
                                            json_str_count++;

                                        }

                                    json_object_iter_next(&it2);

                                }

                        } /* json_obj2 != NULL */

                    json_object_put(json_obj2);

                }
            else
                {

                    /* Grab the first level of the nest values */

                    strlcpy( SaganProcSyslog_LOCAL->json_key[SaganProcSyslog_LOCAL->json_count], key, sizeof(SaganProcSyslog_LOCAL->json_key[SaganProcSyslog_LOCAL->json_count]));
                    strlcpy( SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count], val_str, sizeof(SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count]));
                    SaganProcSyslog_LOCAL->json_count++;

                }


            json_object_iter_next(&it);

        }

    /* This json_object_put works fine with the above (no leak but faults with the
       below */

    json_object_put(json_obj);

    if ( json_str_count > 1 ) 
    {

    for ( i = 1; i < json_str_count; i++ )
        {

            json_obj3 = json_tokener_parse(json_str[i]);

            struct json_object_iterator it3 = json_object_iter_begin(json_obj3);
            struct json_object_iterator itEnd3 = json_object_iter_end(json_obj3);

            while (!json_object_iter_equal(&it3, &itEnd3))
                {

                    const char *key3 = json_object_iter_peek_name(&it3);
                    const char *val_str3;

                    struct json_object *const val3 = json_object_iter_peek_value(&it3);

                    val_str3 = json_object_get_string(val3);

                    if ( val_str3[0] != '{' )
                        {

                            strlcpy( SaganProcSyslog_LOCAL->json_key[SaganProcSyslog_LOCAL->json_count], key3, sizeof(SaganProcSyslog_LOCAL->json_key[SaganProcSyslog_LOCAL->json_count]));
                            strlcpy( SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count], val_str3, sizeof(SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count]));
                            SaganProcSyslog_LOCAL->json_count++;

                        }

                    json_object_iter_next(&it3);

                }


        }

    json_object_put(json_obj3);

    }

    /* User wants the entire JSON to become the "message" */

    if ( !strcmp(Syslog_JSON_Map->syslog_map_message, "%JSON%" ) )
        {
//            strlcpy(SaganProcSyslog_LOCAL->syslog_message, syslog_string, sizeof(SaganProcSyslog_LOCAL->syslog_message));
              snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), " %s", SaganProcSyslog_LOCAL->json_value[i]);
              SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';

        }


    for (i = 0; i < SaganProcSyslog_LOCAL->json_count; i++ )
        {

            /* Strings */

            if ( !strcmp(Syslog_JSON_Map->syslog_map_message, SaganProcSyslog_LOCAL->json_key[i] ) )
                {

		    if ( SaganProcSyslog_LOCAL->json_value[i][0] != ' ' )
			{ 
			snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), " %s", SaganProcSyslog_LOCAL->json_value[i]);
			SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';

			}

//                    strlcpy(SaganProcSyslog_LOCAL->syslog_message, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_message));
                }

            else if ( !strcmp(Syslog_JSON_Map->event_id, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->event_id, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->event_id));
                }

            else if ( !strcmp(Syslog_JSON_Map->syslog_map_host, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_host));
                }

            else if ( !strcmp(Syslog_JSON_Map->syslog_map_facility, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                }

            else if ( !strcmp(Syslog_JSON_Map->syslog_map_priority, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                }

            else if ( !strcmp(Syslog_JSON_Map->syslog_map_level, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_level));
                }

            else if ( !strcmp(Syslog_JSON_Map->syslog_map_tag, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                }

            else if ( !strcmp(Syslog_JSON_Map->syslog_map_date, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_date));
                }

            else if ( !strcmp(Syslog_JSON_Map->syslog_map_time, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_time));
                }

            else if ( !strcmp(Syslog_JSON_Map->syslog_map_program, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_program));
                }

            else if ( !strcmp(Syslog_JSON_Map->src_ip, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->src_ip));
                }

            else if ( !strcmp(Syslog_JSON_Map->dst_ip, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->dst_ip));
                }

            else if ( !strcmp(Syslog_JSON_Map->md5, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->md5, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->md5));
                }

            else if ( !strcmp(Syslog_JSON_Map->sha1, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->sha1, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->sha1));
                }

            else if ( !strcmp(Syslog_JSON_Map->sha256, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->sha256, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->sha256));
                }

            else if ( !strcmp(Syslog_JSON_Map->filename, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->filename, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->filename));
                }

            else if ( !strcmp(Syslog_JSON_Map->hostname, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->hostname, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->hostname));
                }

            else if ( !strcmp(Syslog_JSON_Map->url, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->url, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->url));
                }

            else if ( !strcmp(Syslog_JSON_Map->ja3, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->ja3, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->ja3));
                }

            /* Math */

            else if ( !strcmp(Syslog_JSON_Map->src_port, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->src_port = atoi(SaganProcSyslog_LOCAL->json_value[i]);
                }

            else if ( !strcmp(Syslog_JSON_Map->dst_port, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->dst_port = atoi(SaganProcSyslog_LOCAL->json_value[i]);
                }

            else if ( !strcmp(Syslog_JSON_Map->flow_id, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->flow_id = atol(SaganProcSyslog_LOCAL->json_value[i]);
                }


            /* Multi-function */

            else if ( !strcmp(Syslog_JSON_Map->proto, SaganProcSyslog_LOCAL->json_key[i] ) )
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
