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
#include "debug.h"
#include "message-json-map.h"

#include "parsers/parsers.h"


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

    char *ptr1 = NULL;
    char *ptr2 = NULL;
    char *data = NULL;

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

            JSON_Message_Map[counters->json_message_map].software[0] = '\0';
            JSON_Message_Map[counters->json_message_map].program[0] = '\0';
            JSON_Message_Map[counters->json_message_map].src_ip[0] = '\0';
            JSON_Message_Map[counters->json_message_map].dst_ip[0] = '\0';
            JSON_Message_Map[counters->json_message_map].src_port[0] = '\0';
            JSON_Message_Map[counters->json_message_map].dst_port[0] = '\0';
            JSON_Message_Map[counters->json_message_map].proto[0] = '\0';

            JSON_Message_Map[counters->json_message_map].md5[0] = '\0';
            JSON_Message_Map[counters->json_message_map].sha1[0] = '\0';
            JSON_Message_Map[counters->json_message_map].sha256[0] = '\0';
            JSON_Message_Map[counters->json_message_map].filename[0] = '\0';
            JSON_Message_Map[counters->json_message_map].hostname[0] = '\0';
            JSON_Message_Map[counters->json_message_map].url[0] = '\0';
            JSON_Message_Map[counters->json_message_map].ja3[0] = '\0';
            JSON_Message_Map[counters->json_message_map].event_id[0] = '\0';


            json_obj = json_tokener_parse(json_message_map_buf);

            if ( json_obj == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] JSON message map is incorrect at: \"%s\"", __FILE__, __LINE__, json_message_map_buf);
                    json_object_put(json_obj);
                    return;
                }

            if ( json_object_object_get_ex(json_obj, "software", &tmp))
                {

                    const char *software = json_object_get_string(tmp);

                    if ( software != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].software,  software, sizeof(JSON_Message_Map[counters->json_message_map].software));
                        }

                }

            if ( json_object_object_get_ex(json_obj, "program", &tmp))
                {

                    const char *program = json_object_get_string(tmp);

                    if ( program != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].program,  program, sizeof(JSON_Message_Map[counters->json_message_map].program));
                        }

                }

            /* Suricata event_type == program */

            if ( json_object_object_get_ex(json_obj, "event_type", &tmp))
                {

                    const char *event_type = json_object_get_string(tmp);

                    if ( event_type != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].program,  event_type, sizeof(JSON_Message_Map[counters->json_message_map].program));
                        }
                }

            /* Pull in "message" values.  It could be multiple valus for "message" */

            if ( json_object_object_get_ex(json_obj, "message", &tmp))
                {

                    data = (char*)json_object_get_string(tmp);

                    if ( data != NULL )
                        {

                            Remove_Spaces(data);

                            ptr2 = strtok_r(data, ",", &ptr1);

                            while ( ptr2 != NULL )
                                {

                                    strlcpy(JSON_Message_Map[counters->json_message_map].message[JSON_Message_Map[counters->json_message_map].message_count], ptr2, sizeof(JSON_Message_Map[counters->json_message_map].message[JSON_Message_Map[counters->json_message_map].message_count]));

                                    JSON_Message_Map[counters->json_message_map].message_count++;

                                    ptr2 = strtok_r(NULL, ",", &ptr1);
                                }
                        }

                }

            if ( json_object_object_get_ex(json_obj, "src_ip", &tmp))
                {

                    const char *src_ip = json_object_get_string(tmp);

                    if ( src_ip != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].src_ip,  src_ip, sizeof(JSON_Message_Map[counters->json_message_map].src_ip));
                        }
                }

            /* "dest_ip" is for Suricata compatibility */

            if ( json_object_object_get_ex(json_obj, "dst_ip", &tmp) || json_object_object_get_ex(json_obj, "dest_ip", &tmp) )
                {

                    const char *dst_ip = json_object_get_string(tmp);

                    if ( dst_ip != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].dst_ip,  dst_ip, sizeof(JSON_Message_Map[counters->json_message_map].dst_ip));
                        }
                }

            if ( json_object_object_get_ex(json_obj, "src_port", &tmp))
                {

                    const char *src_port = json_object_get_string(tmp);

                    if ( src_port != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].src_port,  src_port, sizeof(JSON_Message_Map[counters->json_message_map].src_port));
                        }

                }

            if ( json_object_object_get_ex(json_obj, "dst_port", &tmp) || json_object_object_get_ex(json_obj, "dest_port", &tmp) )
                {

                    const char *dst_port = json_object_get_string(tmp);

                    if ( dst_port != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].dst_port,  dst_port, sizeof(JSON_Message_Map[counters->json_message_map].dst_port));
                        }

                }

            if ( json_object_object_get_ex(json_obj, "proto", &tmp))
                {

                    const char *proto = json_object_get_string(tmp);

                    if ( proto != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].proto, proto, sizeof(JSON_Message_Map[counters->json_message_map].proto));
                        }
                }

            if ( json_object_object_get_ex(json_obj, "event_id", &tmp))
                {
                    const char *event_id = json_object_get_string(tmp);

                    if ( event_id != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].event_id,  event_id, sizeof(JSON_Message_Map[counters->json_message_map].event_id));
                        }
                }


            if ( json_object_object_get_ex(json_obj, "flow_id", &tmp))
                {
                    const char *flow_id = json_object_get_string(tmp);

                    if ( flow_id != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].flow_id,  flow_id, sizeof(JSON_Message_Map[counters->json_message_map].flow_id));
                        }
                }

            if ( json_object_object_get_ex(json_obj, "md5", &tmp))
                {

                    const char *md5 = json_object_get_string(tmp);

                    if ( md5 != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].md5, md5, sizeof(JSON_Message_Map[counters->json_message_map].md5));
                        }
                }

            if ( json_object_object_get_ex(json_obj, "sha1", &tmp))
                {

                    const char *sha1 = json_object_get_string(tmp);

                    if ( sha1 != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].sha1,  sha1, sizeof(JSON_Message_Map[counters->json_message_map].sha1));
                        }

                }

            if ( json_object_object_get_ex(json_obj, "sha256", &tmp))
                {

                    const char *sha256 = json_object_get_string(tmp);

                    if ( sha256 != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].sha256,  sha256, sizeof(JSON_Message_Map[counters->json_message_map].sha256));
                        }
                }

            if ( json_object_object_get_ex(json_obj, "filename", &tmp))
                {

                    const char *filename = json_object_get_string(tmp);

                    if ( filename != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].filename,  filename, sizeof(JSON_Message_Map[counters->json_message_map].filename));
                        }
                }

            if ( json_object_object_get_ex(json_obj, "hostname", &tmp))
                {

                    const char *hostname = json_object_get_string(tmp);

                    if ( hostname != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].hostname,  hostname,  sizeof(JSON_Message_Map[counters->json_message_map].hostname));
                        }
                }

            if ( json_object_object_get_ex(json_obj, "url", &tmp))
                {

                    const char *url = json_object_get_string(tmp);

                    if ( url != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].url,  url, sizeof(JSON_Message_Map[counters->json_message_map].url));
                        }
                }

            if ( json_object_object_get_ex(json_obj, "ja3", &tmp))
                {

                    const char *ja3 = json_object_get_string(tmp);

                    if ( ja3 != NULL )
                        {
                            strlcpy(JSON_Message_Map[counters->json_message_map].ja3,  ja3, sizeof(JSON_Message_Map[counters->json_message_map].ja3));
                        }
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
    uint16_t b=0;

    uint32_t score=0;
    uint32_t prev_score=0;
    uint32_t pos=0;

    /* We start at 1 because the SaganProcSyslog_LOCAL->message is considered the
       first JSON string */

    uint16_t json_str_count=1;

    bool found = false;

    struct json_object *json_obj = NULL;
    struct json_object *json_obj2 = NULL;
    struct json_object *json_obj3 = NULL;

    char json_str[JSON_MAX_NEST][JSON_MAX_SIZE];  // = { { 0 } };
    char tmp_message[MAX_SYSLOGMSG] = { 0 };

    strlcpy(json_str[0], SaganProcSyslog_LOCAL->syslog_message, sizeof(json_str[0]));
    json_obj = json_tokener_parse(SaganProcSyslog_LOCAL->syslog_message);

    /* If JSON parsing fails, it wasn't JSON after all */

    if ( json_obj == NULL )
        {

            if ( debug->debugmalformed )
                {
                    Sagan_Log(WARN, "[%s, line %d] Sagan Detected JSON but Libfastjson failed to decode it. The log line was: \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);
                }

            json_object_put(json_obj);
            free(JSON_Message_Map_Found);
            __atomic_add_fetch(&counters->malformed_json_mp_count, 1, __ATOMIC_SEQ_CST);
            return;
        }

    if ( debug->debugjson )
        {
            Sagan_Log(DEBUG, "Syslog Message: \"%s\"\n", SaganProcSyslog_LOCAL->syslog_message);
        }

    struct json_object_iterator it = json_object_iter_begin(json_obj);
    struct json_object_iterator itEnd = json_object_iter_end(json_obj);

    /* Search through all key/values looking for embedded JSON */

    while (!json_object_iter_equal(&it, &itEnd))
        {

            const char *key = json_object_iter_peek_name(&it);

            if ( key == NULL )
                {
                    key = "NULL";
                }

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

                    if  ( val_str != NULL )
                        {
                            strlcpy( SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count], val_str, sizeof(SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count]));
                        }
                    else
                        {
                            strlcpy( SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count], "null", sizeof(SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count]));
                        }

                    if ( SaganProcSyslog_LOCAL->json_count > JSON_MAX_OBJECTS )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Ran out of space for json objects! Consider increasing the JSON_MAX_OBJECTS in the sagan-defs.h and re-compiling.",  __FILE__, __LINE__, a, json_str[a]);
                        }

                    SaganProcSyslog_LOCAL->json_count++;
                }

            json_object_iter_next(&it);
        }

    json_object_put(json_obj);

    if ( debug->debugjson )
        {

            for ( a=0; a < json_str_count; a++ )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] %d. JSON found: \"%s\"",  __FILE__, __LINE__, a, json_str[a]);
                }
        }

    if ( json_str_count > 1 )
        {

            for ( i = 1; i < json_str_count; i++ )
                {

                    json_obj3 = json_tokener_parse(json_str[i]);

                    if ( json_obj3 != NULL )
                        {

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
                }

            json_object_put(json_obj3);
        }

    for (i = 0; i < counters->json_message_map; i++ )
        {

            score = 0;

            for ( a = 0; a < SaganProcSyslog_LOCAL->json_count; a++ )
                {

                    if ( JSON_Message_Map[i].message_count > 1 )
                        {

                            for ( b=0; b < JSON_Message_Map[i].message_count; b++ )
                                {

                                    if ( !strcmp(JSON_Message_Map[i].message[b], SaganProcSyslog_LOCAL->json_key[a] ) )
                                        {

                                            snprintf(tmp_message, sizeof(tmp_message), " %s:%s,", JSON_Message_Map[i].message[b], SaganProcSyslog_LOCAL->json_value[a]);

                                            strlcat(JSON_Message_Map_Found[i].message, tmp_message, sizeof(JSON_Message_Map_Found[i].message));
                                            score++;
                                        }

                                }
                        }

                    else if ( JSON_Message_Map[i].message_count == 1 )
                        {


                            if ( !strcmp(JSON_Message_Map[i].message[0], SaganProcSyslog_LOCAL->json_key[a] ) )

                                {

                                    snprintf(JSON_Message_Map_Found[i].message, sizeof(JSON_Message_Map_Found[i].message), " %s:%s", JSON_Message_Map[i].message[0], SaganProcSyslog_LOCAL->json_value[a]);
                                    score++;

                                }
                        }

                    /* Program  */

                    if ( !strcmp(JSON_Message_Map[i].program, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].program, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].program));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].src_ip, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].src_ip, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].src_ip));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].dst_ip, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].dst_ip, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].dst_ip));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].src_port, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].src_port, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].src_port));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].dst_port, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].dst_port, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].dst_port));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].proto, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].proto, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].proto));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].event_id, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].event_id, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].event_id));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].flow_id, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            JSON_Message_Map_Found[i].flow_id = atol( SaganProcSyslog_LOCAL->json_value[a] );
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].md5, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].md5, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].md5));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].sha1, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].sha1, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].sha1));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].sha256, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].sha256, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].sha256));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].filename, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].filename, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].filename));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].hostname, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].hostname, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].hostname));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].url, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].url, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].url));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].ja3, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].ja3, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].ja3));
                            score++;
                        }

                    if ( !strcmp(JSON_Message_Map[i].ja3, SaganProcSyslog_LOCAL->json_key[a] ) )
                        {
                            strlcpy(JSON_Message_Map_Found[i].ja3, SaganProcSyslog_LOCAL->json_value[a], sizeof(JSON_Message_Map_Found[i].ja3));
                            score++;
                        }

                }

            if ( score > prev_score )
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
                    Sagan_Log(DEBUG, "[%s, line %d] Best message mapping match for software \"%s\" (%d) (score of %d)", __FILE__, __LINE__, JSON_Message_Map[pos].software, pos, prev_score );
                }
            else
                {
                    Sagan_Log(DEBUG, "[%s, line %d] No JSON mappings found", __FILE__, __LINE__);
                }

        }

    if ( found == true )
        {

            __atomic_add_fetch(&counters->json_mp_count, 1, __ATOMIC_SEQ_CST);

            /* Put JSON values into place */

            /* If this is "message":"{value},{value},{value}", get rid of trailing , in the new "message */

            if ( JSON_Message_Map_Found[pos].message[ strlen(JSON_Message_Map_Found[pos].message) - 1 ] == ',' )
                {
                    JSON_Message_Map_Found[pos].message[ strlen(JSON_Message_Map_Found[pos].message) - 1 ] = '\0';
                }

            /* If user wants the orignal JSON from the message, leave it.  Otherwise, copy the new values */

            if ( strcmp( (const char*)JSON_Message_Map[pos].message, "%JSON%"))
                {
//                    strlcpy(SaganProcSyslog_LOCAL->syslog_message, JSON_Message_Map_Found[pos].message, sizeof(SaganProcSyslog_LOCAL->syslog_message));
                    snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), " %s", JSON_Message_Map_Found[pos].message);
                    SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';

                }


            /* Adopt the "flow_id" */

            SaganProcSyslog_LOCAL->flow_id = JSON_Message_Map_Found[pos].flow_id;

            if ( JSON_Message_Map_Found[pos].md5[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->md5, JSON_Message_Map_Found[pos].md5, sizeof(SaganProcSyslog_LOCAL->md5));
                }

            if ( JSON_Message_Map_Found[pos].sha1[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->sha1, JSON_Message_Map_Found[pos].sha1, sizeof(SaganProcSyslog_LOCAL->sha1));
                }

            if ( JSON_Message_Map_Found[pos].sha256[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->sha256, JSON_Message_Map_Found[pos].sha256, sizeof(SaganProcSyslog_LOCAL->sha256));
                }

            if ( JSON_Message_Map_Found[pos].filename[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->filename, JSON_Message_Map_Found[pos].filename, sizeof(SaganProcSyslog_LOCAL->filename));
                }

            if ( JSON_Message_Map_Found[pos].hostname[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->hostname, JSON_Message_Map_Found[pos].hostname, sizeof(SaganProcSyslog_LOCAL->hostname));
                }

            if ( JSON_Message_Map_Found[pos].url[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->url, JSON_Message_Map_Found[pos].url, sizeof(SaganProcSyslog_LOCAL->url));
                }


            if ( JSON_Message_Map_Found[pos].src_ip[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->src_ip, JSON_Message_Map_Found[pos].src_ip, sizeof(SaganProcSyslog_LOCAL->src_ip));
                }

            if ( JSON_Message_Map_Found[pos].dst_ip[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->dst_ip, JSON_Message_Map_Found[pos].dst_ip, sizeof(SaganProcSyslog_LOCAL->dst_ip));
                }

            if ( JSON_Message_Map_Found[pos].src_port[0] != '\0' )
                {
                    SaganProcSyslog_LOCAL->src_port = atoi(JSON_Message_Map_Found[pos].src_port);
                }
            if ( JSON_Message_Map_Found[pos].dst_port[0] != '\0' )
                {
                    SaganProcSyslog_LOCAL->dst_port = atoi(JSON_Message_Map_Found[pos].dst_port);
                }

            if ( JSON_Message_Map_Found[pos].ja3[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->ja3, JSON_Message_Map_Found[pos].ja3, sizeof(SaganProcSyslog_LOCAL->ja3));
                }

            if ( JSON_Message_Map_Found[pos].event_id[0] != '\0' )
                {
                    strlcpy(SaganProcSyslog_LOCAL->event_id, JSON_Message_Map_Found[pos].event_id, sizeof(SaganProcSyslog_LOCAL->event_id));
                }


            if ( JSON_Message_Map_Found[pos].proto[0] != '\0' )
                {

                    if ( !strcasecmp( JSON_Message_Map_Found[pos].proto, "tcp" ) || !strcasecmp( JSON_Message_Map_Found[pos].proto, "TCP" ) )
                        {
                            SaganProcSyslog_LOCAL->proto = 6;
                        }

                    else if ( !strcasecmp( JSON_Message_Map_Found[pos].proto, "udp" ) || !strcasecmp( JSON_Message_Map_Found[pos].proto, "UDP" ) )
                        {
                            SaganProcSyslog_LOCAL->proto = 17;
                        }

                    else if ( !strcasecmp( JSON_Message_Map_Found[pos].proto, "icmp" ) || !strcasecmp( JSON_Message_Map_Found[pos].proto, "ICMP" ) )
                        {
                            SaganProcSyslog_LOCAL->proto = 1;
                        }

                }


            /* Don't override syslog program if no program is present */

            if ( JSON_Message_Map_Found[pos].program[0] != '\0' )
                {

                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, JSON_Message_Map_Found[pos].program, sizeof(SaganProcSyslog_LOCAL->syslog_program));
                    Remove_Spaces(SaganProcSyslog_LOCAL->syslog_program);

                }

            /* If debugging, dump data that was located */

            if ( debug->debugjson )
                {
                    Debug_Sagan_Proc_Syslog( SaganProcSyslog_LOCAL );
                }

        }

    free(JSON_Message_Map_Found);

}

#endif

