/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>
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
            JSON_Message_Map[counters->json_message_map].dst_ip[0] = '\0';
            JSON_Message_Map[counters->json_message_map].src_port[0] = '\0';
            JSON_Message_Map[counters->json_message_map].dst_port[0] = '\0';
            JSON_Message_Map[counters->json_message_map].proto[0] = '\0';

            //JSON_Message_Map[counters->json_message_map].flow_id = 0;
            JSON_Message_Map[counters->json_message_map].md5[0] = '\0';
            JSON_Message_Map[counters->json_message_map].sha1[0] = '\0';
            JSON_Message_Map[counters->json_message_map].sha256[0] = '\0';
            JSON_Message_Map[counters->json_message_map].filename[0] = '\0';
            JSON_Message_Map[counters->json_message_map].hostname[0] = '\0';
            JSON_Message_Map[counters->json_message_map].url[0] = '\0';

            json_obj = json_tokener_parse(json_message_map_buf);

            if ( json_obj == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] JSON message map is incorrect at: \"%s\"", __FILE__, __LINE__, json_message_map_buf);
                    json_object_put(json_obj);
                    return;
                }

            if ( json_object_object_get_ex(json_obj, "program", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].program,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].program));
                }

	    /* Suricata event_type == program */

            if ( json_object_object_get_ex(json_obj, "event_type", &tmp))
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

            if ( json_object_object_get_ex(json_obj, "dst_ip", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].dst_ip,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].dst_ip));
                }

	    /* Suricata compatibility */

            if ( json_object_object_get_ex(json_obj, "dest_ip", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].dst_ip,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].dst_ip));
                }


            if ( json_object_object_get_ex(json_obj, "src_port", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].src_port,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].src_port));
                }

            if ( json_object_object_get_ex(json_obj, "dst_port", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].dst_port,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].dst_port));
                }

	    /* Suricata compatibility */

            if ( json_object_object_get_ex(json_obj, "dest_port", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].dst_port,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].dst_port));
                }

            if ( json_object_object_get_ex(json_obj, "proto", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].proto,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].proto));
                }

            if ( json_object_object_get_ex(json_obj, "flow_id", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].flow_id,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].flow_id));
                }

            if ( json_object_object_get_ex(json_obj, "md5", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].md5,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].md5));
                }

            if ( json_object_object_get_ex(json_obj, "sha1", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].sha1,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].sha1));
                }

            if ( json_object_object_get_ex(json_obj, "sha256", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].sha256,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].sha256));
                }

            if ( json_object_object_get_ex(json_obj, "filename", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].filename,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].filename));
                }

            if ( json_object_object_get_ex(json_obj, "hostname", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].hostname,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].hostname));
                }

            if ( json_object_object_get_ex(json_obj, "url", &tmp))
                {
                    strlcpy(JSON_Message_Map[counters->json_message_map].url,  json_object_get_string(tmp), sizeof(JSON_Message_Map[counters->json_message_map].url));
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

            if ( debug->debugmalformed )
                {
                    Sagan_Log(WARN, "[%s, line %d] Sagan Detected JSON but Libfastjson failed to decode it. The log line was: \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);
                }

            json_object_put(json_obj);
            free(JSON_Message_Map_Found);
            __atomic_add_fetch(&counters->malformed_json_mp_count, 1, __ATOMIC_SEQ_CST);
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

                    struct json_object *json_obj = NULL;
                    json_obj = json_tokener_parse(json_str[a]);

                    if ( json_obj == NULL )
                        {
                            Sagan_Log(WARN, "[%s, line %d] Detected JSON Nest but function was incorrect. The log line was: \"%s\"", __FILE__, __LINE__, json_str[a]);
                            json_object_put(json_obj);
                            free(JSON_Message_Map_Found);
                            return;
                        }



                    if ( !strcmp(JSON_Message_Map[i].message, "%JSON%" ) )
                        {
                            strlcpy( JSON_Message_Map_Found[i].message, SaganProcSyslog_LOCAL->syslog_message, sizeof(JSON_Message_Map_Found[i].message) );
                            has_message = true;
                            score++;
                        }

                    else if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].message, &tmp))
                        {

                            strlcpy(JSON_Message_Map_Found[i].message, SaganProcSyslog_LOCAL->syslog_message, sizeof(JSON_Message_Map_Found[i].message));

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
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].dst_ip, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].dst_ip, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].dst_ip));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].src_port, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].src_port, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].src_port));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].dst_port, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].dst_port, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].dst_port));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].proto, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].proto, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].proto));
                            score++;
                        }


                    /* Suricata specific */

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].flow_id, &tmp))
                        {
                            JSON_Message_Map_Found[i].flow_id = atol( json_object_get_string(tmp) );
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].md5, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].md5, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].md5));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].sha1, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].sha1, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].sha1));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].sha256, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].sha256, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].sha256));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].filename, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].filename, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].filename));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].hostname, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].hostname, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].hostname));
                            score++;
                        }

                    if ( json_object_object_get_ex(json_obj, JSON_Message_Map[i].url, &tmp))
                        {
                            strlcpy(JSON_Message_Map_Found[i].url, json_object_get_string(tmp), sizeof(JSON_Message_Map_Found[i].url));
                            score++;
                        }

                    json_object_put(json_obj);

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

    if ( found == true )
        {

            __atomic_add_fetch(&counters->json_mp_count, 1, __ATOMIC_SEQ_CST);

            /* Put JSON values into place */

            strlcpy(SaganProcSyslog_LOCAL->syslog_message, JSON_Message_Map_Found[pos].message, sizeof(SaganProcSyslog_LOCAL->syslog_message));

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
                    SaganProcSyslog_LOCAL->json_src_flag = true;
                    strlcpy(SaganProcSyslog_LOCAL->src_ip, JSON_Message_Map_Found[pos].src_ip, sizeof(SaganProcSyslog_LOCAL->src_ip));
                }

            if ( JSON_Message_Map_Found[pos].dst_ip[0] != '\0' )
                {
                    SaganProcSyslog_LOCAL->json_dst_flag = true;
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

                }


            if ( debug->debugjson )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] New data extracted from JSON:", __FILE__, __LINE__);
                    Sagan_Log(DEBUG, "[%s, line %d] -------------------------------------------------------", __FILE__, __LINE__);
                    Sagan_Log(DEBUG, "[%s, line %d] Message: \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message );
                    Sagan_Log(DEBUG, "[%s, line %d] Program: \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_program );
                    Sagan_Log(DEBUG, "[%s, line %d] src_ip : \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->src_ip );
                    Sagan_Log(DEBUG, "[%s, line %d] dst_ip : \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->dst_ip );
                    Sagan_Log(DEBUG, "[%s, line %d] src_port : \"%d\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->src_port );
                    Sagan_Log(DEBUG, "[%s, line %d] dst_port : \"%d\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->dst_port );
                    Sagan_Log(DEBUG, "[%s, line %d] proto : \"%d\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->proto );

                }


        }

    free(JSON_Message_Map_Found);
    json_object_put(json_obj);

}

#endif
