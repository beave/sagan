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
//    char is_nested_tmp[8] = { 0 };


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

                    const char *software = json_object_get_string(tmp);

                    if ( software != NULL )
                        {

                            if ( !strcmp(software, config->json_input_software ) )
                                {

                                    Sagan_Log(NORMAL, "Found JSON mapping for '%s'.  Loading values.", config->json_input_software);

                                    if ( json_object_object_get_ex(json_obj, "syslog-source-ip", &tmp))
                                        {

                                            const char *syslog_map_host = json_object_get_string(tmp);

                                            if ( syslog_map_host != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_host,  syslog_map_host, sizeof(Syslog_JSON_Map->syslog_map_host));
                                                }
                                        }


                                    if ( json_object_object_get_ex(json_obj, "facility", &tmp))
                                        {

                                            const char *facility = json_object_get_string(tmp);

                                            if ( facility != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_facility,  facility, sizeof(Syslog_JSON_Map->syslog_map_facility));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "level", &tmp))
                                        {

                                            const char *level = json_object_get_string(tmp);

                                            if ( level != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_level,  level, sizeof(Syslog_JSON_Map->syslog_map_level));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "priority", &tmp))
                                        {

                                            const char *priority = json_object_get_string(tmp);

                                            if ( priority != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_priority,  priority, sizeof(Syslog_JSON_Map->syslog_map_priority));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "tags", &tmp))
                                        {

                                            const char *tag = json_object_get_string(tmp);

                                            if ( tag != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_tag, tag, sizeof(Syslog_JSON_Map->syslog_map_tag));
                                                }
                                        }


                                    if ( json_object_object_get_ex(json_obj, "time", &tmp))
                                        {

                                            const char *time = json_object_get_string(tmp);

                                            if ( time != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_time,  time, sizeof(Syslog_JSON_Map->syslog_map_time));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "date", &tmp))
                                        {

                                            const char *date = json_object_get_string(tmp);

                                            if ( date != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_date, date, sizeof(Syslog_JSON_Map->syslog_map_date));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "program", &tmp) ||
                                            json_object_object_get_ex(json_obj, "event_type", &tmp) )
                                        {

                                            const char *program = json_object_get_string(tmp);

                                            if ( program != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_program, program, sizeof(Syslog_JSON_Map->syslog_map_program));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "message", &tmp))
                                        {

                                            const char *message = json_object_get_string(tmp);

                                            if ( message != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->syslog_map_message, message, sizeof(Syslog_JSON_Map->syslog_map_message));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "src_ip", &tmp))
                                        {

                                            const char *src_ip = json_object_get_string(tmp);

                                            if ( src_ip != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->src_ip,  src_ip, sizeof(Syslog_JSON_Map->src_ip));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "dest_ip", &tmp) ||
                                            json_object_object_get_ex(json_obj, "dst_ip", &tmp) )
                                        {

                                            const char *dst_ip = json_object_get_string(tmp);

                                            if ( dst_ip != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->dst_ip, dst_ip, sizeof(Syslog_JSON_Map->dst_ip));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "src_port", &tmp))
                                        {

                                            const char *src_port = json_object_get_string(tmp);

                                            if ( src_port != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->src_port,  src_port, sizeof(Syslog_JSON_Map->src_port));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "dest_port", &tmp) ||
                                            json_object_object_get_ex(json_obj, "dst_port", &tmp) )
                                        {

                                            const char *dst_port = json_object_get_string(tmp);

                                            if ( dst_port != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->dst_port,  dst_port, sizeof(Syslog_JSON_Map->dst_port));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "proto", &tmp))
                                        {

                                            const char *proto = json_object_get_string(tmp);

                                            if ( proto != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->proto, proto, sizeof(Syslog_JSON_Map->proto));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "md5", &tmp))
                                        {

                                            const char *md5 = json_object_get_string(tmp);

                                            if ( md5 != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->md5,  md5, sizeof(Syslog_JSON_Map->md5));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "sha1", &tmp))
                                        {

                                            const char *sha1 = json_object_get_string(tmp);

                                            if ( sha1 != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->sha1, sha1, sizeof(Syslog_JSON_Map->sha1));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "sha256", &tmp))
                                        {

                                            const char *sha256 = json_object_get_string(tmp);

                                            if ( sha256 != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->sha256, sha256, sizeof(Syslog_JSON_Map->sha256));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "filename", &tmp))
                                        {

                                            const char *filename = json_object_get_string(tmp);

                                            if ( filename != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->filename, filename, sizeof(Syslog_JSON_Map->filename));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "hostname", &tmp))
                                        {

                                            const char *hostname = json_object_get_string(tmp);

                                            if ( hostname != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->hostname, hostname, sizeof(Syslog_JSON_Map->hostname));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "url", &tmp))
                                        {

                                            const char *url = json_object_get_string(tmp);

                                            if ( url != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->url,  url, sizeof(Syslog_JSON_Map->url));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "ja3", &tmp))
                                        {

                                            const char *ja3 = json_object_get_string(tmp);

                                            if ( ja3 != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->ja3, ja3, sizeof(Syslog_JSON_Map->ja3));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "flow_id", &tmp))
                                        {

                                            const char *flow_id = json_object_get_string(tmp);

                                            if ( flow_id != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->flow_id, flow_id, sizeof(Syslog_JSON_Map->flow_id));
                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "event_id", &tmp))
                                        {

                                            const char *event_id = json_object_get_string(tmp);

                                            if ( event_id != NULL )
                                                {
                                                    strlcpy(Syslog_JSON_Map->event_id, event_id, sizeof(Syslog_JSON_Map->event_id));
                                                }
                                        }

                                    /* Sanity Checks */

                                    if ( Syslog_JSON_Map->syslog_map_time[0] == '\0' )
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
        }

    json_object_put(json_obj);

    Sagan_Log(ERROR, "No JSON mappings found for '%s'.  Abort!", config->json_input_software);

}

#endif
