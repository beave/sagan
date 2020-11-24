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

    char *ptmp = NULL;
    char *tok = NULL;

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

                                    /* Syslog source - NOTE: Remove the - one! */

                                    if ( json_object_object_get_ex(json_obj, "syslog-source-ip", &tmp) || json_object_object_get_ex(json_obj, "syslog_source_ip", &tmp) )
                                        {

                                            const char *syslog_map_host = json_object_get_string(tmp);

                                            if ( syslog_map_host != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_host_count > JSON_INPUT_S_SOURCE_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"syslog-source-ip\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_host[JSON_INPUT_S_SOURCE_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_host, syslog_map_host, JSON_INPUT_S_SOURCE_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_host, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_host[ Syslog_JSON_Map->syslog_map_host_count ], ptmp, JSON_INPUT_S_SOURCE);
                                                            Syslog_JSON_Map->syslog_map_host_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }


                                    /* facility */

                                    if ( json_object_object_get_ex(json_obj, "facility", &tmp) )
                                        {

                                            const char *facility = json_object_get_string(tmp);

                                            if ( facility != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_facility_count > JSON_INPUT_FACILITY_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"facility\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_facility[JSON_INPUT_FACILITY_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_facility, facility, JSON_INPUT_FACILITY_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_facility, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_facility[ Syslog_JSON_Map->syslog_map_facility_count ], ptmp, JSON_INPUT_FACILITY);
                                                            Syslog_JSON_Map->syslog_map_facility_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* level */

                                    if ( json_object_object_get_ex(json_obj, "level", &tmp) )
                                        {

                                            const char *level = json_object_get_string(tmp);

                                            if ( level != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_level_count > JSON_INPUT_LEVEL_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"level\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_level[JSON_INPUT_LEVEL_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_level, level, JSON_INPUT_LEVEL_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_level, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_level[ Syslog_JSON_Map->syslog_map_level_count ], ptmp, JSON_INPUT_LEVEL);
                                                            Syslog_JSON_Map->syslog_map_level_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* priority */

                                    if ( json_object_object_get_ex(json_obj, "priority", &tmp) )
                                        {

                                            const char *priority = json_object_get_string(tmp);

                                            if ( priority != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_priority_count > JSON_INPUT_PRIORITY_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"priority\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_priority[JSON_INPUT_PRIORITY_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_priority, priority, JSON_INPUT_PRIORITY_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_priority, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_priority[ Syslog_JSON_Map->syslog_map_priority_count ], ptmp, JSON_INPUT_PRIORITY);
                                                            Syslog_JSON_Map->syslog_map_priority_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* tag */

                                    if ( json_object_object_get_ex(json_obj, "tag", &tmp) )
                                        {

                                            const char *tag = json_object_get_string(tmp);

                                            if ( tag != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_tag_count > JSON_INPUT_TAG_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"tag\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_tag[JSON_INPUT_TAG_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_tag, tag, JSON_INPUT_TAG_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_tag, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_tag[ Syslog_JSON_Map->syslog_map_tag_count ], ptmp, JSON_INPUT_PROGRAM);
                                                            Syslog_JSON_Map->syslog_map_tag_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* username */

                                    if ( json_object_object_get_ex(json_obj, "username", &tmp) )
                                        {

                                            const char *username = json_object_get_string(tmp);

                                            if ( username != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->username_count > JSON_INPUT_USERNAME_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"username\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_username[JSON_INPUT_USERNAME_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_username, username, JSON_INPUT_USERNAME_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_username, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->username[ Syslog_JSON_Map->username_count ], ptmp, JSON_INPUT_USERNAME);
                                                            Syslog_JSON_Map->username_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* time */

                                    if ( json_object_object_get_ex(json_obj, "time", &tmp) )
                                        {

                                            const char *time = json_object_get_string(tmp);

                                            if ( time != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_time_count > JSON_INPUT_TIME_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"time\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_time[JSON_INPUT_TIME_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_time, time, JSON_INPUT_TIME_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_time, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_time[ Syslog_JSON_Map->syslog_map_time_count ], ptmp, JSON_INPUT_TIME);
                                                            Syslog_JSON_Map->syslog_map_time_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }


                                    /* date */

                                    if ( json_object_object_get_ex(json_obj, "date", &tmp) )
                                        {

                                            const char *date = json_object_get_string(tmp);

                                            if ( date != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_date_count > JSON_INPUT_DATE_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"date\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_date[JSON_INPUT_DATE_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_date, date, JSON_INPUT_DATE_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_date, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_date[ Syslog_JSON_Map->syslog_map_date_count ], ptmp, JSON_INPUT_DATE);
                                                            Syslog_JSON_Map->syslog_map_date_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* "program" or "event_type" mapping */

                                    if ( json_object_object_get_ex(json_obj, "program", &tmp) ||
                                            json_object_object_get_ex(json_obj, "event_type", &tmp) )
                                        {

                                            const char *program = json_object_get_string(tmp);

                                            if ( program != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_program_count > JSON_INPUT_PROGRAM_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"program\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_program[JSON_INPUT_PROGRAM_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_program, program, JSON_INPUT_PROGRAM_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_program, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_program[ Syslog_JSON_Map->syslog_map_program_count ], ptmp, JSON_INPUT_PROGRAM);
                                                            Syslog_JSON_Map->syslog_map_program_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* "message" mapping */

                                    if ( json_object_object_get_ex(json_obj, "message", &tmp) )
                                        {

                                            const char *message = json_object_get_string(tmp);

                                            if ( message != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->syslog_map_message_count > JSON_INPUT_MESSAGE_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"message\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_message[JSON_INPUT_MESSAGE_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_message, message, JSON_INPUT_MESSAGE_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_message, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->syslog_map_message[ Syslog_JSON_Map->syslog_map_message_count ], ptmp, JSON_INPUT_MESSAGE);
                                                            Syslog_JSON_Map->syslog_map_message_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* src_ip */

                                    if ( json_object_object_get_ex(json_obj, "src_ip", &tmp) )
                                        {

                                            const char *src_ip = json_object_get_string(tmp);

                                            if ( src_ip != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->src_ip_count > JSON_INPUT_SRCIP_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"src_ip\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_src_ip[JSON_INPUT_SRCIP_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_src_ip, src_ip, JSON_INPUT_SRCIP_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_src_ip, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->src_ip[ Syslog_JSON_Map->src_ip_count ], ptmp, JSON_INPUT_SRCIP);
                                                            Syslog_JSON_Map->src_ip_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    if ( json_object_object_get_ex(json_obj, "dst_ip", &tmp) || json_object_object_get_ex(json_obj, "dest_ip", &tmp) )
                                        {

                                            const char *dst_ip = json_object_get_string(tmp);

                                            if ( dst_ip != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->dst_ip_count > JSON_INPUT_DSTIP_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"dest_ip\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_dst_ip[JSON_INPUT_DSTIP_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_dst_ip, dst_ip, JSON_INPUT_DSTIP_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_dst_ip, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->dst_ip[ Syslog_JSON_Map->dst_ip_count ], ptmp, JSON_INPUT_DSTIP);
                                                            Syslog_JSON_Map->dst_ip_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* src_port */

                                    if ( json_object_object_get_ex(json_obj, "src_port", &tmp) )
                                        {

                                            const char *src_port = json_object_get_string(tmp);

                                            if ( src_port != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->src_port_count > JSON_INPUT_SRCPORT_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"src_port\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_src_port[JSON_INPUT_SRCPORT_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_src_port, src_port, JSON_INPUT_SRCPORT_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_src_port, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->src_port[ Syslog_JSON_Map->src_port_count ], ptmp, JSON_INPUT_SRCPORT);
                                                            Syslog_JSON_Map->src_port_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* dest_port */

                                    if ( json_object_object_get_ex(json_obj, "dst_port", &tmp) || json_object_object_get_ex(json_obj, "dest_port", &tmp)  )
                                        {

                                            const char *dst_port = json_object_get_string(tmp);

                                            if ( dst_port != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->dst_port_count > JSON_INPUT_DSTPORT_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"dest_port\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_dst_port[JSON_INPUT_DSTPORT_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_dst_port, dst_port, JSON_INPUT_DSTPORT_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_dst_port, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->dst_port[ Syslog_JSON_Map->dst_port_count ], ptmp, JSON_INPUT_DSTPORT);
                                                            Syslog_JSON_Map->dst_port_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* proto */

                                    if ( json_object_object_get_ex(json_obj, "proto", &tmp) )
                                        {

                                            const char *proto = json_object_get_string(tmp);

                                            if ( proto != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->proto_count > JSON_INPUT_PROTO_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"proto\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_proto[JSON_INPUT_PROTO_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_proto, proto, JSON_INPUT_PROTO_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_proto, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->proto[ Syslog_JSON_Map->proto_count ], ptmp, JSON_INPUT_PROTO);
                                                            Syslog_JSON_Map->proto_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* md5 */

                                    if ( json_object_object_get_ex(json_obj, "md5", &tmp) )
                                        {

                                            const char *md5 = json_object_get_string(tmp);

                                            if ( md5 != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->md5_count > JSON_INPUT_MD5_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"md5\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_md5[JSON_INPUT_MD5_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_md5, md5, JSON_INPUT_MD5_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_md5, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->md5[ Syslog_JSON_Map->md5_count ], ptmp, JSON_INPUT_MD5);
                                                            Syslog_JSON_Map->md5_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }


                                    /* sha1 */

                                    if ( json_object_object_get_ex(json_obj, "sha1", &tmp) )
                                        {

                                            const char *sha1 = json_object_get_string(tmp);

                                            if ( sha1 != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->sha1_count > JSON_INPUT_SHA1_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"sha1\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_sha1[JSON_INPUT_SHA1_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_sha1, sha1, JSON_INPUT_SHA1_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_sha1, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->sha1[ Syslog_JSON_Map->sha1_count ], ptmp, JSON_INPUT_SHA1);
                                                            Syslog_JSON_Map->sha1_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* sha256 */

                                    if ( json_object_object_get_ex(json_obj, "sha256", &tmp) )
                                        {

                                            const char *sha256 = json_object_get_string(tmp);

                                            if ( sha256 != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->sha256_count > JSON_INPUT_SHA256_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"sha256\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_sha256[JSON_INPUT_SHA256_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_sha256, sha256, JSON_INPUT_SHA256_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_sha256, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->sha256[ Syslog_JSON_Map->sha256_count ], ptmp, JSON_INPUT_SHA256);
                                                            Syslog_JSON_Map->sha256_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* filename */

                                    if ( json_object_object_get_ex(json_obj, "filename", &tmp) )
                                        {

                                            const char *filename = json_object_get_string(tmp);

                                            if ( filename != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->filename_count > JSON_INPUT_FILENAME_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"filename\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_filename[JSON_INPUT_FILENAME_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_filename, filename, JSON_INPUT_FILENAME_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_filename, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->filename[ Syslog_JSON_Map->filename_count ], ptmp, JSON_INPUT_FILENAME);
                                                            Syslog_JSON_Map->filename_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* hostname */

                                    if ( json_object_object_get_ex(json_obj, "hostname", &tmp) )
                                        {

                                            const char *hostname = json_object_get_string(tmp);

                                            if ( hostname != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->hostname_count > JSON_INPUT_HOSTNAME_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"hostname\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_hostname[JSON_INPUT_HOSTNAME_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_hostname, hostname, JSON_INPUT_HOSTNAME_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_hostname, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->hostname[ Syslog_JSON_Map->hostname_count ], ptmp, JSON_INPUT_HOSTNAME);
                                                            Syslog_JSON_Map->hostname_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* url */

                                    if ( json_object_object_get_ex(json_obj, "url", &tmp) )
                                        {

                                            const char *url = json_object_get_string(tmp);

                                            if ( url != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->url_count > JSON_INPUT_URL_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"url\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_url[JSON_INPUT_URL_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_url, url, JSON_INPUT_URL_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_url, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->url[ Syslog_JSON_Map->url_count ], ptmp, JSON_INPUT_URL);
                                                            Syslog_JSON_Map->url_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* ja3 */

                                    if ( json_object_object_get_ex(json_obj, "ja3", &tmp) )
                                        {

                                            const char *ja3 = json_object_get_string(tmp);

                                            if ( ja3 != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->ja3_count > JSON_INPUT_JA3_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"ja3\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_ja3[JSON_INPUT_JA3_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_ja3, ja3, JSON_INPUT_JA3_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_ja3, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->ja3[ Syslog_JSON_Map->ja3_count ], ptmp, JSON_INPUT_JA3);
                                                            Syslog_JSON_Map->ja3_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* flow_id */

                                    if ( json_object_object_get_ex(json_obj, "flow_id", &tmp) )
                                        {

                                            const char *flow_id = json_object_get_string(tmp);

                                            if ( flow_id != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->flow_id_count > JSON_INPUT_FLOW_ID_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"flow_id\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_flow_id[JSON_INPUT_FLOW_ID_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_flow_id, flow_id, JSON_INPUT_FLOW_ID_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_flow_id, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->flow_id[ Syslog_JSON_Map->flow_id_count ], ptmp, JSON_INPUT_FLOW_ID);
                                                            Syslog_JSON_Map->flow_id_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* event_id */

                                    if ( json_object_object_get_ex(json_obj, "event_id", &tmp) )
                                        {

                                            const char *event_id = json_object_get_string(tmp);

                                            if ( event_id != NULL )
                                                {

                                                    if ( Syslog_JSON_Map->event_id_count > JSON_INPUT_EVENT_ID_MAX_COUNT )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] To many \"event_id\" OR statments in %s for mapping %s", __FILE__, __LINE__, json_map, config->json_input_software );
                                                        }

                                                    char tmp_event_id[JSON_INPUT_EVENT_ID_MAX_SIZE] = { 0 };
                                                    memcpy(tmp_event_id, event_id, JSON_INPUT_EVENT_ID_MAX_SIZE);

                                                    ptmp = strtok_r( tmp_event_id, "|", &tok );

                                                    while (ptmp != NULL )
                                                        {
                                                            strlcpy(Syslog_JSON_Map->event_id[ Syslog_JSON_Map->event_id_count ], ptmp, JSON_INPUT_EVENT_ID);
                                                            Syslog_JSON_Map->event_id_count++;
                                                            ptmp = strtok_r(NULL, "|", &tok);
                                                        }

                                                }
                                        }

                                    /* Sanity Checks */

                                    if ( Syslog_JSON_Map->syslog_map_time[0][0] == '\0' )
                                        {
                                            Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'time'. Abort!",  config->json_input_software );
                                        }

                                    else if ( Syslog_JSON_Map->syslog_map_date[0][0] == '\0' )
                                        {
                                            Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'date'. Abort!",  config->json_input_software );
                                        }

                                    else if ( Syslog_JSON_Map->syslog_map_program[0][0] == '\0' )
                                        {
                                            Sagan_Log(ERROR, "Error.  No JSON mapping found in '%s' for 'program'. Abort!",  config->json_input_software );
                                        }

                                    else if ( Syslog_JSON_Map->syslog_map_message[0][0] == '\0' )
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
