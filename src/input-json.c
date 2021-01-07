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

#include "parsers/json.h"

extern struct _SaganCounters *counters;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

extern struct _Syslog_JSON_Map *Syslog_JSON_Map;

void SyslogInput_JSON( char *syslog_string, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    uint16_t i = 0;
    uint8_t a = 0;

    bool program_found = false;
    bool message_found = false;
    bool s_host_found = false;
    bool facility_found = false;
    bool level_found = false;
    bool priority_found = false;
    bool tag_found = false;
    bool username_found = false;
    bool time_found = false;
    bool date_found = false;
    bool src_ip_found = false;
    bool dst_ip_found = false;
    bool src_port_found = false;
    bool dst_port_found = false;
    bool md5_found = false;
    bool sha1_found = false;
    bool sha256_found = false;
    bool filename_found = false;
    bool hostname_found = false;
    bool url_found = false;
    bool ja3_found = false;
    bool flow_id_found = false;
    bool event_id_found = false;
    bool proto_found = false;

    memset(SaganProcSyslog_LOCAL, 0, sizeof(_Sagan_Proc_Syslog));

    memcpy(SaganProcSyslog_LOCAL->syslog_program, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_time, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_date, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_tag, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_level, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_priority, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_facility, "UNDEFINED", 9);
    memcpy(SaganProcSyslog_LOCAL->syslog_host, "0.0.0.0", 8);

    memcpy(SaganProcSyslog_LOCAL->event_id, "UNDEFINED", 8);

    /* Search through all key/values looking for embedded JSON */

    Parse_JSON( syslog_string, SaganProcSyslog_LOCAL );

    /* User wants the entire JSON to become the "message" */

    if ( !strcmp(Syslog_JSON_Map->syslog_map_message[0], "%JSON%" ) )
        {
            snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), "%s", syslog_string);
            SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';
        }

    for (i = 0; i < SaganProcSyslog_LOCAL->json_count; i++ )
        {

            /* Strings - Don't use else if, because all values need to be parsed */

            if ( Syslog_JSON_Map->syslog_map_message[0][0] != '\0' && message_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_message_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_message[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    /* Space added for further "normalization" */

                                    snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), " %s", SaganProcSyslog_LOCAL->json_value[i]);
                                    SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';

                                    message_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->event_id[0][0] != '\0' && event_id_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->event_id_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->event_id[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->event_id, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->event_id));
                                    event_id_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->syslog_map_host[0][0] != '\0' && s_host_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_host_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_host[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_host));
                                    s_host_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_facility[0][0] != '\0' && facility_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_facility_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_facility[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                                    facility_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->syslog_map_priority[0][0] != '\0' && priority_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_priority_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_priority[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                                    priority_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_level[0][0] != '\0' && level_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_level_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_level[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_level));
                                    level_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_tag[0][0] != '\0' && tag_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_tag_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_tag[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                                    tag_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_date[0][0] != '\0' && date_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_date_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_date[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_date));
                                    date_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_time[0][0] != '\0' && time_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_time_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_time[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_time));
                                    time_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->syslog_map_program[0][0] != '\0' && program_found == false )
                {

                    for ( a = 0; a < Syslog_JSON_Map->syslog_map_program_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->syslog_map_program[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_program));
                                    program_found = true;
                                    break;

                                }
                        }
                }


            if ( Syslog_JSON_Map->username[0][0] != '\0' && username_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->username_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->username[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->username, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->username));
                                    username_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->src_ip[0][0] != '\0' && src_ip_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->src_ip_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->src_ip[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->src_ip));
                                    src_ip_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->dst_ip[0][0] != '\0' && dst_ip_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->dst_ip_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->dst_ip[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->dst_ip));
                                    dst_ip_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->md5[0][0] != '\0' && md5_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->md5_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->md5[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->md5, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->md5));
                                    md5_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->sha1[0][0] != '\0' && sha1_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->sha1_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->sha1[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->sha1, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->sha1));
                                    sha1_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->sha256[0][0] != '\0' && sha256_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->sha256_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->sha256[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->sha256, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->sha256));
                                    sha256_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->filename[0][0] != '\0' && filename_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->filename_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->filename[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->filename, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->filename));
                                    filename_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->hostname[0][0] != '\0' && hostname_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->hostname_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->hostname[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->hostname, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->hostname));
                                    hostname_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->url[0][0] != '\0' && url_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->url_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->url[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->url, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->url));
                                    url_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->ja3[0][0] != '\0' && ja3_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->ja3_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->ja3[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    strlcpy(SaganProcSyslog_LOCAL->ja3, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->ja3));
                                    ja3_found = true;
                                    break;

                                }
                        }
                }

            /* Math */

            if ( Syslog_JSON_Map->src_port[0][0] != '\0' && src_port_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->src_port_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->src_port[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    SaganProcSyslog_LOCAL->src_port = atoi(SaganProcSyslog_LOCAL->json_value[i]);

                                    src_port_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->dst_port[0][0] != '\0' && dst_port_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->dst_port_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->dst_port[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    SaganProcSyslog_LOCAL->dst_port = atoi(SaganProcSyslog_LOCAL->json_value[i]);

                                    dst_port_found = true;
                                    break;

                                }
                        }
                }

            if ( Syslog_JSON_Map->flow_id[0][0] != '\0' && flow_id_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->flow_id_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->flow_id[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    SaganProcSyslog_LOCAL->flow_id = atoi(SaganProcSyslog_LOCAL->json_value[i]);

                                    flow_id_found = true;
                                    break;

                                }
                        }
                }


            /* Multi-function */

            if ( Syslog_JSON_Map->proto[0][0] != '\0' && proto_found == false )
                {
                    for ( a = 0; a < Syslog_JSON_Map->proto_count; a++ )
                        {

                            if ( !strcmp(Syslog_JSON_Map->proto[a], SaganProcSyslog_LOCAL->json_key[i] ) )
                                {

                                    if ( !strcasecmp( SaganProcSyslog_LOCAL->json_value[i], "tcp" ) )
                                        {
                                            SaganProcSyslog_LOCAL->proto = 6;
                                            proto_found = true;
                                            break;
                                        }

                                    else if ( !strcasecmp( SaganProcSyslog_LOCAL->json_value[i], "udp" ) )
                                        {
                                            SaganProcSyslog_LOCAL->proto = 17;
                                            proto_found = true;
                                            break;
                                        }

                                    else if ( !strcasecmp( SaganProcSyslog_LOCAL->json_value[i], "icmp" ) )
                                        {
                                            SaganProcSyslog_LOCAL->proto = 1;
                                            proto_found = true;
                                            break;
                                        }

                                }

                        }

                }

        } /* for i */

    /* If debugging, dump data that was located */

    if ( debug->debugjson )
        {
            Debug_Sagan_Proc_Syslog( SaganProcSyslog_LOCAL );
        }

}

#endif
