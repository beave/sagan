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

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;

struct _Syslog_JSON_Map *Syslog_JSON_Map;

void SyslogInput_JSON( char *syslog_string, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    uint16_t i;

    memset(SaganProcSyslog_LOCAL, 0, sizeof(_Sagan_Proc_Syslog));

    memcpy(SaganProcSyslog_LOCAL->syslog_program, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_time, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_date, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_tag, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_level, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_priority, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_facility, "UNDEFINED\0", 10);
    memcpy(SaganProcSyslog_LOCAL->syslog_host, "0.0.0.0\0", 8);

    /* Search through all key/values looking for embedded JSON */

    Parse_JSON( syslog_string, SaganProcSyslog_LOCAL );

    /* User wants the entire JSON to become the "message" */

    if ( !strcmp(Syslog_JSON_Map->syslog_map_message, "%JSON%" ) )
        {
            snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), "%s", syslog_string);
            SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';
        }

    for (i = 0; i < SaganProcSyslog_LOCAL->json_count; i++ )
        {

            /* Strings - Don't use else if, because all values need to be parsed */

            if ( Syslog_JSON_Map->syslog_map_message[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_message, SaganProcSyslog_LOCAL->json_key[i] ) )
                {

                    /* We add a "space" for things like normalization */

                    snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), " %s", SaganProcSyslog_LOCAL->json_value[i]);
                    SaganProcSyslog_LOCAL->syslog_message[ sizeof(SaganProcSyslog_LOCAL->syslog_message) -1 ] = '\0';
                }

            if ( Syslog_JSON_Map->event_id[0] != '\0' && !strcmp(Syslog_JSON_Map->event_id, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->event_id, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->event_id));
                }

            if ( Syslog_JSON_Map->syslog_map_host[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_host, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_host));
                }

            if ( Syslog_JSON_Map->syslog_map_facility[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_facility, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                }

            if ( Syslog_JSON_Map->syslog_map_priority[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_priority, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                }

            if ( Syslog_JSON_Map->syslog_map_level[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_level, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_level));
                }

            if ( Syslog_JSON_Map->syslog_map_tag[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_tag, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                }

            if ( Syslog_JSON_Map->syslog_map_date[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_date, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_date));
                }

            if ( Syslog_JSON_Map->syslog_map_time[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_time, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_time));
                }

            if ( Syslog_JSON_Map->syslog_map_program[0] != '\0' && !strcmp(Syslog_JSON_Map->syslog_map_program, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->syslog_program));
                }

            if ( Syslog_JSON_Map->username[0] != '\0' && !strcmp(Syslog_JSON_Map->username, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->username, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->username));
                }

            if ( Syslog_JSON_Map->src_ip[0] != '\0' && !strcmp(Syslog_JSON_Map->src_ip, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->src_ip, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->src_ip));
                }

            if ( Syslog_JSON_Map->dst_ip[0] != '\0' && !strcmp(Syslog_JSON_Map->dst_ip, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->dst_ip, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->dst_ip));
                }

            if ( Syslog_JSON_Map->md5[0] != '\0' && !strcmp(Syslog_JSON_Map->md5, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->md5, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->md5));
                }

            if ( Syslog_JSON_Map->sha1[0] != '\0' && !strcmp(Syslog_JSON_Map->sha1, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->sha1, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->sha1));
                }

            if ( Syslog_JSON_Map->sha256[0] != '\0' && !strcmp(Syslog_JSON_Map->sha256, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->sha256, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->sha256));
                }

            if ( Syslog_JSON_Map->filename[0] != '\0' && !strcmp(Syslog_JSON_Map->filename, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->filename, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->filename));
                }

            if ( Syslog_JSON_Map->hostname[0] != '\0' && !strcmp(Syslog_JSON_Map->hostname, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->hostname, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->hostname));
                }

            if ( Syslog_JSON_Map->url[0] != '\0' && !strcmp(Syslog_JSON_Map->url, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->url, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->url));
                }

            if ( Syslog_JSON_Map->ja3[0] != '\0' && !strcmp(Syslog_JSON_Map->ja3, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    strlcpy(SaganProcSyslog_LOCAL->ja3, SaganProcSyslog_LOCAL->json_value[i], sizeof(SaganProcSyslog_LOCAL->ja3));
                }

            /* Math */

            if ( Syslog_JSON_Map->src_port[0] != '\0' && !strcmp(Syslog_JSON_Map->src_port, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->src_port = atoi(SaganProcSyslog_LOCAL->json_value[i]);
                }

            if ( Syslog_JSON_Map->dst_port[0] != '\0' && !strcmp(Syslog_JSON_Map->dst_port, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->dst_port = atoi(SaganProcSyslog_LOCAL->json_value[i]);
                }

            if ( Syslog_JSON_Map->flow_id[0] != '\0' && !strcmp(Syslog_JSON_Map->flow_id, SaganProcSyslog_LOCAL->json_key[i] ) )
                {
                    SaganProcSyslog_LOCAL->flow_id = atol(SaganProcSyslog_LOCAL->json_value[i]);
                }


            /* Multi-function */

            if ( Syslog_JSON_Map->proto[0] != '\0' && !strcmp(Syslog_JSON_Map->proto, SaganProcSyslog_LOCAL->json_key[i] ) )
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
