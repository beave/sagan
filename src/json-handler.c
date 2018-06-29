/* $Id$ */

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

/* json.c
 *
 * Functions that handle JSON output.
 *
 */



#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "references.h"
#include "util-base64.h"
#include "util-time.h"
#include "sagan-config.h"
#include "json-handler.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;

/*****************************************************************************
 * Format_JSON_Alert_EVE - Sends only alerts out to eve file in JSON
 *****************************************************************************/

void Format_JSON_Alert_EVE( _Sagan_Event *Event, char *str, size_t size )
{

    char *proto = NULL;
    char *drop = NULL;

    char timebuf[64];
    char classbuf[64];

    if ( Event->ip_proto == 17 )
        {
            proto = "UDP";
        }

    else if ( Event->ip_proto == 6 )
        {
            proto = "TCP";
        }

    else if ( Event->ip_proto == 1 )
        {
            proto = "ICMP";
        }

    else if ( Event->ip_proto != 1 || Event->ip_proto != 6 || Event->ip_proto != 17 )
        {
            proto = "UNKNOWN";
        }

    if ( Event->drop == true )
        {

            drop = "blocked";

        }
    else
        {
            drop = "allowed";
        }

    CreateIsoTimeString(&Event->event_time, timebuf, sizeof(timebuf));

    unsigned long b64_len = strlen(Event->message) * 2;
    uint8_t b64_target[b64_len];

    Base64Encode( (const unsigned char*)Event->message, strlen(Event->message), b64_target, &b64_len);
    Classtype_Lookup( Event->class, classbuf, sizeof(classbuf) );

    snprintf(str, size, EVE_ALERT, timebuf, FlowGetId(Event->event_time), config->eve_interface, Event->ip_src, Event->src_port, Event->ip_dst, Event->dst_port, proto, drop, Event->generatorid, Event->sid, Event->rev,Event->f_msg, classbuf, Event->pri, b64_target, "", Event->host, !Event->json_normalize ? "{}" : json_object_to_json_string_ext(Event->json_normalize, FJSON_TO_STRING_PLAIN));

    if ( debug->debugjson )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Format_JSON_Alert_EVE Output: %s", __FILE__, __LINE__, str);
        }

}

/*****************************************************************************
 * Format_JSON_Log_EVE - Outputs all logs to the JSON/Eve file.
 *****************************************************************************/

void Format_JSON_Log_EVE( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, struct timeval tp, char *str, size_t size, json_object *json_normalize )
{

    struct json_object *jobj;
    char timebuf[64];
    char tmp[32];
    char *proto = NULL;

    char tmp_data[MAX_SYSLOGMSG+1024] = { 0 };

    CreateIsoTimeString(&tp, timebuf, sizeof(timebuf));

    jobj = json_object_new_object();

    json_object *jdate = json_object_new_string(timebuf);
    json_object_object_add(jobj,"timestamp", jdate);

    json_object *jevent_type = json_object_new_string("log");
    json_object_object_add(jobj,"event_type", jevent_type);

    json_object *jflow_id = json_object_new_int64( FlowGetId(tp) );
    json_object_object_add(jobj,"flow_id", jflow_id);

    json_object *jsyslog_host = json_object_new_string(SaganProcSyslog_LOCAL->syslog_host);
    json_object_object_add(jobj,"syslog_source", jsyslog_host);

    json_object *jsyslog_proto = json_object_new_string(config->sagan_proto_string);
    json_object_object_add(jobj,"syslog_proto", jsyslog_proto);

    json_object *jsyslog_facility = json_object_new_string(SaganProcSyslog_LOCAL->syslog_facility);
    json_object_object_add(jobj,"facility", jsyslog_facility);

    json_object *jsyslog_priority = json_object_new_string(SaganProcSyslog_LOCAL->syslog_priority);
    json_object_object_add(jobj,"priority", jsyslog_priority);

    json_object *jsyslog_level = json_object_new_string(SaganProcSyslog_LOCAL->syslog_level);
    json_object_object_add(jobj,"level", jsyslog_level);

    json_object *jsyslog_tag = json_object_new_string(SaganProcSyslog_LOCAL->syslog_tag);
    json_object_object_add(jobj,"tag", jsyslog_tag);

    snprintf(tmp, sizeof(tmp), "%s %s", SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog_LOCAL->syslog_time);
    json_object *jsyslog_timestamp = json_object_new_string(tmp);
    json_object_object_add(jobj,"source_timestamp", jsyslog_timestamp);

    json_object *jsyslog_program = json_object_new_string(SaganProcSyslog_LOCAL->syslog_program);
    json_object_object_add(jobj,"program", jsyslog_program);

    json_object *jsyslog_message = json_object_new_string(SaganProcSyslog_LOCAL->syslog_message);
    json_object_object_add(jobj,"message", jsyslog_message);

    snprintf(tmp_data, sizeof(tmp_data), "%s", json_object_to_json_string(jobj));
    tmp_data[strlen(tmp_data) - 2] = '\0';

    snprintf(str, size, "%s, \"normalize\": %s }", tmp_data,  json_object_to_json_string_ext(json_normalize, FJSON_TO_STRING_PLAIN));

    if ( debug->debugjson )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Format_JSON_Log_EVE Output: %s", __FILE__, __LINE__, str);
        }

}
