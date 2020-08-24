/* $Id$ */

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

/* json.c
 *
 * Functions that handle JSON output.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "references.h"
#include "rules.h"
#include "util-base64.h"
#include "util-time.h"
#include "sagan-config.h"
#include "json-handler.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _Rule_Struct *rulestruct;

/*****************************************************************************
 * Format_JSON_Alert_EVE - Sends only alerts out to eve file in JSON
 *****************************************************************************/

void Format_JSON_Alert_EVE( _Sagan_Event *Event, char *str, size_t size )
{

    struct json_object *jobj;
    struct json_object *jobj_alert;

    char *proto = NULL;
    char *action = NULL;

    char timebuf[64];
    char classbuf[64];

    /* For base64 encoding */

    unsigned long b64_len = strlen(Event->message) * 2;
    uint8_t b64_target[b64_len];

    char tmp_data[MAX_SYSLOGMSG*2] = { 0 };

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
            action = "blocked";
        }
    else
        {
            action = "allowed";
        }

    CreateIsoTimeString(&Event->event_time, timebuf, sizeof(timebuf));

    if ( config->eve_alerts_base64 == true )
        {
            Base64Encode( (const unsigned char*)Event->message, strlen(Event->message), b64_target, &b64_len);
        }

    Classtype_Lookup( Event->class, classbuf, sizeof(classbuf) );

    jobj = json_object_new_object();
    jobj_alert = json_object_new_object();

    json_object *jdate = json_object_new_string(timebuf);
    json_object_object_add(jobj,"timestamp", jdate);

    /* If we don't have a flow_id,  create one */

    if ( Event->flow_id == 0 )
        {
            json_object *jflow_id = json_object_new_int64( FlowGetId(Event->event_time) );
            json_object_object_add(jobj,"flow_id", jflow_id);
        }
    else
        {

            /* Get already corresponding flow_id (likely from JSON/suricata) */

            json_object *jflow_id = json_object_new_int64( Event->flow_id );
            json_object_object_add(jobj,"flow_id", jflow_id);
        }


    json_object *jin_iface = json_object_new_string( config->eve_interface );
    json_object_object_add(jobj,"in_iface", jin_iface);

    json_object *jevent_type = json_object_new_string( "alert" );
    json_object_object_add(jobj,"event_type", jevent_type);

    json_object *jsrc_ip = json_object_new_string( Event->ip_src );
    json_object_object_add(jobj,"src_ip", jsrc_ip);

    json_object *jsrc_port = json_object_new_int( Event->src_port );
    json_object_object_add(jobj,"src_port", jsrc_port);

    json_object *jdest_ip = json_object_new_string( Event->ip_dst );
    json_object_object_add(jobj,"dest_ip", jdest_ip);

    json_object *jdest_port = json_object_new_int( Event->dst_port );
    json_object_object_add(jobj,"dest_port", jdest_port);

    json_object *jproto = json_object_new_string( proto );
    json_object_object_add(jobj,"proto", jproto);

    if ( config->eve_alerts_base64 == true )
        {
            json_object *jpayload = json_object_new_string( (const char *)b64_target );
            json_object_object_add(jobj,"payload", jpayload);
        }
    else
        {
            json_object *jpayload = json_object_new_string( Event->message );
            json_object_object_add(jobj,"payload", jpayload);
        }

    json_object *jstream = json_object_new_string( "0" );
    json_object_object_add(jobj,"stream", jstream);

    json_object *jxff = json_object_new_string( Event->host );
    json_object_object_add(jobj,"xff", jxff);

    json_object *jsyslog_facility = json_object_new_string(Event->facility);
    json_object_object_add(jobj,"facility", jsyslog_facility);

    json_object *jsyslog_priority = json_object_new_string(Event->priority);
    json_object_object_add(jobj,"priority", jsyslog_priority);

    json_object *jsyslog_level = json_object_new_string(Event->level);
    json_object_object_add(jobj,"level", jsyslog_level);

    json_object *jsyslog_program = json_object_new_string(Event->program);
    json_object_object_add(jobj,"program", jsyslog_program);

    json_object *jsyslog_host = json_object_new_string(config->sagan_sensor_name);
    json_object_object_add(jobj,"host", jsyslog_host);

    /* Alert data */

    json_object *jaction_alert = json_object_new_string( action );
    json_object_object_add(jobj_alert,"action", jaction_alert);

    json_object *jgid_alert = json_object_new_int64( Event->generatorid );
    json_object_object_add(jobj_alert,"gid", jgid_alert);

    json_object *jsignature_alert = json_object_new_int64( Event->sid );
    json_object_object_add(jobj_alert,"signature_id", jsignature_alert);

    json_object *jrev_alert = json_object_new_int64( Event->rev );
    json_object_object_add(jobj_alert,"rev", jrev_alert);

    json_object *jsig_name_alert = json_object_new_string( Event->f_msg );
    json_object_object_add(jobj_alert,"signature", jsig_name_alert);

    json_object *jclass_alert = json_object_new_string( classbuf );
    json_object_object_add(jobj_alert,"category", jclass_alert);

    json_object *jseverity_alert = json_object_new_int( Event->pri );
    json_object_object_add(jobj_alert,"severity", jseverity_alert);

    /* libfastjson doesn't support JSON_C_TO_STRING_NOSLASHESCAPE :( */

    snprintf(tmp_data, sizeof(tmp_data), "%s", json_object_to_json_string(jobj));
    tmp_data[strlen(tmp_data) - 2] = '\0';

    snprintf(str, size, "%s, \"alert\": %s", tmp_data, json_object_to_json_string(jobj_alert));

#ifdef WITH_BLUEDOT

    /* If we have bluedot data, dump it to eve */

    if ( Event->bluedot_results != 0 )
        {
            snprintf(tmp_data, sizeof(tmp_data), ", \"bluedot\": %s", Event->bluedot_json);
            strlcat(str, tmp_data, size);

        }

#endif

    if ( rulestruct[Event->found].metadata_json[0] != '\0' )
        {

            str[ strlen(str) - 2 ] = '\0';
            snprintf(tmp_data, sizeof(tmp_data), ", \"metadata\": %s }",  rulestruct[Event->found].metadata_json);
            strlcat(str, tmp_data, size);

        }

    /* Dump any normalization (liblognorm) data, if we have any */

    snprintf(tmp_data, sizeof(tmp_data), ", \"normalize\": %s", Event->json_normalize[0] == '\0' ? "null" : Event->json_normalize);

    strlcat(str, tmp_data, size);

    strlcat(str, " }", size);

    json_object_put(jobj);
    json_object_put(jobj_alert);

    if ( debug->debugjson )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Format_JSON_Alert_EVE Output: %s", __FILE__, __LINE__, str);
        }

}

/*****************************************************************************
 * Format_JSON_Log_EVE - Outputs all logs to the JSON/Eve file.
 *****************************************************************************/

void Format_JSON_Log_EVE( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, struct timeval tp, char *str, size_t size )
{

    struct json_object *jobj;
    char timebuf[64] = { 0 };
    char tmp[32] = { 0 };

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

    /* liblognorm doesn't support JSON_C_TO_STRING_NOSLASHESCAPE :( */

    /*

    This was for adding "normalization" data (when applicable).  It's been removed but
    might need it some day?

    snprintf(tmp_data, sizeof(tmp_data), "%s", json_object_to_json_string(jobj));
    tmp_data[strlen(tmp_data) - 2] = '\0';
    snprintf(str, size, "%s, \"normalize\": %s }", tmp_data,  SaganProcSyslog_LOCAL->json_normalize);
    */

    snprintf(str, size, "%s", json_object_to_json_string(jobj));

    json_object_put(jobj);

    if ( debug->debugjson )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Format_JSON_Log_EVE Output: %s", __FILE__, __LINE__, str);
        }

}

#endif
