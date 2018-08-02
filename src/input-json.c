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

struct _SaganCounters *counters;
struct _SaganConfig *config;

struct _Syslog_JSON_Map *Syslog_JSON_Map;


struct _SyslogInput *SyslogInput_JSON( char *syslog_string )
{

    struct _SyslogInput *SyslogInput = NULL;

    struct json_object *json_obj = NULL;
    struct json_object *tmp = NULL;

    char syslog_host[MAX_SYSLOG_HOST] = { 0 };
    char syslog_facility[MAX_SYSLOG_FACILITY] = { 0 };
    char syslog_priority[MAX_SYSLOG_PRIORITY] = { 0 };
    char syslog_level[MAX_SYSLOG_LEVEL] = { 0 };
    char syslog_tag[MAX_SYSLOG_TAG] = { 0 };
    char syslog_date[MAX_SYSLOG_DATE] = { 0 };
    char syslog_time[MAX_SYSLOG_TIME] = { 0 };
    char syslog_program[MAX_SYSLOG_PROGRAM] = { 0 };
    char syslog_message[MAX_SYSLOGMSG] = { 0 };

    SyslogInput = malloc(sizeof(_SyslogInput));

    if ( SyslogInput == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SyslogInput. Abort!", __FILE__, __LINE__);
        }

    memset(SyslogInput, 0, sizeof(_SyslogInput));

    SyslogInput->syslog_host = "UNDEFINED";
    SyslogInput->syslog_facility = "UNDEFINED";
    SyslogInput->syslog_priority = "UNDEFINED";
    SyslogInput->syslog_level = "UNDEFINED";
    SyslogInput->syslog_tag = "UNDEFINED";
    SyslogInput->syslog_date = "UNDEFINED";
    SyslogInput->syslog_time = "UNDEFINED";
    SyslogInput->syslog_program = "UNDEFINED";
    SyslogInput->syslog_msg = "UNDEFINED";

    json_obj = json_tokener_parse(syslog_string);

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_host, &tmp))
        {
            strlcpy(syslog_host,  json_object_get_string(tmp), sizeof(syslog_host));
            SyslogInput->syslog_host = syslog_host;
        }

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_facility, &tmp))
        {
            strlcpy(syslog_facility,  json_object_get_string(tmp), sizeof(syslog_facility));
            SyslogInput->syslog_facility = syslog_facility;
        }

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_priority, &tmp))
        {
            strlcpy(syslog_priority,  json_object_get_string(tmp), sizeof(syslog_priority));
            SyslogInput->syslog_priority = syslog_priority;
        }

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_level, &tmp))
        {
            strlcpy(syslog_level,  json_object_get_string(tmp), sizeof(syslog_level));
            SyslogInput->syslog_level = syslog_level;
        }

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_tags, &tmp))
        {
            strlcpy(syslog_tag,  json_object_get_string(tmp), sizeof(syslog_tag));
            SyslogInput->syslog_tag = syslog_tag;
        }

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_date, &tmp))
        {
            strlcpy(syslog_date,  json_object_get_string(tmp), sizeof(syslog_date));
            SyslogInput->syslog_date = syslog_date;
        }

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_time, &tmp))
        {
            strlcpy(syslog_time,  json_object_get_string(tmp), sizeof(syslog_time));
            SyslogInput->syslog_time = syslog_date;
        }

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_program, &tmp))
        {
            strlcpy(syslog_program,  json_object_get_string(tmp), sizeof(syslog_program));
            SyslogInput->syslog_program = syslog_program;
        }

    if ( json_object_object_get_ex(json_obj, Syslog_JSON_Map->syslog_map_message, &tmp))
        {
            strlcpy(syslog_message,  json_object_get_string(tmp), sizeof(syslog_message));
            SyslogInput->syslog_msg = syslog_message;
        }


    json_object_put(json_obj);

    return(SyslogInput);

}

#endif
