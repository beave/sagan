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

/* external.c
 *
 * Threaded function for user defined external system (execl) calls.  This
 * allows sagan to pass information to a external program.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "version.h"

#include "lockfile.h"
#include "references.h"
#include "sagan-config.h"
#include "util-time.h"
#include "output-plugins/external.h"

struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

pthread_mutex_t ext_mutex = PTHREAD_MUTEX_INITIALIZER;


void External_Thread ( _Sagan_Event *Event, char *execute_script )
{

#ifndef HAVE_LIBFASTJSON
    Sagan_Log(WARN, "[%s, line %d] The 'external' rule option requires Sagan to be compiled with 'linfastjson'.",  __FILE__, __LINE__);
#endif

#ifdef HAVE_LIBFASTJSON

    int in[2];
    int out[2];
    int n;
    int pid;
    char buf[MAX_SYSLOGMSG];
    char tmpref[256];
    char timebuf[64] = { 0 };

    char tmp_data[MAX_SYSLOGMSG*2] = { 0 };
    char data[MAX_SYSLOGMSG*2] = { 0 };


    char *drop=NULL;
    char *proto=NULL;

    struct json_object *jobj;

    if ( debug->debugexternal )
        {
            Sagan_Log(WARN, "[%s, line %d] In External_Thread()", __FILE__, __LINE__);
        }

    Reference_Lookup( Event->found, 1, tmpref, sizeof(tmpref));
    CreateTimeString(&Event->event_time, timebuf, sizeof(timebuf), 1);

    if ( Event->drop == 1 )
        {
            drop="true";
        }
    else
        {
            drop="false";
        }

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

    jobj = json_object_new_object();

    json_object *jsensor_id = json_object_new_int64( Event->sid );
    json_object_object_add(jobj,"signature_id", jsensor_id);

    json_object *jsignature = json_object_new_string( Event->f_msg );
    json_object_object_add(jobj,"signature", jsignature);

    json_object *jrev = json_object_new_int64( Event->rev );
    json_object_object_add(jobj,"rev", jrev);

    json_object *jseverity = json_object_new_int( Event->pri );
    json_object_object_add(jobj,"severity", jseverity);

    json_object *jcategory = json_object_new_string( Event->class );
    json_object_object_add(jobj,"category", jcategory);

    json_object *jpriority = json_object_new_int( Event->pri );
    json_object_object_add(jobj,"priority", jpriority);

    json_object *jtimestamp = json_object_new_string( timebuf );
    json_object_object_add(jobj,"timestamp", jtimestamp);

    json_object *jdrop = json_object_new_string( drop );
    json_object_object_add(jobj,"drop", jdrop);

    json_object *jflow_id = json_object_new_int64( FlowGetId(Event->event_time) );
    json_object_object_add(jobj,"flow_id", jflow_id);

    json_object *jin_iface = json_object_new_string( config->eve_interface );
    json_object_object_add(jobj,"in_iface", jin_iface);

    json_object *jip_src = json_object_new_string( Event->ip_src );
    json_object_object_add(jobj,"src_ip", jip_src);

    json_object *jsrc_port = json_object_new_int( Event->src_port );
    json_object_object_add(jobj,"src_port", jsrc_port);

    json_object *jip_dst = json_object_new_string( Event->ip_dst );
    json_object_object_add(jobj,"dest_ip", jip_dst);

    json_object *jdst_port = json_object_new_int( Event->dst_port );
    json_object_object_add(jobj,"dest_port", jdst_port);

    json_object *jxff = json_object_new_string( Event->host );
    json_object_object_add(jobj,"xff", jxff);

    json_object *jproto = json_object_new_string( proto );
    json_object_object_add(jobj,"proto", jproto);

    json_object *jsyslog_facility = json_object_new_string( Event->facility );
    json_object_object_add(jobj,"syslog_facility", jsyslog_facility);

    json_object *jsyslog_level = json_object_new_string( Event->level );
    json_object_object_add(jobj,"syslog_level", jsyslog_level);

    json_object *jsyslog_priority = json_object_new_string( Event->priority );
    json_object_object_add(jobj,"syslog_priority", jsyslog_priority);

    json_object *jsyslog_message = json_object_new_string( Event->message );
    json_object_object_add(jobj,"syslog_message", jsyslog_message);

    /* liblognorm doesn't support JSON_C_TO_STRING_NOSLASHESCAPE :( */

    snprintf(tmp_data, sizeof(tmp_data), "%s", json_object_to_json_string(jobj));
    tmp_data[strlen(tmp_data) - 2] = '\0';

    snprintf(data, sizeof(data), "%s, \"normalize\": %s }\n", tmp_data, !Event->json_normalize ? "{}" : Event->json_normalize);

    data[ sizeof(data) - 1 ] = '\0';

    json_object_put(jobj);

    if ( debug->debugexternal )
        {
            Sagan_Log(WARN, "[%s, line %d] Sending: %s", __FILE__, __LINE__, data);
        }

    pthread_mutex_lock( &ext_mutex );

    if ( pipe(in) < 0 )
        {
            Remove_Lock_File();
            Sagan_Log(ERROR, "[%s, line %d] Cannot create input pipe!", __FILE__, __LINE__);
        }


    if ( pipe(out) < 0 )
        {
            Remove_Lock_File();
            Sagan_Log(ERROR, "[%s, line %d] Cannot create output pipe!", __FILE__, __LINE__);
        }

    pid=fork();
    if ( pid < 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot create external program process", __FILE__, __LINE__);
        }
    else if ( pid == 0 )
        {
            /* Causes problems with alert.log */

            close(0);
            close(1);
            close(2);

            dup2(in[0],0);		// Stdin..
            dup2(out[1],1);
            dup2(out[1],2);

            close(in[1]);
            close(out[0]);

            execl(execute_script, execute_script, NULL, (char *)NULL);

            Remove_Lock_File();
            Sagan_Log(WARN, "[%s, line %d] Cannot execute %s", __FILE__, __LINE__, execute_script);
        }

    close(in[0]);
    close(out[1]);

    /* Write to child input */

    n = write(in[1], data, strlen(data));
    close(in[1]);

    n = read(out[0], buf, sizeof(buf));
    close(out[0]);
    buf[n] = 0;

    waitpid(pid, NULL, 0);

    pthread_mutex_unlock( &ext_mutex );

    if ( debug->debugexternal == 1 )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Executed %s", __FILE__, __LINE__, execute_script);
        }

#endif

}

