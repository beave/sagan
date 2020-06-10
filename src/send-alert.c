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

/* send-alert.c
 *
 * Sends alert information to the correct processor
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include "sagan.h"
#include "version.h"

#include "output.h"
#include "gen-msg.h"

#include "processors/engine.h"

struct _SaganConfig *config;

void Send_Alert ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, char *json_normalize, _Sagan_Processor_Info *processor_info, char *ip_src, char *ip_dst, char *normalize_http_uri, char *normalize_http_hostname, int proto, uint64_t sid, int src_port, int dst_port, int pos, struct timeval tp, char *bluedot_json, unsigned char bluedot_results  )
{

    char tmp[64] = { 0 };

    struct _Sagan_Event *SaganProcessorEvent = NULL;
    SaganProcessorEvent = malloc(sizeof(struct _Sagan_Event));

    if ( SaganProcessorEvent == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcessorEvent. Abort!", __FILE__, __LINE__);
        }

    memset(SaganProcessorEvent, 0, sizeof(_Sagan_Event));

    if ( processor_info->processor_generator_id != SAGAN_PROCESSOR_GENERATOR_ID )
        {

            Generator_Lookup(processor_info->processor_generator_id, sid, tmp, sizeof(tmp));
            SaganProcessorEvent->f_msg           =       tmp;

        }
    else
        {

            SaganProcessorEvent->f_msg           =       processor_info->processor_name;
        }

    SaganProcessorEvent->message         =       SaganProcSyslog_LOCAL->syslog_message;
    SaganProcessorEvent->program	 = 	 SaganProcSyslog_LOCAL->syslog_program;
    SaganProcessorEvent->level           =       SaganProcSyslog_LOCAL->syslog_level;

    SaganProcessorEvent->facility        =       processor_info->processor_facility;
    SaganProcessorEvent->priority        =       processor_info->processor_priority;	/* Syslog priority */
    SaganProcessorEvent->pri             =       processor_info->processor_pri;		/* Sagan priority */
    SaganProcessorEvent->class           =       processor_info->processor_class;
    SaganProcessorEvent->tag             =       processor_info->processor_tag;
    SaganProcessorEvent->rev             =       processor_info->processor_rev;

    SaganProcessorEvent->ip_src          =       ip_src;
    SaganProcessorEvent->ip_dst          =       ip_dst;

    SaganProcessorEvent->dst_port        =       dst_port;
    SaganProcessorEvent->src_port        =       src_port;

    SaganProcessorEvent->found           =       pos;

    SaganProcessorEvent->normalize_http_uri	=	normalize_http_uri;
    SaganProcessorEvent->normalize_http_hostname=	normalize_http_hostname;

    SaganProcessorEvent->sid             =       sid;

    SaganProcessorEvent->host		 = 	 SaganProcSyslog_LOCAL->syslog_host;
    SaganProcessorEvent->time            =       SaganProcSyslog_LOCAL->syslog_time;
    SaganProcessorEvent->date            =       SaganProcSyslog_LOCAL->syslog_date;
    SaganProcessorEvent->ip_proto        =       proto;

    SaganProcessorEvent->event_time	 =       tp;

    SaganProcessorEvent->generatorid     =       processor_info->processor_generator_id;

    SaganProcessorEvent->json_normalize     =    json_normalize;
    SaganProcessorEvent->bluedot_json       =    bluedot_json;
    SaganProcessorEvent->bluedot_results    =    bluedot_results;

    SaganProcessorEvent->flow_id	    =    SaganProcSyslog_LOCAL->flow_id;


    Output ( SaganProcessorEvent );
    free(SaganProcessorEvent);

}

