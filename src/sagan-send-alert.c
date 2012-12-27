/*
** Copyright (C) 2009-2012 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2012 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-send-alert.c 
 *
 * Fromats the alert for the SaganProcessor struct to send to output formats.
 *
 */

//#ifdef HAVE_CONFIG_H
//#include "config.h"             /* From autoconf */
//#endif

//#include <stdio.h>
//j#include "sagan.h"
/*
void Sagan_Send_Alert ( _SaganProcSyslog *SaganProcSyslog_LOCAL, 
                        int alertid, 
			char *generator_msg, 
			char *ip_src, char *ip_dst, 
			int port_src, int port_dst, 
			int proto  ) {

char tmp[64] = { 0 };

        struct _Sagan_Event *SaganProcessorEvent = NULL;
        SaganProcessorEvent = malloc(sizeof(struct _Sagan_Event));
        memset(SaganProcessorEvent, 0, sizeof(_SaganEvent));

        SaganProcessorEvent->f_msg = generator_msg;
        SaganProcessorEvent->message = SaganProcSyslog_LOCAL->syslog_message;

        SaganProcessorEvent->program         =       WEBSENSE_PROCESSOR_NAME;
        SaganProcessorEvent->facility        =       WEBSENSE_PROCESSOR_FACILITY;
        SaganProcessorEvent->priority        =       WEBSENSE_PROCESSOR_PRIORITY;

        SaganProcessorEvent->pri             =       WEBSENSE_PROCESSOR_PRI;
        SaganProcessorEvent->class           =       WEBSENSE_PROCESSOR_CLASS;
        SaganProcessorEvent->tag             =       WEBSENSE_PROCESSOR_TAG;
        SaganProcessorEvent->rev             =       WEBSENSE_PROCESSOR_REV;

        SaganProcessorEvent->ip_src          =       ip_src;
        SaganProcessorEvent->ip_dst          =       SaganProcSyslog_LOCAL->syslog_host;
        SaganProcessorEvent->dst_port        =       config->sagan_port;
        SaganProcessorEvent->src_port        =       config->sagan_port;
        SaganProcessorEvent->found           =       0;

        snprintf(tmp, sizeof(tmp), "%d", alertid);
        SaganProcessorEvent->sid             =       tmp;
        SaganProcessorEvent->time            =       SaganProcSyslog_LOCAL->syslog_time;
        SaganProcessorEvent->date            =       SaganProcSyslog_LOCAL->syslog_date;
        SaganProcessorEvent->ip_proto        =       proto;

        SaganProcessorEvent->event_time_sec  =          time(NULL);
        SaganProcessorEvent->found              =       0;

        SaganProcessorEvent->generatorid     =       WEBSENSE_PROCESSOR_GENERATOR_ID;

        Sagan_Output ( SaganProcessorEvent );
        free(SaganProcessorEvent);
}
*/
