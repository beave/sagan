/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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

/* alert.c
 *
 * Provides logging functionality in a 'snort like' format.  Usually in
 * the /var/log/sagan directory named 'alert'
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "sagan.h"

#include "alert.h"
#include "util-time.h"
#include "references.h"
#include "sagan-config.h"

struct _Rule_Struct *rulestruct;
struct _SaganConfig *config;
struct _SaganCounters *counters;

void Alert_File( _Sagan_Event *Event )
{

    char tmpref[256];
    char timebuf[64];

    CreateTimeString(&Event->event_time, timebuf, sizeof(timebuf), 1);

    counters->alert_total++;

    fprintf(config->sagan_alert_stream, "\n[**] [%lu:%s] %s [**]\n", Event->generatorid, Event->sid, Event->f_msg);
    fprintf(config->sagan_alert_stream, "[Classification: %s] [Priority: %d] [%s]\n", Event->class, Event->pri, Event->host );
    fprintf(config->sagan_alert_stream, "[Alert Time: %s]\n", timebuf);
    fprintf(config->sagan_alert_stream, "%s %s %s:%d -> %s:%d %s %s\n", Event->date, Event->time, Event->ip_src, Event->src_port, Event->ip_dst, Event->dst_port, Event->facility, Event->priority);
    fprintf(config->sagan_alert_stream, "Message: %s\n", Event->message);

    if ( Event->found != 0 ) {

        Reference_Lookup( Event->found, 0, tmpref, sizeof(tmpref) );

        if (strcmp(tmpref, "" )) {
            fprintf(config->sagan_alert_stream, "%s\n", tmpref);
        }
    }


    fflush(config->sagan_alert_stream);

}
