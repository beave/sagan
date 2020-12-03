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
#include <errno.h>

#include "sagan.h"

#include "alert.h"
#include "util-time.h"
#include "rules.h"
#include "references.h"
#include "sagan-config.h"

struct _Rule_Struct *rulestruct;
struct _SaganConfig *config;
struct _SaganCounters *counters;

void Alert_File( _Sagan_Event *Event )
{

    char tmpref[256];
    char timebuf[64];

    FILE *sagan_alert_stream;
    int sagan_alert_stream_int = 0;

    CreateTimeString(&Event->event_time, timebuf, sizeof(timebuf), 1);

    __atomic_add_fetch(&counters->alert_total, 1, __ATOMIC_SEQ_CST);

    if (( sagan_alert_stream = fopen( config->sagan_alert_filepath, "a" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open %s (%s). Abort", __FILE__, __LINE__, config->sagan_alert_filepath, strerror(errno));
        }

    sagan_alert_stream_int = fileno( sagan_alert_stream );


    File_Lock( sagan_alert_stream_int );

    fprintf(sagan_alert_stream, "\n[**] [%lu:%" PRIu64 ":%d] %s [**]\n", Event->generatorid, Event->sid, Event->rev, Event->f_msg);
    fprintf(sagan_alert_stream, "[Classification: %s] [Priority: %d] [%s]\n", Event->class, Event->pri, Event->host );
    fprintf(sagan_alert_stream, "[Alert Time: %s]\n", timebuf);
    fprintf(sagan_alert_stream, "%s %s %s:%d [%s] -> %s:%d [%s] %s %s %s\n", Event->date, Event->time, Event->ip_src, Event->src_port, Event->country_src,  Event->ip_dst, Event->dst_port, Event->country_dst, Event->facility, Event->priority, Event->program);
    fprintf(sagan_alert_stream, "Message: %s\n", Event->message);

    if ( Event->found != 0 )
        {

            Reference_Lookup( Event->found, 0, tmpref, sizeof(tmpref) );

            if (strcmp(tmpref, "" ))
                {
                    fprintf(sagan_alert_stream, "%s\n", tmpref);
                }
        }

    File_Unlock( sagan_alert_stream_int );
    fclose(sagan_alert_stream);

}
