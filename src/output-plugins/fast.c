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

/* fast.c
 *
 * Provides logging functionality in a 'snort like' fast format.
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
#include "references.h"
#include "sagan-config.h"
#include "util-time.h"

#include "output-plugins/alert.h"

struct _Rule_Struct *rulestruct;
struct _SaganConfig *config;
struct _SaganCounters *counters;

void Fast_File( _Sagan_Event *Event )
{

    char timebuf[64];

    CreateTimeString(&Event->event_time, timebuf, sizeof(timebuf), 0);

    fprintf(config->sagan_fast_stream, "%s [**] [%lu:%s] %s [**] [Classification: %s] [Priority: %d] ", timebuf,
            Event->generatorid, Event->sid, Event->f_msg, Event->class, Event->pri);

    if ( Event->ip_proto == 1 ) {
        fprintf(config->sagan_fast_stream, "{ICMP}");
    }

    else if ( Event->ip_proto == 6 ) {
        fprintf(config->sagan_fast_stream, "{TCP}");
    }

    else if ( Event->ip_proto == 17 ) {
        fprintf(config->sagan_fast_stream, "{UDP}");
    }

    else if ( Event->ip_proto != 1 && Event->ip_proto !=6 && Event->ip_proto != 17 ) {
        fprintf(config->sagan_fast_stream, "{UNKNOWN}");
    }

    fprintf(config->sagan_fast_stream," %s:%d -> %s:%d\n", Event->ip_src, Event->src_port, Event->ip_dst, Event->dst_port);

    fflush(config->sagan_fast_stream);

}
