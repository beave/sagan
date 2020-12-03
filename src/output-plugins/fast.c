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
#include <errno.h>

#include "sagan.h"
#include "references.h"
#include "sagan-config.h"
#include "util-time.h"

#include "output-plugins/alert.h"

struct _Rule_Struct *rulestruct;
struct _SaganConfig *config;

void Fast_File( _Sagan_Event *Event )
{

    char timebuf[64];
    FILE *sagan_fast_stream;
    int sagan_fast_stream_int = 0;

    CreateTimeString(&Event->event_time, timebuf, sizeof(timebuf), 0);

    if (( sagan_fast_stream = fopen( config->fast_filename, "a" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open %s (%s). Abort", __FILE__, __LINE__, config->sagan_alert_filepath, strerror(errno));
        }

    sagan_fast_stream_int = fileno( sagan_fast_stream );

    File_Lock( sagan_fast_stream_int );

    fprintf( sagan_fast_stream, "%s [**] [%lu:%" PRIu64 ":%d] %s [**] [Classification: %s] [Priority: %d] [Program: %s] ", timebuf,
             Event->generatorid, Event->sid, Event->rev, Event->f_msg, Event->class, Event->pri, Event->program);

    if ( Event->ip_proto == 1 )
        {
            fprintf(sagan_fast_stream, "{ICMP}");
        }

    else if ( Event->ip_proto == 6 )
        {
            fprintf(sagan_fast_stream, "{TCP}");
        }

    else if ( Event->ip_proto == 17 )
        {
            fprintf(sagan_fast_stream, "{UDP}");
        }

    else if ( Event->ip_proto != 1 && Event->ip_proto !=6 && Event->ip_proto != 17 )
        {
            fprintf(sagan_fast_stream, "{UNKNOWN}");
        }

    fprintf(sagan_fast_stream," %s:%d [%s] -> %s:%d [%s]\n", Event->ip_src, Event->src_port, Event->country_src, Event->ip_dst, Event->dst_port, Event->country_dst);

    File_Unlock( sagan_fast_stream_int );

    fclose(sagan_fast_stream);

}
