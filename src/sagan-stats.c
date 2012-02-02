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

/* sagan-stats.c 
 *
 * Simply dumps statistics of Sagan to the user or via sagan.log
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

#include "sagan.h"

struct _SaganCounters *counters;

void sagan_statistics( _SaganConfig *config ) { 

char timet[20];

time_t t;
struct tm *now;
unsigned long seconds = 0; 
unsigned long total=0; 

/* This is used to calulate the events per/second */
/* Champ Clark III - 11/17/2011 */

t = time(NULL);
now=localtime(&t);
strftime(timet, sizeof(timet), "%s",  now);
seconds = atol(timet) - atol(config->sagan_startutime);

/* if statement prevents floating point exception */

if ( seconds != 0 ) total = counters->sagantotal / seconds; 

sbool flag=0;

	if ((isatty(1))) {

		    sagan_log(config, 0, "--------------------------------------------------------------------------");
                    sagan_log(config, 0, "Total number of events processed: %" PRIu64 "", counters->sagantotal);
                    sagan_log(config, 0, "Total number of events thresholded: %" PRIu64 " (%.3f%%)", counters->threshold_total, CalcPct( counters->threshold_total, counters->sagantotal) );
                    sagan_log(config, 0, "Total number of signatures matched: %" PRIu64 " (%.3f%%)",  counters->saganfound, CalcPct( counters->saganfound, counters->sagantotal ) );
		    if ( config->output_thread_flag ) sagan_log(config, 0, "Total output plugin dropped: %" PRIu64 " (%.3f%%)", counters->sagan_output_drop, CalcPct(counters->sagan_output_drop, counters->sagantotal) );
		    if (  config->processor_thread_flag ) sagan_log(config, 0, "Total processor plugin dropped: %" PRIu64 " (%.3f%%)", counters->sagan_processor_drop, CalcPct(counters->sagan_processor_drop, counters->sagantotal) );
		    
		    sagan_log(config, 0, "Total dropped: %" PRIu64 " (%.3f%%)", counters->sagan_processor_drop + counters->sagan_output_drop + counters->sagan_log_drop, CalcPct(counters->sagan_processor_drop + counters->sagan_output_drop + counters->sagan_log_drop, counters->sagantotal) );

	
		    if ( seconds < 60 || seconds == 0 ) { 
		    sagan_log(config, 0, "Average Events Per-Second: %lu [%lu of 60 seconds. Calculating...]", total, seconds);
		    } else { 
		    sagan_log(config, 0, "Average Events Per-Second: %lu", total);
		    }

		    
		    sagan_log(config, 0, "--------------------------------------------------------------------------");

	
	}
}
