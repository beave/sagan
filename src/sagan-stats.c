/*
** Copyright (C) 2009-2011 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2011 Champ Clark III <cclark@quadrantsec.com>
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

#include "sagan.h"

struct _SaganCounters *counters;

void sagan_statistics( _SaganConfig *config ) { 

sbool flag=0;

	if ((isatty(1))) {

		    sagan_log(config, 0, "--------------------------------------------------------------------------");
                    sagan_log(config, 0, "Total number of events processed: %" PRIu64 "", counters->sagantotal);
                    sagan_log(config, 0, "Total number of events thresholded: %" PRIu64 " (%.3f%%)", counters->threshold_total, CalcPct( counters->threshold_total, counters->sagantotal) );
                    sagan_log(config, 0, "Total number of signatures matched: %" PRIu64 " (%.3f%%)",  counters->saganfound, CalcPct( counters->saganfound, counters->sagantotal ) );
		    sagan_log(config, 0, "Total events dropped: %" PRIu64 " (%.3f%%)", counters->sagandrop, CalcPct(counters->sagandrop, counters->sagantotal) );
		    sagan_log(config, 0, "--------------------------------------------------------------------------");

                    if ( config->sagan_ext_flag ) { 
		       sagan_log(config, 0, "Max external threads: %" PRIu64 " of %" PRIu64 " (%.3f%%) | External events dropped: %" PRIu64 "", counters->threadmaxextc,  config->max_external_threads, CalcPct( counters->threadmaxextc, config->max_external_threads), counters->saganexternaldrop);
		       flag=1;
		       }

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
                    
		    if ( config->dbtype ) { 
		       sagan_log(config, 0, "Max Snort database threads: %" PRIu64 " of %" PRIu64 " (%.3f%%) | Snort DB drops: %" PRIu64 "", counters->threadmaxdbc, config->maxdb_threads, CalcPct( counters->threadmaxdbc, config->maxdb_threads), counters->sagansnortdrop);
		       flag=1;
		       }

                    if ( config->logzilla_dbtype ) { 
		       sagan_log(config, 0, "Max Logzilla threads: %" PRIu64 " of %" PRIu64 " (%.3f%%) | Logzilla events dropped: %" PRIu64 "", counters->threadmaxlogzillac, config->max_logzilla_threads, CalcPct( counters->threadmaxlogzillac, config->max_logzilla_threads), counters->saganlogzilladrop);
		       flag=1;
		       }
#endif

#ifdef HAVE_LIBESMTP
		    if ( config->sagan_esmtp_flag ) {
		       sagan_log(config, 0, "Max SMTP threads reached: %" PRIu64 " of %" PRIu64 " (%.3f%%) | SMTP events dropped: %" PRIu64 "", counters->threadmaxemailc, config->max_email_threads, CalcPct( counters->threadmaxemailc, config->max_email_threads), counters->saganesmtpdrop);
		       flag=1;
		       }
#endif

#ifdef HAVE_LIBPRELUDE
		   if ( config->sagan_prelude_flag ) { 
		      sagan_log(config, 0, "Max Prelude threads reached: %" PRIu64 " of %" PRIu64 " (%.3f%%) | Prelude events dropped: %" PRIu64 "", counters->threadmaxpreludec, config->max_prelude_threads, CalcPct( counters->threadmaxpreludec, config->max_prelude_threads), counters->saganpreludedrop);
		      flag=1;
		      }
#endif

if ( flag == 1) sagan_log(config, 0, "--------------------------------------------------------------------------");
	
	}
}
