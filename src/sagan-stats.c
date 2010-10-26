/*
** Copyright (C) 2009-2010 Softwink, Inc. 
** Copyright (C) 2009-2010 Champ Clark III <champ@softwink.com>
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

uint64_t sagantotal;
uint64_t saganfound;
uint64_t sagandrop;
uint64_t threshold_total;


char sagan_extern[MAXPATH];

#ifdef HAVE_LIBESMTP
char sagan_esmtp_server[ESMTPSERVER];
#endif

uint64_t threadmaxextc;
uint64_t threadmaxdbc;
int  dbtype;
int  logzilla_log;
uint64_t threadmaxlogzillac;
uint64_t threadmaxemailc;

uint64_t max_ext_threads;
uint64_t max_email_threads;
uint64_t max_logzilla_threads;
uint64_t maxdb_threads;

int flag=0;

uint64_t saganesmtpdrop;
uint64_t saganexternaldrop;
uint64_t saganlogzilladrop;
uint64_t sagansnortdrop;

void sagan_statistics() { 

	if ((isatty(1))) {

		    sagan_log(0, "--------------------------------------------------------------------------");
                    sagan_log(0, "Total number of events processed: %" PRIu64 "", sagantotal);
                    sagan_log(0, "Total number of events thresholded: %" PRIu64 " (%.3f%%)", threshold_total, CalcPct( threshold_total, sagantotal) );
                    sagan_log(0, "Total number of signatures matched: %" PRIu64 " (%.3f%%)",  saganfound, CalcPct( saganfound, sagantotal ) );
		    sagan_log(0, "Total events dropped: %" PRIu64 " (%.3f%%)", sagandrop, CalcPct(sagandrop, sagantotal) );
		    sagan_log(0, "--------------------------------------------------------------------------");

                    if ( strcmp(sagan_extern, "" )) { 
		       sagan_log(0, "Max external threads: %" PRIu64 " of %" PRIu64 " (%.3f%%) | External events dropped: %" PRIu64 "", threadmaxextc,  max_ext_threads, CalcPct( threadmaxextc, max_ext_threads), saganexternaldrop);
		       flag=1;
		       }

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
                    
		    if ( dbtype != 0 ) { 
		       sagan_log(0, "Max Snort database threads: %" PRIu64 " of %" PRIu64 " (%.3f%%) | Snort DB drops: %" PRIu64 "", threadmaxdbc, maxdb_threads, CalcPct( threadmaxdbc, maxdb_threads), sagansnortdrop);
		       flag=1;
		       }

                    if ( logzilla_log != 0 ) { 
		       sagan_log(0, "Max Logzilla threads: %" PRIu64 " of %" PRIu64 " (%.3f%%) | Logzilla events dropped: %" PRIu64 "", threadmaxlogzillac, max_logzilla_threads, CalcPct( threadmaxlogzillac, max_logzilla_threads), saganlogzilladrop);
		       flag=1;
		       }
#endif

#ifdef HAVE_LIBESMTP
                    if ( strcmp(sagan_esmtp_server, "" )) {
		       sagan_log(0, "Max SMTP threads reached: %" PRIu64 " of %" PRIu64 " (%.3f%%) | SMTP events dropped: %" PRIu64 "", threadmaxemailc, max_email_threads, CalcPct( threadmaxemailc, max_email_threads), saganesmtpdrop);
		       flag=1;
		       }
#endif

if ( flag == 1) sagan_log(0, "--------------------------------------------------------------------------");
	
	}
}
