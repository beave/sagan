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
#include "sagan.h"

unsigned long long sagantotal;
unsigned long long saganfound;
unsigned long long sagandrop;
unsigned long long threshold_total;


char sagan_extern[MAXPATH];

#ifdef HAVE_LIBESMTP
char sagan_esmtp_server[ESMTPSERVER];
#endif

int threadmaxextc;
int threadmaxdbc;
int  dbtype;
int  logzilla_log;
int threadmaxlogzillac;
int threadmaxemailc;

int flag=0;


unsigned long long saganesmtpdrop;
unsigned long long saganexternaldrop;
unsigned long long saganlogzilladrop;
unsigned long long sagansnortdrop;

void sagan_statistics() { 

	if ((isatty(1))) {

		    sagan_log(0, "--------------------------------------------------------------------------");
                    sagan_log(0, "Total number of events processed: %lu", sagantotal);
                    sagan_log(0, "Total number of events thresholded: %lu", threshold_total);
                    sagan_log(0, "Total number of signatures matched: %lu", saganfound);
		    sagan_log(0, "Total events dropped: %d", sagandrop);
		    sagan_log(0, "--------------------------------------------------------------------------");

                    if ( strcmp(sagan_extern, "" )) { 
		       sagan_log(0, "Max external threads: %d | External events dropped: %lu", threadmaxextc, saganexternaldrop);
		       flag=1;
		       }

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
                    
		    if ( dbtype != 0 ) { 
		       sagan_log(0, "Max Snort database threads: %d | Snort DB drops: %lu", threadmaxdbc, sagansnortdrop);
		       flag=1;
		       }

                    if ( logzilla_log != 0 ) { 
		       sagan_log(0, "Max Logzilla threads: %d | Logzilla events dropped: %lu", threadmaxlogzillac, saganlogzilladrop);
		       flag=1;
		       }
#endif

#ifdef HAVE_LIBESMTP
                    if ( strcmp(sagan_esmtp_server, "" )) {
		       sagan_log(0, "Max SMTP threads reached: %d | SMTP events dropped: %lu", threadmaxemailc, saganesmtpdrop);
		       flag=1;
		       }
#endif

if ( flag == 1) sagan_log(0, "--------------------------------------------------------------------------");
	
	}
}
