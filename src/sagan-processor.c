/*
** Copyright (C) 2009-2014 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2014 Champ Clark III <cclark@quadrantsec.com>
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
 
/* sagan-processor.c 
* 
* This becomes a threaded operation.  This handles all CPU intensive processes.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "sagan.h"

#include "processors/sagan-engine.h"
#include "processors/sagan-search.h"
#include "processors/sagan-track-clients.h"
#include "processors/sagan-blacklist.h"

#ifdef WITH_WEBSENSE
#include "processors/sagan-websense.h"
#endif

struct _Sagan_Droplist *SaganDroplist;
struct _SaganCounters *counters;
struct _Sagan_Proc_Syslog *SaganProcSyslog;
struct _SaganConfig *config;

int proc_msgslot; 		/* Comes from sagan.c */

pthread_cond_t SaganProcDoWork;
pthread_mutex_t SaganProcWorkMutex;
pthread_mutex_t SaganIgnoreCounter=PTHREAD_MUTEX_INITIALIZER;

void Sagan_Processor ( void ) {

struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL = NULL;
SaganProcSyslog_LOCAL = malloc(sizeof(struct _Sagan_Proc_Syslog));
memset(SaganProcSyslog_LOCAL, 0, sizeof(struct _Sagan_Proc_Syslog));

sbool ignore_flag=0;

int i;
int rc;

for (;;) { 

	pthread_mutex_lock(&SaganProcWorkMutex);

	while ( proc_msgslot == 0 ) pthread_cond_wait(&SaganProcDoWork, &SaganProcWorkMutex);

	proc_msgslot--;		/* This was ++ before coming over, so we now -- it to get to
				 * original value */

	strlcpy(SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog[proc_msgslot].syslog_host, sizeof(SaganProcSyslog_LOCAL->syslog_host)); 
	strlcpy(SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog[proc_msgslot].syslog_facility, sizeof(SaganProcSyslog_LOCAL->syslog_facility)); 
	strlcpy(SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog[proc_msgslot].syslog_priority, sizeof(SaganProcSyslog_LOCAL->syslog_priority)); 
	strlcpy(SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog[proc_msgslot].syslog_level, sizeof(SaganProcSyslog_LOCAL->syslog_level)); 
	strlcpy(SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog[proc_msgslot].syslog_tag, sizeof(SaganProcSyslog_LOCAL->syslog_tag)); 
	strlcpy(SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog[proc_msgslot].syslog_date, sizeof(SaganProcSyslog_LOCAL->syslog_date)); 
	strlcpy(SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog[proc_msgslot].syslog_time, sizeof(SaganProcSyslog_LOCAL->syslog_time)); 
	strlcpy(SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog[proc_msgslot].syslog_program, sizeof(SaganProcSyslog_LOCAL->syslog_program)); 
	strlcpy(SaganProcSyslog_LOCAL->syslog_message, SaganProcSyslog[proc_msgslot].syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message)); 

	pthread_mutex_unlock(&SaganProcWorkMutex);

	/* Check for general "drop" items.  We do this first so we can save CPU later */

        if ( config->sagan_droplist_flag ) {

	        ignore_flag=0;

			for (i = 0; i < counters->droplist_count; i++) {

				if (strstr(SaganProcSyslog[proc_msgslot].syslog_message, SaganDroplist[i].ignore_string)) {
	       
					pthread_mutex_lock(&SaganIgnoreCounter);
					counters->ignore_count++;
					pthread_mutex_unlock(&SaganIgnoreCounter);
               
					ignore_flag=1;
					break;
               			}
			}
	}

	/* If we're in a ignore state,  then we can bypass the processors */

	if ( ignore_flag == 0 ) { 

		Sagan_Engine(SaganProcSyslog_LOCAL);

#ifdef WITH_WEBSENSE

		if ( config->websense_flag ) { 

			for (i=1; i < config->websense_parse_depth+1; i++) {

				rc = Sagan_Websense(SaganProcSyslog_LOCAL, i);
				if ( rc == 0 ) break; 		/* Exit for() if nothing is found.  No reason 
			                                           search config->websense_parse_depth. */
				}
		}

#endif

		if ( config->blacklist_flag ) Sagan_Blacklist(SaganProcSyslog_LOCAL);
		if ( config->search_nocase_flag ) Sagan_Search(SaganProcSyslog_LOCAL, 1);
		if ( config->search_case_flag ) Sagan_Search(SaganProcSyslog_LOCAL, 2); 
		if ( config->sagan_track_clients_flag) sagan_track_clients(SaganProcSyslog_LOCAL);

		} // End if if (ignore_Flag)
  } //  for (;;)

Sagan_Log(S_WARN, "[%s, line %d] Holy cow! You should never see this message!", __FILE__, __LINE__);
free(SaganProcSyslog_LOCAL);		/* Should never make it here */
}

