/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
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
* This becomes a threaded operation.  This handles all CPU intensive output plugins
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

struct _Sagan_Droplist *SaganDroplist;
struct _SaganCounters *counters;

int Sagan_Blacklist ( _SaganProcSyslog * );

struct _Sagan_Proc_Syslog *SaganProcSyslog;
struct _SaganConfig *config;

int proc_msgslot; 
int i; 
int rc; 
sbool ignore_flag=0;

pthread_cond_t SaganProcDoWork;
pthread_mutex_t SaganProcWorkMutex;

void Sagan_Processor ( void ) {

struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL = NULL;
SaganProcSyslog_LOCAL = malloc(sizeof(struct _Sagan_Proc_Syslog));
memset(SaganProcSyslog_LOCAL, 0, sizeof(struct _Sagan_Proc_Syslog));

//#ifdef WITH_WEBSENSE
//curl_global_init(CURL_GLOBAL_ALL);
//#endif

for (;;) { 

	pthread_mutex_lock(&SaganProcWorkMutex);

	while ( proc_msgslot == 0 ) pthread_cond_wait(&SaganProcDoWork, &SaganProcWorkMutex);

	proc_msgslot--;

	/* Do we need to "ignore" this inbound log message? Used to save CPU */

        if ( config->sagan_droplist_flag ) {

        ignore_flag=0;

        for (i = 0; i < counters->droplist_count; i++) {
            if (strstr(SaganProcSyslog_LOCAL->syslog_message, SaganDroplist[i].ignore_string)) {
               counters->ignore_count++;
               ignore_flag=1;
               }
          }
        }

	memset(SaganProcSyslog_LOCAL, 0, sizeof(struct _Sagan_Proc_Syslog));

	snprintf(SaganProcSyslog_LOCAL->syslog_host, sizeof(SaganProcSyslog_LOCAL->syslog_host), "%s", SaganProcSyslog[proc_msgslot].syslog_host);
	snprintf(SaganProcSyslog_LOCAL->syslog_facility, sizeof(SaganProcSyslog_LOCAL->syslog_facility), "%s", SaganProcSyslog[proc_msgslot].syslog_facility);
	snprintf(SaganProcSyslog_LOCAL->syslog_priority, sizeof(SaganProcSyslog_LOCAL->syslog_priority), "%s", SaganProcSyslog[proc_msgslot].syslog_priority);
	snprintf(SaganProcSyslog_LOCAL->syslog_level, sizeof(SaganProcSyslog_LOCAL->syslog_level), "%s", SaganProcSyslog[proc_msgslot].syslog_level);
	snprintf(SaganProcSyslog_LOCAL->syslog_tag, sizeof(SaganProcSyslog_LOCAL->syslog_tag), "%s", SaganProcSyslog[proc_msgslot].syslog_tag);
	snprintf(SaganProcSyslog_LOCAL->syslog_date, sizeof(SaganProcSyslog_LOCAL->syslog_date), "%s", SaganProcSyslog[proc_msgslot].syslog_date);
	snprintf(SaganProcSyslog_LOCAL->syslog_time, sizeof(SaganProcSyslog_LOCAL->syslog_time), "%s", SaganProcSyslog[proc_msgslot].syslog_time);
	snprintf(SaganProcSyslog_LOCAL->syslog_program, sizeof(SaganProcSyslog_LOCAL->syslog_program), "%s", SaganProcSyslog[proc_msgslot].syslog_program);
	snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), "%s", SaganProcSyslog[proc_msgslot].syslog_message);
        
	pthread_mutex_unlock(&SaganProcWorkMutex);

	if ( ignore_flag == 0 ) { 

        Sagan_Engine(SaganProcSyslog_LOCAL);

	/* If i == even then ip src 
	 * If i == odd then ip dst */

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
	}
     }

free(SaganProcSyslog_LOCAL);
}

