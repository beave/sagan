/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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

/* processor.c
*
* This becomes a threaded operation.  This handles all CPU intensive processes.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "sagan.h"
#include "sagan-defs.h"
#include "ignore-list.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

#include "processors/engine.h"
#include "processors/track-clients.h"
#include "processors/blacklist.h"
#include "processors/dynamic-rules.h"

struct _Sagan_Ignorelist *SaganIgnorelist;
struct _SaganCounters *counters;
struct _Sagan_Proc_Syslog *SaganProcSyslog;
struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;

int proc_msgslot; 		/* Comes from sagan.c */
int proc_running;   	        /* Comes from sagan.c */
unsigned char dynamic_rule_flag; /* Comes from sagan.c */

sbool death=false;

pthread_cond_t SaganProcDoWork;
pthread_mutex_t SaganProcWorkMutex;

pthread_cond_t SaganReloadCond;
pthread_mutex_t SaganReloadMutex;

pthread_mutex_t SaganDynamicFlag;

pthread_mutex_t SaganIgnoreCounter=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganClientTracker=PTHREAD_MUTEX_INITIALIZER;


void Processor ( void )
{

    (void)SetThreadName("SaganWorker");

    struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL = NULL;
    SaganProcSyslog_LOCAL = malloc(sizeof(struct _Sagan_Proc_Syslog));

    if ( SaganProcSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL, 0, sizeof(struct _Sagan_Proc_Syslog));

    sbool ignore_flag = false;

    int i;

//    for (;;)
    while(death == false)
        {

            pthread_mutex_lock(&SaganProcWorkMutex);

            while ( proc_msgslot == 0 ) pthread_cond_wait(&SaganProcDoWork, &SaganProcWorkMutex);

            if ( config->sagan_reload )
                {
                    pthread_cond_wait(&SaganReloadCond, &SaganReloadMutex);
                }

            proc_running++;
            proc_msgslot--;	/* This was ++ before coming over, so we now -- it to get to
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

            if ( config->sagan_droplist_flag )
                {

                    ignore_flag = false;

                    for (i = 0; i < counters->droplist_count; i++)
                        {

                            if (Sagan_strstr(SaganProcSyslog_LOCAL->syslog_message, SaganIgnorelist[i].ignore_string))
                                {

                                    pthread_mutex_lock(&SaganIgnoreCounter);
                                    counters->ignore_count++;
                                    pthread_mutex_unlock(&SaganIgnoreCounter);

                                    ignore_flag = true;
                                    goto outside_loop;	/* Stop processing from ignore list */
                                }
                        }
                }

outside_loop:

            /* If we're in a ignore state,  then we can bypass the processors */

            if ( ignore_flag == false )
                {

                    (void)Sagan_Engine(SaganProcSyslog_LOCAL, dynamic_rule_flag );

                    /* If this is a dynamic run,  reset back to normal */

                    if ( dynamic_rule_flag == DYNAMIC_RULE )
                        {

                            pthread_mutex_lock(&SaganDynamicFlag);
                            dynamic_rule_flag = 0;
                            pthread_mutex_unlock(&SaganDynamicFlag);

                        }

                    if ( config->sagan_track_clients_flag )
                        {
                            Track_Clients( SaganProcSyslog_LOCAL->syslog_host );
                        }

                } // End if if (ignore_Flag)


            pthread_mutex_lock(&SaganProcWorkMutex);
            proc_running--;
            pthread_mutex_unlock(&SaganProcWorkMutex);
        } //  for (;;)

    printf("DEATH: %d\n", proc_running);
    config->max_processor_threads--;
    pthread_exit(NULL);

//    Sagan_Log(WARN, "[%s, line %d] Holy cow! You should never see this message!", __FILE__, __LINE__);
//    free(SaganProcSyslog_LOCAL);		/* Should never make it here */
}

