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
#include <atomic.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "sagan.h"
#include "sagan-defs.h"
#include "ignore-list.h"
#include "sagan-config.h"
#include "input-pipe.h"
#include "parsers/parsers.h"

#ifdef HAVE_LIBFASTJSON
#include "input-json.h"
#include "message-json-map.h"
#endif

#include "processors/engine.h"
#include "processors/track-clients.h"
#include "processors/blacklist.h"
#include "processors/dynamic-rules.h"
#include "processors/client-stats.h"

struct _SaganCounters *counters;
struct _Sagan_Proc_Syslog *SaganProcSyslog;
struct _Sagan_Pass_Syslog *SaganPassSyslog;
struct _SaganConfig *config;
struct _SaganDebug *debug;


int proc_msgslot; 		/* Comes from sagan.c */
int proc_running;   	        /* Comes from sagan.c */

bool dynamic_rule_flag = NORMAL_RULE;
uint32_t dynamic_line_count = 0;


bool death=false;

pthread_cond_t SaganProcDoWork;
pthread_mutex_t SaganProcWorkMutex;

pthread_cond_t SaganReloadCond;
pthread_mutex_t SaganReloadMutex;

pthread_mutex_t SaganDynamicFlag;

void Processor ( void )
{

    (void)SetThreadName("SaganProcessor");

    struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL = NULL;
    SaganProcSyslog_LOCAL = malloc(sizeof(struct _Sagan_Proc_Syslog));

    if ( SaganProcSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog_LOCAL, 0, sizeof(struct _Sagan_Proc_Syslog));


    struct _Sagan_Pass_Syslog *SaganPassSyslog_LOCAL = NULL;
    SaganPassSyslog_LOCAL = malloc(sizeof(struct _Sagan_Pass_Syslog));

    if ( SaganPassSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganPassSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    memset(SaganPassSyslog_LOCAL, 0, sizeof(struct _Sagan_Pass_Syslog));

    int i;

    while(death == false)
        {

            pthread_mutex_lock(&SaganProcWorkMutex);

            while ( proc_msgslot == 0 ) pthread_cond_wait(&SaganProcDoWork, &SaganProcWorkMutex);

            if ( config->sagan_reload )
                {
                    pthread_cond_wait(&SaganReloadCond, &SaganReloadMutex);
                }

            proc_msgslot--;     /* This was ++ before coming over, so we now -- it to get to
                                 * original value */


            /* Copy inbound array from global to local */

            for (i=0; i < config->max_batch; i++)
                {


                    if (debug->debugsyslog)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] [batch position %d] Raw log: %s",  __FILE__, __LINE__, i, SaganPassSyslog[proc_msgslot].syslog[i]);
                        }

                    strlcpy(SaganPassSyslog_LOCAL->syslog[i],  SaganPassSyslog[proc_msgslot].syslog[i], sizeof(SaganPassSyslog_LOCAL->syslog[i]));
                }


            pthread_mutex_unlock(&SaganProcWorkMutex);

            __atomic_add_fetch(&proc_running, 1, __ATOMIC_SEQ_CST);

            /* Process local syslog buffer */

            for (i=0; i < config->max_batch; i++)
                {

//		    memset(SaganProcSyslog_LOCAL, 0, sizeof(struct _Sagan_Proc_Syslog));

                    if ( config->input_type == INPUT_PIPE )
                        {
                            SyslogInput_Pipe( SaganPassSyslog_LOCAL->syslog[i], SaganProcSyslog_LOCAL );
                        }
                    else
                        {
                            SyslogInput_JSON( SaganPassSyslog_LOCAL->syslog[i], SaganProcSyslog_LOCAL );
                        }

                    if (debug->debugsyslog)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] **[Parsed Syslog]*********************************", __FILE__, __LINE__);
                            Sagan_Log(DEBUG, "[%s, line %d] Host: %s | Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s | Date: %s | Time: %s | Event ID: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->syslog_date, SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog_LOCAL->event_id);
                            Sagan_Log(DEBUG, "[%s, line %d] Parsed message: %s", __FILE__, __LINE__,  SaganProcSyslog_LOCAL->syslog_message);
                        }

                    /* Dynamic goes here */

                    if ( config->dynamic_load_flag == true )
                        {

                            __atomic_add_fetch(&dynamic_line_count, 1, __ATOMIC_SEQ_CST);

                            if ( dynamic_line_count >= config->dynamic_load_sample_rate )
                                {
                                    dynamic_rule_flag = DYNAMIC_RULE;

                                    __atomic_store_n (&dynamic_line_count, 0, __ATOMIC_SEQ_CST);

                                }
                        }

                    (void)Sagan_Engine(SaganProcSyslog_LOCAL, dynamic_rule_flag );

                    /* If this is a dynamic run,  reset back to normal */

                    if ( dynamic_rule_flag == DYNAMIC_RULE )
                        {
                            dynamic_rule_flag = NORMAL_RULE;
                        }


                    if ( config->client_stats_flag )
                        {

                            Client_Stats_Add_Update_IP ( SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_message );

                        }


                    if ( config->sagan_track_clients_flag )
                        {
                            Track_Clients( SaganProcSyslog_LOCAL->syslog_host );
                        }

                }

            __atomic_sub_fetch(&proc_running, 1, __ATOMIC_SEQ_CST);

        } /*  for (;;) */

    /* Exit thread on shutdown. */

    __atomic_sub_fetch(&config->max_processor_threads, 1, __ATOMIC_SEQ_CST);

    /* Cleans up valgrind */

//    free(SaganPassSyslog_LOCAL);
//    free(SaganProcSyslog_LOCAL);

    pthread_exit(NULL);

}

