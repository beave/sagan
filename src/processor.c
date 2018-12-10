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

struct _SaganCounters *counters;
struct _Sagan_Proc_Syslog *SaganProcSyslog;
struct _Sagan_Pass_Syslog *SaganPassSyslog;
struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
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

    struct _SyslogInput *SyslogInput = NULL;

    SyslogInput = malloc(sizeof(_SyslogInput));

    if ( SyslogInput == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SyslogInput. Abort!", __FILE__, __LINE__);
        }

    memset(SyslogInput, 0, sizeof(_SyslogInput));


//    bool ignore_flag = false;

    int i;

    while(death == false)
        {

            pthread_mutex_lock(&SaganProcWorkMutex);

            while ( proc_msgslot == 0 ) pthread_cond_wait(&SaganProcDoWork, &SaganProcWorkMutex);

            if ( config->sagan_reload )
                {
                    pthread_cond_wait(&SaganReloadCond, &SaganReloadMutex);
                }

            proc_msgslot--;	/* This was ++ before coming over, so we now -- it to get to
                                 * original value */


            /* Copy inbound array from global to local */

            for (i=0; i < config->max_batch; i++)
                {
                    printf("batch %d: %s\n", i,  SaganPassSyslog[proc_msgslot].syslog[i]);
                    memcpy(SaganPassSyslog_LOCAL->syslog[i],  SaganPassSyslog[proc_msgslot].syslog[i], sizeof(SaganPassSyslog_LOCAL->syslog[i]));
                }

            pthread_mutex_unlock(&SaganProcWorkMutex);

            __atomic_add_fetch(&proc_running, 1, __ATOMIC_SEQ_CST);

            /* Process local syslog buffer */

            for (i=0; i < config->max_batch; i++)
                {

                    if ( config->input_type == INPUT_PIPE )
                        {
                            SyslogInput_Pipe( SaganPassSyslog_LOCAL->syslog[i], SyslogInput );
                        }
                    else
                        {
                            SyslogInput_JSON( SaganPassSyslog_LOCAL->syslog[i], SyslogInput );
                        }


                    /*
                                        if (debug->debugsyslog)
                                            {
                                                Sagan_Log(DEBUG, "[%s, line %d] **[RAW Syslog]*********************************", __FILE__, __LINE__);
                                                Sagan_Log(DEBUG, "[%s, line %d] Host: %s | Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s | Date: %s | Time: %s", __FILE__, __LINE__, SyslogInput->syslog_host, SyslogInput->syslog_program, SyslogInput->syslog_facility, SyslogInput->syslog_priority, SyslogInput->syslog_level, SyslogInput->syslog_tag, SyslogInput->syslog_date, SyslogInput->syslog_time);
                                                Sagan_Log(DEBUG, "[%s, line %d] Raw message: %s", __FILE__, __LINE__,  SyslogInput->syslog_message);
                                            }
                    */


                    /* Copy data from processors */

                    memcpy(SaganProcSyslog_LOCAL->syslog_host, SyslogInput->syslog_host, sizeof(SaganProcSyslog_LOCAL->syslog_host));
                    memcpy(SaganProcSyslog_LOCAL->syslog_facility, SyslogInput->syslog_facility, sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                    memcpy(SaganProcSyslog_LOCAL->syslog_priority, SyslogInput->syslog_priority, sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                    memcpy(SaganProcSyslog_LOCAL->syslog_level, SyslogInput->syslog_level, sizeof(SaganProcSyslog_LOCAL->syslog_level));
                    memcpy(SaganProcSyslog_LOCAL->syslog_tag, SyslogInput->syslog_tag, sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                    memcpy(SaganProcSyslog_LOCAL->syslog_date, SyslogInput->syslog_date, sizeof(SaganProcSyslog_LOCAL->syslog_date));
                    memcpy(SaganProcSyslog_LOCAL->syslog_time, SyslogInput->syslog_time, sizeof(SaganProcSyslog_LOCAL->syslog_time));
                    memcpy(SaganProcSyslog_LOCAL->syslog_program, SyslogInput->syslog_program, sizeof(SaganProcSyslog_LOCAL->syslog_program));
                    memcpy(SaganProcSyslog_LOCAL->syslog_message, SyslogInput->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message));

                    /* Dynamic goes here */

                    if ( config->dynamic_load_flag == true )
                        {

                            __atomic_add_fetch(&dynamic_line_count, 1, __ATOMIC_SEQ_CST);

                            if ( dynamic_line_count >= config->dynamic_load_sample_rate )
                                {
                                    __atomic_store_n (&dynamic_rule_flag, DYNAMIC_RULE, __ATOMIC_SEQ_CST);
                                    __atomic_store_n (&dynamic_line_count, 0, __ATOMIC_SEQ_CST);

                                }
                        }


                    (void)Sagan_Engine(SaganProcSyslog_LOCAL, dynamic_rule_flag );

                    /* If this is a dynamic run,  reset back to normal */

                    if ( dynamic_rule_flag == DYNAMIC_RULE )
                        {

                            __atomic_store_n (&dynamic_rule_flag, NORMAL_RULE, __ATOMIC_SEQ_CST);

                        }

                    if ( config->sagan_track_clients_flag )
                        {
                            Track_Clients( SyslogInput->syslog_host );
                        }

                }

            __atomic_sub_fetch(&proc_running, 1, __ATOMIC_SEQ_CST);

        } /*  for (;;) */

    /* Exit thread on shutdown. */

    __atomic_sub_fetch(&config->max_processor_threads, 1, __ATOMIC_SEQ_CST);

    pthread_exit(NULL);

}

