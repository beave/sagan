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

/*
 * sagan-flowbit.c -
 *
 * Used to track multiple log lines and alert
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-flowbit.h"
#include "sagan-rules.h"

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _Sagan_Flowbit *flowbit;
struct _Sagan_Flowbit_Track *flowbit_track;

pthread_mutex_t SaganFlowbitMutex=PTHREAD_MUTEX_INITIALIZER;

int Sagan_Flowbit(int rule_position, char *ip_src_char, char *ip_dst_char )
{

    time_t t;
    struct tm *now;
    char  timet[20];
    int i;
    int z;
    uint64_t ip_src;
    uint64_t ip_dst;

    sbool flowbit_match = 0;


    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    ip_src = IP2Bit(ip_src_char);
    ip_dst = IP2Bit(ip_dst_char);

    if ( debug->debugflowbit)
        {
            Sagan_Log(S_DEBUG, "[%s, line %d] -- All flowbits and values ---------------", __FILE__, __LINE__);

            for (i=0; i<counters->flowbit_track_count; i++)
                Sagan_Log(S_DEBUG, "[%s, line %d] Flowbit memory position: %d | Flowbit name: %s | Flowbit state: %d", __FILE__, __LINE__,  i, flowbit_track[i].flowbit_name, flowbit_track[i].flowbit_state);
        }


    /* Clean up expired flowbits */

    for (i=0; i<counters->flowbit_track_count; i++)
        {
            if (  flowbit_track[i].flowbit_state == 1 && atol(timet) >= flowbit_track[i].flowbit_expire )
                {
                    if (debug->debugflowbit) Sagan_Log(S_DEBUG, "[%s, line %d] Cleaning up expired flowbit %s", __FILE__, __LINE__, flowbit_track[i].flowbit_name);
                    flowbit_track[i].flowbit_state = 0;
                }
        }

    /* Flowbit "isset" */

    if ( rulestruct[rule_position].flowbit_flag == 3 )
        {
            for (i = 0; i < counters->flowbit_track_count; i++)
                {

                    if (!strcmp(flowbit[rulestruct[rule_position].flowbit_memory_position].flowbit_name, flowbit_track[i].flowbit_name) &&
                            flowbit_track[i].flowbit_state == 1 )
                        {

                            if ( rulestruct[rule_position].flowbit_type == 0 ) return(TRUE);

                            if ( rulestruct[rule_position].flowbit_type == 1 )
                                if ( flowbit_track[i].ip_src == ip_src && flowbit_track[i].ip_dst == ip_dst ) return(TRUE);

                            if ( rulestruct[rule_position].flowbit_type == 2 )
                                if ( flowbit_track[i].ip_src == ip_src ) return(TRUE);

                            if ( rulestruct[rule_position].flowbit_type == 3 )
                                if ( flowbit_track[i].ip_dst == ip_dst ) return(TRUE);

                            if ( debug->debugflowbit ) Sagan_Log(S_DEBUG, "[%s, line %d] Flowbit \"%s\" has been set. TRIGGERING",  __FILE__, __LINE__, flowbit[rulestruct[rule_position].flowbit_memory_position].flowbit_name);
                        }

                } /* End of for i */

            return(FALSE);

        } /* End of flowbit_flag == 3 */

    /* Flowbit "set" */

    if ( rulestruct[rule_position].flowbit_flag == 1 )
        {

            for (i = 0; i < counters->flowbit_track_count; i++)
                {

                    if (!strcmp(flowbit[rulestruct[rule_position].flowbit_memory_position].flowbit_name, flowbit_track[i].flowbit_name) &&
                            flowbit_track[i].ip_src == ip_src &&
                            flowbit_track[i].ip_dst == ip_dst )
                        {

                            pthread_mutex_lock(&SaganFlowbitMutex);
                            flowbit_track[i].flowbit_expire = atol(timet) + rulestruct[rule_position].flowbit_timeout;
                            flowbit_track[i].flowbit_state = 1;
                            pthread_mutex_unlock(&SaganFlowbitMutex);

                            flowbit_match = 1;

                        }

                }

            if ( flowbit_match == 0 )
                {

                    pthread_mutex_lock(&SaganFlowbitMutex);

                    flowbit_track = ( _Sagan_Flowbit_Track * ) realloc(flowbit_track, (counters->flowbit_track_count+1) * sizeof(_Sagan_Flowbit_Track));

                    flowbit_track[counters->flowbit_track_count].flowbit_memory_position = rule_position;
                    flowbit_track[counters->flowbit_track_count].flowbit_name = flowbit[rulestruct[rule_position].flowbit_memory_position].flowbit_name;
                    flowbit_track[counters->flowbit_track_count].ip_src = ip_src;
                    flowbit_track[counters->flowbit_track_count].ip_dst = ip_dst;
                    flowbit_track[counters->flowbit_track_count].flowbit_expire = atol(timet) + rulestruct[rule_position].flowbit_timeout;
                    flowbit_track[counters->flowbit_track_count].flowbit_state = 1;

                    counters->flowbit_track_count++;

                    pthread_mutex_unlock(&SaganFlowbitMutex);
                }

	return(TRUE);

        } /* End if flowbit_flag == 1 */

    /* Flowbit "unset" */

    if ( rulestruct[rule_position].flowbit_flag == 2 )
        {
            for (i = 0; i < counters->flowbit_track_count; i++)
                {

                    if (!strcmp(flowbit[rulestruct[rule_position].flowbit_memory_position].flowbit_name, flowbit_track[i].flowbit_name) && flowbit_track[i].flowbit_state == 1)
                        {

                            if ( rulestruct[rule_position].flowbit_type == 0 )
                                {
                                    pthread_mutex_lock(&SaganFlowbitMutex);
                                    flowbit_track[i].flowbit_state = 0;
                                    pthread_mutex_unlock(&SaganFlowbitMutex);
                                    return(FALSE);
                                }

                            if ( rulestruct[rule_position].flowbit_type == 1 )
                                if ( flowbit_track[i].ip_src == ip_src && flowbit_track[i].ip_dst == ip_dst )
                                    {
                                        pthread_mutex_lock(&SaganFlowbitMutex);
                                        flowbit_track[i].flowbit_state = 0;
                                        pthread_mutex_unlock(&SaganFlowbitMutex);
                                        return(FALSE);
                                    }

                            if ( rulestruct[rule_position].flowbit_type == 2 )
                                if ( flowbit_track[i].ip_src == ip_src )
                                    {
                                        pthread_mutex_lock(&SaganFlowbitMutex);
                                        flowbit_track[i].flowbit_state = 0;
                                        pthread_mutex_unlock(&SaganFlowbitMutex);
                                        return(FALSE);
                                    }

                            if ( rulestruct[rule_position].flowbit_type == 3 )
                                if ( flowbit_track[i].ip_dst == ip_dst )
                                    {
                                        pthread_mutex_lock(&SaganFlowbitMutex);
                                        flowbit_track[i].flowbit_state = 0;
                                        pthread_mutex_unlock(&SaganFlowbitMutex);
                                        return(FALSE);
                                    }


                        } /* End of strcmp */

                } /* End of for i */

            return(FALSE);

        } /* End of flowbit_flag == 2 */


    /* Flowbit "isnotset" */

    if ( rulestruct[rule_position].flowbit_flag == 4  )
        {

            if ( counters->flowbit_track_count == 0 ) return(TRUE);     /* for loop fails if nothing is in the table.  If there is nothing
                                                                                                           in the table,  we obviously didn't match */

            flowbit_match = 0;

            for (i = 0; i < counters->flowbit_track_count; i++)
                {

                    if (!strcmp(flowbit[rulestruct[rule_position].flowbit_memory_position].flowbit_name, flowbit_track[i].flowbit_name) && flowbit_track[i].flowbit_state == 1 )
                        {

                            if ( rulestruct[rule_position].flowbit_type == 0 ) return(FALSE);

                            if ( rulestruct[rule_position].flowbit_type == 1 )
                                if ( flowbit_track[i].ip_src == ip_src && flowbit_track[i].ip_dst == ip_dst ) return(FALSE);

                            if ( rulestruct[rule_position].flowbit_type == 2 )
                                if ( flowbit_track[i].ip_src == ip_src ) return(FALSE);

                            if ( rulestruct[rule_position].flowbit_type == 3 )
                                if ( flowbit_track[i].ip_dst == ip_dst ) return(FALSE);

                        }

                } /* End of for i  */

            return(TRUE);

        } /* Enfo of if flowbit_flag == 4 */

    return(FALSE);

}  /* End of Sagan_Flowbit(); */

/*****************************************************************************
 * Sagan_Flowbit_Type - Defines the "type" of flowbit tracking based on user
 * input
 *****************************************************************************/

int Sagan_Flowbit_Type ( char *type, int linecount, const char *ruleset )
{

    if (!strcmp(type, "none"))
        return(0);

    if (!strcmp(type, "both"))
        return(1);

    if (!strcmp(type, "by_src"))
        return(2);

    if (!strcmp(type, "by_dst"))
        return(3);

    Sagan_Log(S_ERROR, "[%s, line %d] Expected 'none', 'both', by_src' or 'by_dst'.  Got '%s' at line %d.", __FILE__, __LINE__, type, linecount, ruleset);
    return(0); 	/* Should never make it here */

}

