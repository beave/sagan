/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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
 * sagan-flowbit.c - Functions used for tracking events over multiple log
 * lines.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-ipc.h"
#include "sagan-flowbit.h"
#include "sagan-rules.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

pthread_mutex_t Flowbit_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t CounterMutex;	/* From sagan-engine.c */

struct _Sagan_IPC_Counters *counters_ipc;
struct _Sagan_IPC_Flowbit *flowbit_ipc;

/*****************************************************************************
 * Sagan_Flowbit_Condition - Used for testing "isset" & "isnotset".  Full
 * rule condition is tested here and returned.
 *****************************************************************************/

int Sagan_Flowbit_Condition(int rule_position, char *ip_src_char, char *ip_dst_char )
{

    time_t t;
    struct tm *now;
    char  timet[20];
    char  tmp[128] = { 0 };
    char *tmp_flowbit_name = NULL;
    char *tok = NULL;

    int i;
    int a;

    uint32_t ip_src;
    uint32_t ip_dst;

    sbool flowbit_match = 0;
    int flowbit_total_match = 0;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    ip_src = IP2Bit(ip_src_char);
    ip_dst = IP2Bit(ip_dst_char);

    int and_or = 0;

    Sagan_Flowbit_Cleanup();

    for (i = 0; i < rulestruct[rule_position].flowbit_count; i++) {

        /*******************
         *      ISSET      *
         *******************/

        if ( rulestruct[rule_position].flowbit_type[i] == 3 ) {

            for (a = 0; a < counters_ipc->flowbit_count; a++) {

                strlcpy(tmp, rulestruct[rule_position].flowbit_name[i], sizeof(tmp));

                if (Sagan_strstr(rulestruct[rule_position].flowbit_name[i], "|")) {
                    tmp_flowbit_name = strtok_r(tmp, "|", &tok);
                    and_or = 1;
                } else {
                    tmp_flowbit_name = strtok_r(tmp, "&", &tok);
                    and_or = 0; 					/* Need this? */
                }

                while (tmp_flowbit_name != NULL ) {

                    if (!strcmp(tmp_flowbit_name, flowbit_ipc[a].flowbit_name) &&
                        flowbit_ipc[a].flowbit_state == 1 ) {

                        /* direction: none */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 0 )

                        {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"isset\" flowbit \"%s\" (direction: \"none\"). (any -> any)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name);
                            }

                            flowbit_total_match++;
                        }

                        /* direction: both */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 1 &&
                             flowbit_ipc[a].ip_src == ip_src &&
                             flowbit_ipc[a].ip_dst == ip_dst )

                        {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"isset\" flowbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_src_char, ip_dst_char);
                            }

                            flowbit_total_match++;
                        }

                        /* direction: by_src */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 2 &&
                             flowbit_ipc[a].ip_src == ip_src )

                        {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"isset\" flowbit \"%s\" (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_src_char);
                            }

                            flowbit_total_match++;
                        }

                        /* direction: by_dst */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 3 &&
                             flowbit_ipc[a].ip_dst == ip_dst )

                        {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"isset\" flowbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_dst_char);
                            }

                            flowbit_total_match++;
                        }

                        /* direction: reverse */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 4 &&
                             flowbit_ipc[a].ip_src == ip_dst &&
                             flowbit_ipc[a].ip_dst == ip_src )

                        {
                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"isset\" flowbit \"%s\" (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_dst_char, ip_src_char);
                            }

                            flowbit_total_match++;
                        }

                    } /* End of strcmp flowbit_name & flowbit_state = 1 */


                    if ( and_or == 1) {
                        tmp_flowbit_name = strtok_r(NULL, "|", &tok);
                    } else {
                        tmp_flowbit_name = strtok_r(NULL, "&", &tok);
                    }

                } /* End of "while tmp_flowbit_name" */

            } /* End of "for a" */

        } /* End "if" flowbit_type == 3 (ISSET) */

        /*******************
        *    ISNOTSET     *
        *******************/

        if ( rulestruct[rule_position].flowbit_type[i] == 4 ) {

            flowbit_match = 0;

            for (a = 0; a < counters_ipc->flowbit_count; a++) {

                strlcpy(tmp, rulestruct[rule_position].flowbit_name[i], sizeof(tmp));

                if (Sagan_strstr(rulestruct[rule_position].flowbit_name[i], "|")) {
                    tmp_flowbit_name = strtok_r(tmp, "|", &tok);
                    and_or = 1;
                } else {
                    tmp_flowbit_name = strtok_r(tmp, "&", &tok);
                    and_or = 0;                                  /* Need this? */
                }

                while (tmp_flowbit_name != NULL ) {

                    if (!strcmp(tmp_flowbit_name, flowbit_ipc[a].flowbit_name)) {


                        flowbit_match=1;


                        if ( flowbit_ipc[a].flowbit_state == 0 ) {

                            /* direction: none */

                            if ( rulestruct[rule_position].flowbit_direction[i] == 0 ) {

                                if ( debug->debugflowbit) {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] \"isnotset\" flowbit \"%s\" (direction: \"none\"). (any -> any)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name);
                                }

                                flowbit_total_match++;
                            }

                            /* direction: both */

                            if ( rulestruct[rule_position].flowbit_direction[i] == 1 ) {


                                if ( flowbit_ipc[a].ip_src == ip_src &&
                                     flowbit_ipc[a].ip_dst == ip_dst ) {

                                    if ( debug->debugflowbit) {
                                        Sagan_Log(S_DEBUG, "[%s, line %d] \"isnotset\" flowbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_src_char, ip_dst_char);
                                    }

                                    flowbit_total_match++;
                                }
                            }

                            /* direction: by_src */

                            if ( rulestruct[rule_position].flowbit_direction[i] == 2 ) {

                                if ( flowbit_ipc[a].ip_src == ip_src ) {

                                    if ( debug->debugflowbit) {
                                        Sagan_Log(S_DEBUG, "[%s, line %d] \"isnotset\" flowbit \"%s\" (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_src_char);
                                    }

                                    flowbit_total_match++;
                                }
                            }

                            /* direction: by_dst */

                            if ( rulestruct[rule_position].flowbit_direction[i] == 3 ) {

                                if ( flowbit_ipc[a].ip_dst == ip_dst ) {

                                    if ( debug->debugflowbit) {
                                        Sagan_Log(S_DEBUG, "[%s, line %d] \"isnotset\" flowbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_dst_char);
                                    }

                                    flowbit_total_match++;
                                }
                            }

                            /* direction: reverse */

                            if ( rulestruct[rule_position].flowbit_direction[i] == 4 ) {

                                if ( flowbit_ipc[a].ip_src == ip_dst &&
                                     flowbit_ipc[a].ip_dst == ip_src ) {

                                    if ( debug->debugflowbit) {
                                        Sagan_Log(S_DEBUG, "[%s, line %d] \"isnotset\" flowbit \"%s\" (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_dst_char, ip_src_char);
                                    }

                                    flowbit_total_match++;
                                }
                            }

                        } /* End flowbit_state == 0 */

                    } /* End of strcmp flowbit_name */

                    if ( and_or == 1) {
                        tmp_flowbit_name = strtok_r(NULL, "|", &tok);
                    } else {
                        tmp_flowbit_name = strtok_r(NULL, "&", &tok);
                    }

                } /* End of "while tmp_flowbit_name" */
            } /* End of "for a" */

            if ( and_or == 1 && flowbit_match == 1 ) {
                flowbit_total_match = rulestruct[rule_position].flowbit_condition_count;	/* Do we even need this for OR? */
            }

            if ( and_or == 0 && flowbit_match == 0 ) {
                flowbit_total_match = rulestruct[rule_position].flowbit_condition_count;
            }

        } /* End of "flowbit_type[i] == 4" */

    } /* End of "for i" */

    /* IF we match all criteria for isset/isnotset
     *
     * If we match the flowbit_conditon_count (number of concurrent flowbits)
     * we trigger.  It it's an "or" statement,  we trigger if any of the
     * flowbits are set.
     *
     */

    if ( ( rulestruct[rule_position].flowbit_condition_count == flowbit_total_match ) || ( and_or == 1 && flowbit_total_match != 0 ) ) {

        if ( debug->debugflowbit) {
            Sagan_Log(S_DEBUG, "[%s, line %d] Condition of flowbit returning TRUE. %d %d", __FILE__, __LINE__, rulestruct[rule_position].flowbit_condition_count, flowbit_total_match);
        }

        return(true);
    }

    /* isset/isnotset failed. */

    if ( debug->debugflowbit) {
        Sagan_Log(S_DEBUG, "[%s, line %d] Condition of flowbit returning FALSE. %d %d", __FILE__, __LINE__, rulestruct[rule_position].flowbit_condition_count, flowbit_total_match);
    }

    return(false);

}  /* End of Sagan_Flowbit_Condition(); */


/*****************************************************************************
 * Sagan_Flowbit_Set - Used to "set" & "unset" flowbit.  All rule "set" and
 * "unset" happen here.
 *****************************************************************************/

void Sagan_Flowbit_Set(int rule_position, char *ip_src_char, char *ip_dst_char )
{

    int i = 0;
    int a = 0;

    time_t t;
    struct tm *now;
    char  timet[20];

    char tmp[128] = { 0 };
    char *tmp_flowbit_name = NULL;
    char *tok = NULL;

    sbool flowbit_match = 0;
    sbool flowbit_unset_match = 0;

    uint32_t ip_src = 0;
    uint32_t ip_dst = 0;

    ip_src = IP2Bit(ip_src_char);
    ip_dst = IP2Bit(ip_dst_char);

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    struct _Sagan_Flowbit_Track *flowbit_track;

    flowbit_track = malloc(sizeof(_Sagan_Flowbit_Track));

    if ( flowbit_track  == NULL ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for flowbit_track. Abort!", __FILE__, __LINE__);
    }

    memset(flowbit_track, 0, sizeof(_Sagan_Flowbit_Track));

    int flowbit_track_count = 0;

    Sagan_Flowbit_Cleanup();


    for (i = 0; i < rulestruct[rule_position].flowbit_count; i++) {

        /*******************
         *      UNSET      *
         *******************/

        if ( rulestruct[rule_position].flowbit_type[i] == 2 ) {

            /* Flowbits & (ie - bit1&bit2) */

            strlcpy(tmp, rulestruct[rule_position].flowbit_name[i], sizeof(tmp));
            tmp_flowbit_name = strtok_r(tmp, "&", &tok);

            while( tmp_flowbit_name != NULL ) {


                for (a = 0; a < counters_ipc->flowbit_count; a++) {

                    if ( !strcmp(tmp_flowbit_name, flowbit_ipc[a].flowbit_name )) {

                        /* direction: none */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 0 ) {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"unset\" flowbit \"%s\" (direction: \"none\"). (any -> any)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name);
                            }


                            Sagan_File_Lock(config->shm_flowbit);
			    pthread_mutex_lock(&Flowbit_Mutex); 

                            flowbit_ipc[a].flowbit_state = 0;

			    pthread_mutex_unlock(&Flowbit_Mutex);
                            Sagan_File_Unlock(config->shm_flowbit);

                            flowbit_unset_match = 1;

                        }


                        /* direction: both */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 1 &&
                             flowbit_ipc[a].ip_src == ip_src &&
                             flowbit_ipc[a].ip_dst == ip_dst ) {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"unset\" flowbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_src_char, ip_dst_char);
                            }

                            Sagan_File_Lock(config->shm_flowbit);
			    pthread_mutex_lock(&Flowbit_Mutex);

                            flowbit_ipc[a].flowbit_state = 0;

			    pthread_mutex_unlock(&Flowbit_Mutex);
                            Sagan_File_Unlock(config->shm_flowbit);

                            flowbit_unset_match = 1;

                        }

                        /* direction: by_src */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 2 &&
                             flowbit_ipc[a].ip_src == ip_src )

                        {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"unset\" flowbit \"%s\" (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_src_char);
                            }

                            Sagan_File_Lock(config->shm_flowbit);
			    pthread_mutex_lock(&Flowbit_Mutex);

                            flowbit_ipc[a].flowbit_state = 0;

			    pthread_mutex_unlock(&Flowbit_Mutex);
                            Sagan_File_Unlock(config->shm_flowbit);

                            flowbit_unset_match = 1;

                        }


                        /* direction: by_dst */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 3 &&
                             flowbit_ipc[a].ip_dst == ip_dst ) {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"unset\" flowbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_dst_char);
                            }

                            Sagan_File_Lock(config->shm_flowbit);
			    pthread_mutex_lock(&Flowbit_Mutex);

                            flowbit_ipc[a].flowbit_state = 0;

			    pthread_mutex_unlock(&Flowbit_Mutex);
                            Sagan_File_Unlock(config->shm_flowbit);

                            flowbit_unset_match = 1;

                        }

                        /* direction: reverse */

                        if ( rulestruct[rule_position].flowbit_direction[i] == 4 &&
                             flowbit_ipc[a].ip_dst == ip_src &&
                             flowbit_ipc[a].ip_src == ip_dst )

                        {

                            if ( debug->debugflowbit) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] \"unset\" flowbit \"%s\" (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, flowbit_ipc[a].flowbit_name, ip_dst_char, ip_src_char);
                            }

                            Sagan_File_Lock(config->shm_flowbit);
			    pthread_mutex_lock(&Flowbit_Mutex);

                            flowbit_ipc[a].flowbit_state = 0;
			
    			    pthread_mutex_unlock(&Flowbit_Mutex);
                            Sagan_File_Unlock(config->shm_flowbit);

                            flowbit_unset_match = 1;

                        }
                    }
                }

                if ( debug->debugflowbit && flowbit_unset_match == 0 ) {
                    Sagan_Log(S_DEBUG, "[%s, line %d] No flowbit found to \"unset\" for %s.", __FILE__, __LINE__, tmp_flowbit_name);
                }

                tmp_flowbit_name = strtok_r(NULL, "&", &tok);
            }
        } /* While & flowbits (ie - bit1&bit2) */

        /*******************
         *      SET        *
        *******************/

        if ( rulestruct[rule_position].flowbit_type[i] == 1 ) {

            flowbit_match = 0;

            /* Flowbits & (ie - bit1&bit2) */

            strlcpy(tmp, rulestruct[rule_position].flowbit_name[i], sizeof(tmp));
            tmp_flowbit_name = strtok_r(tmp, "&", &tok);

            while( tmp_flowbit_name != NULL ) {

                for (a = 0; a < counters_ipc->flowbit_count; a++) {

                    /* Do we have the flowbit already in memory?  If so,  update the information */

                    if (!strcmp(flowbit_ipc[a].flowbit_name, tmp_flowbit_name) &&
                        flowbit_ipc[a].ip_src == ip_src &&
                        flowbit_ipc[a].ip_dst == ip_dst ) {

                        Sagan_File_Lock(config->shm_flowbit);
			pthread_mutex_lock(&Flowbit_Mutex);

                        flowbit_ipc[a].flowbit_date = atol(timet);
                        flowbit_ipc[a].flowbit_expire = atol(timet) + rulestruct[rule_position].flowbit_timeout[i];
                        flowbit_ipc[a].flowbit_state = 1;

                        if ( debug->debugflowbit) {
                            Sagan_Log(S_DEBUG, "[%s, line %d] [%d] Updated via \"set\" for flowbit \"%s\", [%d].  New expire time is %d (%d) [%u -> %u]. ", __FILE__, __LINE__, a, tmp_flowbit_name, i, flowbit_ipc[i].flowbit_expire, rulestruct[rule_position].flowbit_timeout[i], flowbit_ipc[a].ip_src, flowbit_ipc[a].ip_dst);
                        }

			pthread_mutex_unlock(&Flowbit_Mutex);
                        Sagan_File_Unlock(config->shm_flowbit);

                        flowbit_match = 1;
                    }

                }


                /* If the flowbit isn't in memory,  store it to be created later */

                if ( flowbit_match == 0 ) {

                    flowbit_track = ( _Sagan_Flowbit_Track * ) realloc(flowbit_track, (flowbit_track_count+1) * sizeof(_Sagan_Flowbit_Track));

                    if ( flowbit_track == NULL ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for flow_track. Abort!", __FILE__, __LINE__);
                    }

                    strlcpy(flowbit_track[flowbit_track_count].flowbit_name, tmp_flowbit_name, sizeof(flowbit_track[flowbit_track_count].flowbit_name));
                    flowbit_track[flowbit_track_count].flowbit_timeout = rulestruct[rule_position].flowbit_timeout[i];
                    flowbit_track_count++;

                }

                tmp_flowbit_name = strtok_r(NULL, "&", &tok);

            } /* While & flowbits (ie - bit1&bit2) */

        } /* if flowbit_type == 1 */

    } /* Out of for i loop */

    /* Do we have any flowbits in memory that need to be created?  */

    if ( flowbit_track_count != 0 ) {

        for (i = 0; i < flowbit_track_count; i++) {

            if ( Sagan_Clean_IPC_Object(FLOWBIT) == 0 ) {

                Sagan_File_Lock(config->shm_flowbit);
		pthread_mutex_lock(&Flowbit_Mutex);

                flowbit_ipc[counters_ipc->flowbit_count].ip_src = ip_src;
                flowbit_ipc[counters_ipc->flowbit_count].ip_dst = ip_dst;
                flowbit_ipc[counters_ipc->flowbit_count].flowbit_date = atol(timet);
                flowbit_ipc[counters_ipc->flowbit_count].flowbit_expire = atol(timet) + flowbit_track[i].flowbit_timeout;
                flowbit_ipc[counters_ipc->flowbit_count].flowbit_state = 1;
                flowbit_ipc[counters_ipc->flowbit_count].expire = flowbit_track[i].flowbit_timeout;

                strlcpy(flowbit_ipc[counters_ipc->flowbit_count].flowbit_name, flowbit_track[i].flowbit_name, sizeof(flowbit_ipc[counters_ipc->flowbit_count].flowbit_name));

		pthread_mutex_unlock(&Flowbit_Mutex);
                Sagan_File_Unlock(config->shm_flowbit);

                if ( debug->debugflowbit) {
                    Sagan_Log(S_DEBUG, "[%s, line %d] [%d] Created flowbit \"%s\" via \"set\" [%s -> %s],", __FILE__, __LINE__, counters_ipc->flowbit_count, flowbit_ipc[counters_ipc->flowbit_count].flowbit_name, ip_src_char, ip_dst_char);
                }

                Sagan_File_Lock(config->shm_counters);
		pthread_mutex_lock(&CounterMutex);

                counters_ipc->flowbit_count++;

		pthread_mutex_unlock(&CounterMutex);
                Sagan_File_Unlock(config->shm_counters);

            }
        }
    }

    free(flowbit_track);

} /* End of Sagan_Flowbit_Set */


/*****************************************************************************
 * Sagan_Flowbit_Type - Defines the "type" of flowbit tracking based on user
 * input
 *****************************************************************************/

int Sagan_Flowbit_Type ( char *type, int linecount, const char *ruleset )
{

    if (!strcmp(type, "none")) {
        return(0);
    }

    if (!strcmp(type, "both")) {
        return(1);
    }

    if (!strcmp(type, "by_src")) {
        return(2);
    }

    if (!strcmp(type, "by_dst")) {
        return(3);
    }

    if (!strcmp(type, "reverse")) {
        return(4);
    }

    Sagan_Log(S_ERROR, "[%s, line %d] Expected 'none', 'both', by_src', 'by_dst' or 'reverse'.  Got '%s' at line %d.", __FILE__, __LINE__, type, linecount, ruleset);

    return(0); 	/* Should never make it here */

}


/*****************************************************************************
 * Sagan_Flowbit_Cleanup - Find "expired" flowbits and toggle the "state"
 * to "off"
 *****************************************************************************/

void Sagan_Flowbit_Cleanup(void)
{

    int i = 0;

    time_t t;
    struct tm *now;
    char  timet[20];

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);


    for (i=0; i<counters_ipc->flowbit_count; i++) {
        if (  flowbit_ipc[i].flowbit_state == 1 && atol(timet) >= flowbit_ipc[i].flowbit_expire ) {
            if (debug->debugflowbit) {
                Sagan_Log(S_DEBUG, "[%s, line %d] Setting flowbit %s to \"expired\" state.", __FILE__, __LINE__, flowbit_ipc[i].flowbit_name);
            }
            flowbit_ipc[i].flowbit_state = 0;
        }
    }

}
