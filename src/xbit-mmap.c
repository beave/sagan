/* $Id$ */
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

/* xbit-mmap.c - memory mapped xbit support a la 'Suricata' style */

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
#include "ipc.h"
#include "xbit.h"
#include "xbit-mmap.h"
#include "rules.h"
#include "sagan-config.h"
#include "util-time.h"


struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct _Sagan_IPC_Counters *counters_ipc;
struct _Sagan_IPC_Xbit *Xbit_IPC;

pthread_mutex_t Xbit_Mutex=PTHREAD_MUTEX_INITIALIZER;

/*************************************************/
/* Xbit_Set_MMAP - Used to "set", "unset" a xbit */
/*************************************************/

void Xbit_Set_MMAP(int rule_position, char *ip_src_char, char *ip_dst_char, char *syslog_message )
{

    int r = 0;
    int x = 0;

    bool xbit_match = false;
    uint32_t hash;

    if ( Clean_IPC_Object(XBIT) == 0 )
        {

            for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
                {

                    if ( rulestruct[rule_position].xbit_type[r] == XBIT_SET )
                        {

                            hash = Xbit_Return_Tracking_Hash( rule_position, r, ip_src_char, ip_dst_char );

                            xbit_match = false;

                            for ( x = 0; x < counters_ipc->xbit_count; x++ )
                                {

                                    if ( hash == Xbit_IPC[x].xbit_hash && rulestruct[rule_position].xbit_name_hash[r] == Xbit_IPC[x].xbit_name_hash )
                                        {

                                            if ( debug->debugxbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Got an xbit match at %d.  Updating xbit '%s' [hash: %u]", __FILE__, __LINE__, x, Xbit_IPC[x].xbit_name, Xbit_IPC[x].xbit_hash);
                                                }

                                            xbit_match = true;

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Xbit_Mutex);

                                            strlcpy(Xbit_IPC[x].syslog_message, syslog_message, sizeof(Xbit_IPC[x].syslog_message));
                                            strlcpy(Xbit_IPC[x].signature_msg, rulestruct[rule_position].s_msg, sizeof(Xbit_IPC[x].signature_msg));
                                            Xbit_IPC[x].xbit_expire = Return_Epoch() + rulestruct[rule_position].xbit_expire[r];
                                            Xbit_IPC[x].expire = rulestruct[rule_position].xbit_expire[r];
                                            Xbit_IPC[x].sid = rulestruct[rule_position].s_sid;
                                            Xbit_IPC[x].xbit_hash = hash;
                                            Xbit_IPC[x].xbit_name_hash = rulestruct[rule_position].xbit_name_hash[r];
                                            File_Unlock(config->shm_xbit);
                                            pthread_mutex_unlock(&Xbit_Mutex);

                                        }

                                }


                            /* No xbit to update, add one */

                            if ( xbit_match == false )
                                {

                                    File_Lock(config->shm_xbit);
                                    pthread_mutex_lock(&Xbit_Mutex);

                                    strlcpy(Xbit_IPC[counters_ipc->xbit_count].xbit_name, rulestruct[rule_position].xbit_name[r], sizeof(Xbit_IPC[counters_ipc->xbit_count].xbit_name));
                                    strlcpy(Xbit_IPC[counters_ipc->xbit_count].syslog_message, syslog_message, sizeof(Xbit_IPC[counters_ipc->xbit_count].syslog_message));
                                    strlcpy(Xbit_IPC[counters_ipc->xbit_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(Xbit_IPC[counters_ipc->xbit_count].signature_msg));

                                    Xbit_IPC[counters_ipc->xbit_count].xbit_expire = Return_Epoch() + rulestruct[rule_position].xbit_expire[r];
                                    Xbit_IPC[x].expire = rulestruct[rule_position].xbit_expire[r];
                                    Xbit_IPC[counters_ipc->xbit_count].sid = rulestruct[rule_position].s_sid;
                                    Xbit_IPC[counters_ipc->xbit_count].xbit_hash = hash;
                                    Xbit_IPC[counters_ipc->xbit_count].xbit_name_hash = rulestruct[rule_position].xbit_name_hash[r];

                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] Adding xbit '%s' at %d [hash: %u]", __FILE__, __LINE__, Xbit_IPC[x].xbit_name, x, Xbit_IPC[x].xbit_hash);
                                        }

                                    counters_ipc->xbit_count++;

                                    pthread_mutex_unlock(&Xbit_Mutex);
                                    File_Unlock(config->shm_xbit);

                                }

                        }

                    /* UNSET */

                    else if ( rulestruct[rule_position].xbit_type[r] == XBIT_UNSET )
                        {

                            hash = Xbit_Return_Tracking_Hash( rule_position, r, ip_src_char, ip_dst_char );

                            xbit_match = false;

                            for ( x = 0; x < counters_ipc->xbit_count; x++ )
                                {

                                    if ( hash == Xbit_IPC[x].xbit_hash && rulestruct[rule_position].xbit_name_hash[r] == Xbit_IPC[x].xbit_name_hash )
                                        {

                                            if ( debug->debugxbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Unsetting xbit '%s' at %d [hash: %u]", __FILE__, __LINE__, Xbit_IPC[x].xbit_name, x, Xbit_IPC[x].xbit_hash);
                                                }

                                            Xbit_IPC[x].xbit_expire = 0;

                                        }

                                }

                        }

                } /* for (r = 0; r < rulestruct[rule_position].xbit_count; r++) */
        }
}

/**********************************************************/
/* Xbit_Condition_MMAP - Handles logic for isset/isnotset */
/**********************************************************/

bool Xbit_Condition_MMAP(int rule_position, char *ip_src_char, char *ip_dst_char)
{

    int r = 0;
    int x = 0;
    int xbit_isset = 0;
    int xbit_isnotset = 0;

    bool xbit_match = false;

    uint32_t hash;

    for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
        {

            if ( rulestruct[rule_position].xbit_type[r] == XBIT_ISSET )
                {

                    hash = Xbit_Return_Tracking_Hash( rule_position, r, ip_src_char, ip_dst_char );

                    for ( x = 0; x < counters_ipc->xbit_count; x++ )
                        {

                            if ( hash == Xbit_IPC[x].xbit_hash &&
                                    rulestruct[rule_position].xbit_name_hash[r] == Xbit_IPC[x].xbit_name_hash &&
                                    Xbit_IPC[x].xbit_expire != 0 )
                                {

                                    if ( Return_Epoch() < Xbit_IPC[x].xbit_expire )
                                        {

                                            if ( debug->debugxbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' found for 'isset' at %d [hash: %u]", __FILE__, __LINE__, Xbit_IPC[x].xbit_name, x, Xbit_IPC[x].xbit_hash);
                                                }

                                            xbit_isset++;
                                            break;

                                        }
                                }
                        }
                }

            else if ( rulestruct[rule_position].xbit_type[r] == XBIT_ISNOTSET )
                {

                    hash = Xbit_Return_Tracking_Hash( rule_position, r, ip_src_char, ip_dst_char );

                    for ( x = 0; x < counters_ipc->xbit_count; x++ )
                        {

                            if ( hash == Xbit_IPC[x].xbit_hash &&
                                    rulestruct[rule_position].xbit_name_hash[r] == Xbit_IPC[x].xbit_name_hash &&
                                    Xbit_IPC[x].xbit_expire != 0 )
                                {
                                    if ( Return_Epoch() < Xbit_IPC[x].xbit_expire )
                                        {

                                            xbit_match = true;
                                            break;
                                        }
                                }
                        }

                    if ( xbit_match == false )
                        {

                            if ( debug->debugxbit )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' not found for 'isnotset'", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r]);
                                }

                            xbit_isnotset++;
                        }
                }
        }


    /* check counts for set/unset! return if == */

    if ( rulestruct[rule_position].xbit_isset_count == xbit_isset &&
            rulestruct[rule_position].xbit_isnotset_count == xbit_isnotset )
        {

            if ( debug->debugxbit )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Xbit_Condition is returning true.", __FILE__, __LINE__);
                }

            return(true);
        }

    if ( debug->debugxbit )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Xbit_Condition is returning false.", __FILE__, __LINE__);
        }

    return(false);

}

