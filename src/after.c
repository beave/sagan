/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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

/* after.c - Logic for "after" in Saga rule */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <pthread.h>
#include <time.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "rules.h"
#include "after.h"

pthread_mutex_t After_By_Src_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t After_By_Dst_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t After_By_Src_Port_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t After_By_Dst_Port_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t After_By_Username_Mutex=PTHREAD_MUTEX_INITIALIZER;

struct after_by_src_ipc *afterbysrc_ipc;
struct after_by_dst_ipc *afterbydst_ipc;
struct after_by_srcport_ipc *afterbysrcport_ipc;
struct after_by_dstport_ipc *afterbydstport_ipc;
struct after_by_username_ipc *afterbyusername_ipc;

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct _Sagan_IPC_Counters *counters_ipc;

/*******************/
/* After by source */
/*******************/

sbool After_By_Src ( int rule_position, char *ip_src, uint32_t ip_src_u32 )
{

    sbool after_log_flag = true;
    sbool after_flag = false;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    for (i = 0; i < counters_ipc->after_count_by_src; i++ ) {

        if ( afterbysrc_ipc[rule_position].ipsrc == ip_src_u32  && !strcmp(afterbysrc_ipc[rule_position].sid, rulestruct[rule_position].s_sid )) {

            after_flag = true;

            File_Lock(config->shm_after_by_src);
            pthread_mutex_lock(&After_By_Src_Mutex);

            afterbysrc_ipc[rule_position].count++;
            afterbysrc_ipc[rule_position].total_count++;

            after_oldtime = atol(timet) - afterbysrc_ipc[rule_position].utime;
            if ( after_oldtime > rulestruct[rule_position].after_seconds || afterbysrc_ipc[rule_position].count == 0 ) {
                afterbysrc_ipc[rule_position].count=1;
                afterbysrc_ipc[rule_position].utime = atol(timet);
                after_log_flag = true;
            }

            if ( rulestruct[rule_position].after_count < afterbysrc_ipc[rule_position].count ) {
                after_log_flag = false;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "After SID %s by source IP address. [%s]", afterbysrc_ipc[rule_position].sid, ip_src);
                }

                counters->after_total++;
            }

            pthread_mutex_unlock(&After_By_Src_Mutex);
            File_Unlock(config->shm_after_by_src);

        }
    }


    /* If not found,  add it to the array */

    if ( after_flag == false ) {

        if ( Clean_IPC_Object(AFTER_BY_SRC) == 0 ) {

            File_Lock(config->shm_after_by_src);
            pthread_mutex_lock(&After_By_Src_Mutex);

            afterbysrc_ipc[counters_ipc->after_count_by_src].ipsrc = ip_src_u32;
            strlcpy(afterbysrc_ipc[counters_ipc->after_count_by_src].sid, rulestruct[rule_position].s_sid, sizeof(afterbysrc_ipc[counters_ipc->after_count_by_src].sid));
            afterbysrc_ipc[counters_ipc->after_count_by_src].count = 1;
            afterbysrc_ipc[counters_ipc->after_count_by_src].utime = atol(timet);
            afterbysrc_ipc[counters_ipc->after_count_by_src].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_src++;

            pthread_mutex_unlock(&After_By_Src_Mutex);
            File_Unlock(config->shm_after_by_src);

        }

    }

    return(after_log_flag);
}

/************************/
/* After by Destination */
/************************/

sbool After_By_Dst ( int rule_position, char *ip_dst, uint32_t ip_dst_u32 )
{

    sbool after_log_flag = true;
    sbool after_flag = false;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    for (i = 0; i < counters_ipc->after_count_by_dst; i++ ) {

        if ( afterbydst_ipc[rule_position].ipdst == ip_dst_u32  && !strcmp(afterbydst_ipc[rule_position].sid, rulestruct[rule_position].s_sid )) {

            after_flag = true;

            File_Lock(config->shm_after_by_dst);
            pthread_mutex_lock(&After_By_Dst_Mutex);

            afterbydst_ipc[rule_position].count++;
            afterbydst_ipc[rule_position].total_count++;

            after_oldtime = atol(timet) - afterbydst_ipc[rule_position].utime;
            if ( after_oldtime > rulestruct[rule_position].after_seconds || afterbydst_ipc[rule_position].count == 0 ) {
                afterbydst_ipc[rule_position].count=1;
                afterbydst_ipc[rule_position].utime = atol(timet);
                after_log_flag = true;
            }

            if ( rulestruct[rule_position].after_count < afterbydst_ipc[rule_position].count ) {
                after_log_flag = false;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "After SID %s by destination IP address. [%s]", afterbydst_ipc[rule_position].sid, ip_dst);
                }

                counters->after_total++;
            }

            pthread_mutex_unlock(&After_By_Dst_Mutex);
            File_Unlock(config->shm_after_by_dst);

        }
    }


    /* If not found,  add it to the array */

    if ( after_flag == false ) {

        if ( Clean_IPC_Object(AFTER_BY_DST) == 0 ) {

            File_Lock(config->shm_after_by_dst);
            pthread_mutex_lock(&After_By_Dst_Mutex);

            afterbydst_ipc[counters_ipc->after_count_by_dst].ipdst = ip_dst_u32;
            strlcpy(afterbydst_ipc[counters_ipc->after_count_by_dst].sid, rulestruct[rule_position].s_sid, sizeof(afterbydst_ipc[counters_ipc->after_count_by_dst].sid));
            afterbydst_ipc[counters_ipc->after_count_by_dst].count = 1;
            afterbydst_ipc[counters_ipc->after_count_by_dst].utime = atol(timet);
            afterbydst_ipc[counters_ipc->after_count_by_dst].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_dst++;

            pthread_mutex_unlock(&After_By_Dst_Mutex);
            File_Unlock(config->shm_after_by_dst);

        }

    }

    return(after_log_flag);
}

/*********************/
/* After by username */
/*********************/

sbool After_By_Username( int rule_position, char *normalize_username )
{

    sbool after_log_flag = true;
    sbool after_flag = false;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching username / sid */

    for (i = 0; i < counters_ipc->after_count_by_username; i++ ) {

        if ( !strcmp(afterbyusername_ipc[rule_position].username, normalize_username) &&
             !strcmp(afterbyusername_ipc[rule_position].sid, rulestruct[rule_position].s_sid )) {

            after_flag = true;

            File_Lock(config->shm_after_by_username);
            pthread_mutex_lock(&After_By_Username_Mutex);

            afterbyusername_ipc[rule_position].count++;
            afterbyusername_ipc[rule_position].total_count;

            after_oldtime = atol(timet) - afterbyusername_ipc[rule_position].utime;
            if ( after_oldtime > rulestruct[rule_position].after_seconds || afterbysrc_ipc[rule_position].count == 0 ) {
                afterbyusername_ipc[rule_position].count=1;
                afterbyusername_ipc[rule_position].utime = atol(timet);
                after_log_flag = true;
            }

            if ( rulestruct[rule_position].after_count < afterbyusername_ipc[rule_position].count ) {
                after_log_flag = false;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "After SID %s by_username / by_string. [%s]", afterbyusername_ipc[rule_position].sid, normalize_username);
                }

                counters->after_total++;

            }

            pthread_mutex_unlock(&After_By_Username_Mutex);
            File_Unlock(config->shm_after_by_username);

        }
    }

    /* If not found, add to the username array */

    if ( after_flag == false ) {

        if ( Clean_IPC_Object(AFTER_BY_DST) == 0 ) {

            File_Lock(config->shm_after_by_username);
            pthread_mutex_lock(&After_By_Username_Mutex);

            strlcpy(afterbyusername_ipc[counters_ipc->after_count_by_username].username, normalize_username, sizeof(afterbyusername_ipc[counters_ipc->after_count_by_username].username));
            strlcpy(afterbyusername_ipc[counters_ipc->after_count_by_username].sid, rulestruct[rule_position].s_sid, sizeof(afterbyusername_ipc[counters_ipc->after_count_by_username].sid));
            afterbyusername_ipc[counters_ipc->after_count_by_username].count = 1;
            afterbyusername_ipc[counters_ipc->after_count_by_username].utime = atol(timet);
            afterbyusername_ipc[counters_ipc->after_count_by_username].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_username++;

            pthread_mutex_unlock(&After_By_Username_Mutex);
            File_Unlock(config->shm_after_by_username);
        }
    }

    return(after_log_flag);

} 

/***************************/
/* After by source IP port */
/***************************/

sbool After_By_SrcPort( int rule_position, uint32_t ip_srcport_u32 )
{

    sbool after_log_flag = true;
    sbool after_flag = false;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching src / sid */

    for (i = 0; i < counters_ipc->after_count_by_srcport; i++ ) {

        if ( afterbysrcport_ipc[rule_position].ipsrcport == ip_srcport_u32 && !strcmp(afterbysrcport_ipc[rule_position].sid, rulestruct[rule_position].s_sid )) {
            after_flag = true;

            File_Lock(config->shm_after_by_srcport);
            pthread_mutex_lock(&After_By_Src_Port_Mutex);

            afterbysrcport_ipc[rule_position].count++;
            afterbysrcport_ipc[rule_position].total_count++;

            after_oldtime = atol(timet) - afterbysrcport_ipc[rule_position].utime;
            if ( after_oldtime > rulestruct[rule_position].after_seconds || afterbysrc_ipc[rule_position].count == 0 ) {
                afterbysrcport_ipc[rule_position].count=1;
                afterbysrcport_ipc[rule_position].utime = atol(timet);
                after_log_flag = true;
            }

            if ( rulestruct[rule_position].after_count < afterbysrcport_ipc[rule_position].count ) {
                after_log_flag = false;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "After SID %s by source IP port. [%d]", afterbysrcport_ipc[rule_position].sid, ip_srcport_u32);
                }

                counters->after_total++;
            }

            pthread_mutex_unlock(&After_By_Src_Port_Mutex);
            File_Unlock(config->shm_after_by_srcport);

        }
    }

    /* If not found,  add it to the array */

    if ( after_flag == false ) {

        if ( Clean_IPC_Object(AFTER_BY_SRCPORT) == 0 ) {

            File_Lock(config->shm_after_by_srcport);
            pthread_mutex_lock(&After_By_Src_Port_Mutex);

            afterbysrcport_ipc[counters_ipc->after_count_by_srcport].ipsrcport = ip_srcport_u32;
            strlcpy(afterbysrcport_ipc[counters_ipc->after_count_by_srcport].sid, rulestruct[rule_position].s_sid, sizeof(afterbysrcport_ipc[counters_ipc->after_count_by_srcport].sid));
            afterbysrcport_ipc[counters_ipc->after_count_by_srcport].count = 1;
            afterbysrcport_ipc[counters_ipc->after_count_by_srcport].utime = atol(timet);
            afterbysrcport_ipc[counters_ipc->after_count_by_srcport].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_srcport++;

            pthread_mutex_unlock(&After_By_Src_Port_Mutex);
            File_Unlock(config->shm_after_by_srcport);

        }
    }

    return(after_log_flag);

}

/********************************/
/* After by destination IP port */
/********************************/

sbool After_By_DstPort( int rule_position, uint32_t ip_dstport_u32 )
{

    sbool after_log_flag = true;
    sbool after_flag = false;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching dst / sid */

    for (i = 0; i < counters_ipc->after_count_by_dstport; i++ ) {

        if ( afterbydstport_ipc[rule_position].ipdstport == ip_dstport_u32 && !strcmp(afterbydstport_ipc[rule_position].sid, rulestruct[rule_position].s_sid )) {
            after_flag = true;

            File_Lock(config->shm_after_by_dstport);
            pthread_mutex_lock(&After_By_Dst_Port_Mutex);

            afterbydstport_ipc[rule_position].count++;
            afterbydstport_ipc[rule_position].total_count++;

            after_oldtime = atol(timet) - afterbydstport_ipc[rule_position].utime;
            if ( after_oldtime > rulestruct[rule_position].after_seconds || afterbydst_ipc[rule_position].count == 0 ) {
                afterbydstport_ipc[rule_position].count=1;
                afterbydstport_ipc[rule_position].utime = atol(timet);
                after_log_flag = true;
            }

            if ( rulestruct[rule_position].after_count < afterbydstport_ipc[rule_position].count ) {
                after_log_flag = false;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "After SID %s by destination IP port. [%d]", afterbydstport_ipc[rule_position].sid, ip_dstport_u32);
                }

                counters->after_total++;
            }

            pthread_mutex_unlock(&After_By_Dst_Port_Mutex);
            File_Unlock(config->shm_after_by_dstport);

        }
    }

    /* If not found,  add it to the array */

    if ( after_flag == false ) {

        if ( Clean_IPC_Object(AFTER_BY_SRCPORT) == 0 ) {

            File_Lock(config->shm_after_by_dstport);
            pthread_mutex_lock(&After_By_Dst_Port_Mutex);

            afterbydstport_ipc[counters_ipc->after_count_by_dstport].ipdstport = ip_dstport_u32;
            strlcpy(afterbydstport_ipc[counters_ipc->after_count_by_dstport].sid, rulestruct[rule_position].s_sid, sizeof(afterbydstport_ipc[counters_ipc->after_count_by_dstport].sid));
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].count = 1;
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].utime = atol(timet);
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_dstport++;

            pthread_mutex_unlock(&After_By_Dst_Port_Mutex);
            File_Unlock(config->shm_after_by_dstport);

        }
    }

    return(after_log_flag);

}

