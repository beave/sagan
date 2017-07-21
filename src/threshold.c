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

/* threshold.c - Logic for "threshold" in rules */

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
#include "threshold.h"

pthread_mutex_t Thresh_By_Src_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Thresh_By_Dst_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Thresh_By_Src_Port_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Thresh_By_Dst_Port_Mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t Thresh_By_Username_Mutex=PTHREAD_MUTEX_INITIALIZER;

struct thresh_by_src_ipc *threshbysrc_ipc;
struct thresh_by_dst_ipc *threshbydst_ipc;
struct thresh_by_srcport_ipc *threshbysrcport_ipc;
struct thresh_by_dstport_ipc *threshbydstport_ipc;
struct thresh_by_username_ipc *threshbyusername_ipc;

struct _Sagan_IPC_Counters *counters_ipc;

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

/***********************/
/* Threshold by source */
/***********************/

sbool Thresh_By_Src ( int rule_position, char *ip_src, uint32_t ip_src_u32 )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    sbool thresh_flag = false;
    sbool thresh_log_flag = false;

    uintmax_t thresh_oldtime;

    int i;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching src / sid */

    for (i = 0; i < counters_ipc->thresh_count_by_src; i++ ) {

        if ( threshbysrc_ipc[i].ipsrc == ip_src_u32 && !strcmp(threshbysrc_ipc[i].sid, rulestruct[rule_position].s_sid )) {

            thresh_flag = true;

            File_Lock(config->shm_thresh_by_src);
            pthread_mutex_lock(&Thresh_By_Src_Mutex);

            threshbysrc_ipc[i].count++;
            thresh_oldtime = atol(timet) - threshbysrc_ipc[i].utime;

            threshbysrc_ipc[i].utime = atol(timet);

            if ( thresh_oldtime > rulestruct[rule_position].threshold_seconds ) {
                threshbysrc_ipc[i].count=1;
                threshbysrc_ipc[i].utime = atol(timet);
                thresh_log_flag = false;
            }

            if ( rulestruct[rule_position].threshold_count < threshbysrc_ipc[i].count ) {
                thresh_log_flag = true;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "Threshold SID %s by source IP address. [%s]", threshbysrc_ipc[i].sid, ip_src);
                }

                counters->threshold_total++;
            }

            pthread_mutex_unlock(&Thresh_By_Src_Mutex);
            File_Unlock(config->shm_thresh_by_src);
        }
    }

    /* If not found,  add it to the array */

    if ( thresh_flag == false ) {

        if ( Clean_IPC_Object(THRESH_BY_SRC) == 0 ) {

            File_Lock(config->shm_thresh_by_src);
            pthread_mutex_lock(&Thresh_By_Src_Mutex);

            threshbysrc_ipc[counters_ipc->thresh_count_by_src].ipsrc = ip_src_u32;
            strlcpy(threshbysrc_ipc[counters_ipc->thresh_count_by_src].sid, rulestruct[rule_position].s_sid, sizeof(threshbysrc_ipc[counters_ipc->thresh_count_by_src].sid));
            threshbysrc_ipc[counters_ipc->thresh_count_by_src].count = 1;
            threshbysrc_ipc[counters_ipc->thresh_count_by_src].utime = atol(timet);
            threshbysrc_ipc[counters_ipc->thresh_count_by_src].expire = rulestruct[rule_position].threshold_seconds;

            counters_ipc->thresh_count_by_src++;

            pthread_mutex_unlock(&Thresh_By_Src_Mutex);
            File_Unlock(config->shm_thresh_by_src);
        }
    }

    return(thresh_log_flag);
}

/****************************/
/* Threshold by destination */
/****************************/

sbool Thresh_By_Dst ( int rule_position, char *ip_dst, uint32_t ip_dst_u32 )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    sbool thresh_flag = false;
    sbool thresh_log_flag = false;

    uintmax_t thresh_oldtime;

    int i;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching dst / sid */

    for (i = 0; i < counters_ipc->thresh_count_by_dst; i++ ) {

        if ( threshbydst_ipc[i].ipdst == ip_dst_u32 && !strcmp(threshbydst_ipc[i].sid, rulestruct[rule_position].s_sid )) {

            thresh_flag = true;

            File_Lock(config->shm_thresh_by_dst);
            pthread_mutex_lock(&Thresh_By_Dst_Mutex);

            threshbydst_ipc[i].count++;
            thresh_oldtime = atol(timet) - threshbydst_ipc[i].utime;

            threshbydst_ipc[i].utime = atol(timet);

            if ( thresh_oldtime > rulestruct[rule_position].threshold_seconds ) {

                threshbydst_ipc[i].count=1;
                threshbydst_ipc[i].utime = atol(timet);
                thresh_log_flag = false;

            }

            if ( rulestruct[rule_position].threshold_count < threshbydst_ipc[i].count ) {

                thresh_log_flag = true;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "Threshold SID %s by destination IP address. [%s]", threshbydst_ipc[i].sid, ip_dst);
                }

                counters->threshold_total++;
            }

            pthread_mutex_unlock(&Thresh_By_Dst_Mutex);
            File_Unlock(config->shm_thresh_by_dst);
        }
    }

    /* If not found,  add it to the array */

    if ( thresh_flag == false ) {

        if ( Clean_IPC_Object(THRESH_BY_DST) == 0 ) {

            File_Lock(config->shm_thresh_by_dst);
            pthread_mutex_lock(&Thresh_By_Dst_Mutex);

            threshbydst_ipc[counters_ipc->thresh_count_by_dst].ipdst = ip_dst_u32;
            strlcpy(threshbydst_ipc[counters_ipc->thresh_count_by_dst].sid, rulestruct[rule_position].s_sid, sizeof(threshbydst_ipc[counters_ipc->thresh_count_by_dst].sid));
            threshbydst_ipc[counters_ipc->thresh_count_by_dst].count = 1;
            threshbydst_ipc[counters_ipc->thresh_count_by_dst].utime = atol(timet);
            threshbydst_ipc[counters_ipc->thresh_count_by_dst].expire = rulestruct[rule_position].threshold_seconds;

            counters_ipc->thresh_count_by_dst++;

            pthread_mutex_unlock(&Thresh_By_Dst_Mutex);
            File_Unlock(config->shm_thresh_by_dst);
        }
    }

    return(thresh_log_flag);
}

/*************************/
/* Threshold by username */
/*************************/

sbool Thresh_By_Username( int rule_position, char *normalize_username )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    sbool thresh_flag = false;
    sbool thresh_log_flag = false;

    uintmax_t thresh_oldtime;

    int i;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array fror matching username / sid */

    for (i = 0; i < counters_ipc->thresh_count_by_username; i++) {

        if ( !strcmp(threshbyusername_ipc[rule_position].username, normalize_username) && !strcmp(threshbyusername_ipc[rule_position].sid, rulestruct[rule_position].s_sid )) {

            thresh_flag = true;

            File_Lock(config->shm_thresh_by_username);
            pthread_mutex_lock(&Thresh_By_Username_Mutex);

            threshbyusername_ipc[rule_position].count++;
            thresh_oldtime = atol(timet) - threshbyusername_ipc[rule_position].utime;
            threshbyusername_ipc[rule_position].utime = atol(timet);

            if ( thresh_oldtime > rulestruct[rule_position].threshold_seconds ) {
                threshbyusername_ipc[rule_position].count=1;
                threshbyusername_ipc[rule_position].utime = atol(timet);
                thresh_log_flag = false;
            }

            if ( rulestruct[rule_position].threshold_count < threshbyusername_ipc[rule_position].count ) {

                thresh_log_flag = true;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "Threshold SID %s by_username / by_string. [%s]", threshbyusername_ipc[rule_position].sid, normalize_username);
                }

                counters->threshold_total++;
            }

            pthread_mutex_unlock(&Thresh_By_Username_Mutex);
            File_Unlock(config->shm_thresh_by_username);

        }
    }

    /* Username not found, add it to array */

    if ( thresh_flag == false ) {

        if ( Clean_IPC_Object(THRESH_BY_USERNAME) == 0 ) {

            File_Lock(config->shm_thresh_by_username);
            pthread_mutex_lock(&Thresh_By_Username_Mutex);

            strlcpy(threshbyusername_ipc[counters_ipc->thresh_count_by_username].username, normalize_username, sizeof(threshbyusername_ipc[counters_ipc->thresh_count_by_username].username));
            strlcpy(threshbyusername_ipc[counters_ipc->thresh_count_by_username].sid, rulestruct[rule_position].s_sid, sizeof(threshbyusername_ipc[counters_ipc->thresh_count_by_username].sid));
            threshbyusername_ipc[counters_ipc->thresh_count_by_username].count = 1;
            threshbyusername_ipc[counters_ipc->thresh_count_by_username].utime = atol(timet);
            threshbyusername_ipc[counters_ipc->thresh_count_by_username].expire = rulestruct[rule_position].threshold_seconds;

            counters_ipc->thresh_count_by_username++;

            pthread_mutex_unlock(&Thresh_By_Username_Mutex);
            File_Unlock(config->shm_thresh_by_username);
        }
    }

    return(thresh_log_flag);
}

/*********************************/
/* Threshold by destination port */
/*********************************/

sbool Thresh_By_DstPort( int rule_position, uint32_t ip_dstport_u32 )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    sbool thresh_flag = false;
    sbool thresh_log_flag = false;

    uintmax_t thresh_oldtime;

    int i;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching dst port / sid */

    for (i = 0; i < counters_ipc->thresh_count_by_dstport; i++ ) {

        if ( threshbydstport_ipc[rule_position].ipdstport == ip_dstport_u32 && !strcmp(threshbydstport_ipc[rule_position].sid, rulestruct[rule_position].s_sid )) {

            thresh_flag = true;

            File_Lock(config->shm_thresh_by_dstport);
            pthread_mutex_lock(&Thresh_By_Dst_Port_Mutex);

            threshbydstport_ipc[rule_position].count++;
            thresh_oldtime = atol(timet) - threshbydstport_ipc[rule_position].utime;
            threshbydstport_ipc[rule_position].utime = atol(timet);

            if ( thresh_oldtime > rulestruct[rule_position].threshold_seconds ) {

                threshbydstport_ipc[rule_position].count=1;
                threshbydstport_ipc[rule_position].utime = atol(timet);
                thresh_log_flag = false;
            }

            if ( rulestruct[rule_position].threshold_count < threshbydstport_ipc[rule_position].count ) {
                thresh_log_flag = true;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "Threshold SID %s by destination IP port. [%s]", threshbydstport_ipc[rule_position].sid, ip_dstport_u32);
                }

                counters->threshold_total++;
            }

            pthread_mutex_unlock(&Thresh_By_Dst_Port_Mutex);
            File_Unlock(config->shm_thresh_by_dstport);

        }
    }

    /* If not found,  add it to the array */

    if ( thresh_flag == false ) {

        if ( Clean_IPC_Object(THRESH_BY_DSTPORT) == 0 ) {

            File_Lock(config->shm_thresh_by_dstport);
            pthread_mutex_lock(&Thresh_By_Dst_Port_Mutex);


            threshbydstport_ipc[counters_ipc->thresh_count_by_dstport].ipdstport = ip_dstport_u32;
            strlcpy(threshbydstport_ipc[counters_ipc->thresh_count_by_dstport].sid, rulestruct[rule_position].s_sid, sizeof(threshbydstport_ipc[counters_ipc->thresh_count_by_dstport].sid));
            threshbydstport_ipc[counters_ipc->thresh_count_by_dstport].count = 1;
            threshbydstport_ipc[counters_ipc->thresh_count_by_dstport].utime = atol(timet);
            threshbydstport_ipc[counters_ipc->thresh_count_by_dstport].expire = rulestruct[rule_position].threshold_seconds;

            counters_ipc->thresh_count_by_dstport++;

            pthread_mutex_unlock(&Thresh_By_Dst_Port_Mutex);
            File_Unlock(config->shm_thresh_by_dstport);
        }
    }

    return(thresh_log_flag);
}

/****************************/
/* Threshold by source port */
/****************************/

sbool Thresh_By_SrcPort( int rule_position, uint32_t ip_srcport_u32 )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    sbool thresh_flag = false;
    sbool thresh_log_flag = false;

    uintmax_t thresh_oldtime;

    int i;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching src port / sid */

    for (i = 0; i < counters_ipc->thresh_count_by_srcport; i++ ) {

        if ( threshbysrcport_ipc[rule_position].ipsrcport == ip_srcport_u32 && !strcmp(threshbysrcport_ipc[rule_position].sid, rulestruct[rule_position].s_sid )) {

            thresh_flag = true;

            File_Lock(config->shm_thresh_by_srcport);
            pthread_mutex_lock(&Thresh_By_Src_Port_Mutex);

            threshbysrcport_ipc[rule_position].count++;
            thresh_oldtime = atol(timet) - threshbysrcport_ipc[rule_position].utime;
            threshbysrcport_ipc[rule_position].utime = atol(timet);

            if ( thresh_oldtime > rulestruct[rule_position].threshold_seconds ) {

                threshbysrcport_ipc[rule_position].count=1;
                threshbysrcport_ipc[rule_position].utime = atol(timet);
                thresh_log_flag = false;
            }

            if ( rulestruct[rule_position].threshold_count < threshbysrcport_ipc[rule_position].count ) {
                thresh_log_flag = true;

                if ( debug->debuglimits ) {
                    Sagan_Log(S_NORMAL, "Threshold SID %s by source IP port. [%s]", threshbysrcport_ipc[rule_position].sid, ip_srcport_u32);
                }

                counters->threshold_total++;
            }

            pthread_mutex_unlock(&Thresh_By_Src_Port_Mutex);
            File_Unlock(config->shm_thresh_by_srcport);

        }
    }

    /* If not found,  add it to the array */

    if ( thresh_flag == false ) {

        if ( Clean_IPC_Object(THRESH_BY_SRCPORT) == 0 ) {

            File_Lock(config->shm_thresh_by_srcport);
            pthread_mutex_lock(&Thresh_By_Src_Port_Mutex);


            threshbysrcport_ipc[counters_ipc->thresh_count_by_srcport].ipsrcport = ip_srcport_u32;
            strlcpy(threshbysrcport_ipc[counters_ipc->thresh_count_by_srcport].sid, rulestruct[rule_position].s_sid, sizeof(threshbysrcport_ipc[counters_ipc->thresh_count_by_srcport].sid));
            threshbysrcport_ipc[counters_ipc->thresh_count_by_srcport].count = 1;
            threshbysrcport_ipc[counters_ipc->thresh_count_by_srcport].utime = atol(timet);
            threshbysrcport_ipc[counters_ipc->thresh_count_by_srcport].expire = rulestruct[rule_position].threshold_seconds;

            counters_ipc->thresh_count_by_srcport++;

            pthread_mutex_unlock(&Thresh_By_Src_Port_Mutex);
            File_Unlock(config->shm_thresh_by_srcport);
        }
    }

    return(thresh_log_flag);
}

