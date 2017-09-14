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

/* after.c - Logic for "after" in Sagan rule */

/* TODO:  Need to test IPC limits for threshold/after/client tracking */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "rules.h"
#include "after.h"
#include "ipc.h"

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

sbool After_By_Src ( int rule_position, char *ip_src, unsigned char *ip_src_bits, char *selector )
{

    sbool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    for (i = 0; i < counters_ipc->after_count_by_src; i++ )
        {

            if ( 0 == memcmp(afterbysrc_ipc[i].ipsrc, ip_src_bits, sizeof(afterbysrc_ipc[i].ipsrc)) &&
                    !strcmp(afterbysrc_ipc[i].sid, rulestruct[rule_position].s_sid) &&
                    (NULL == selector || 0 == strcmp(selector, afterbysrc_ipc[i].selector)) )
                {

                    File_Lock(config->shm_after_by_src);
                    pthread_mutex_lock(&After_By_Src_Mutex);

                    afterbysrc_ipc[i].count++;
                    afterbysrc_ipc[i].total_count++;

                    after_oldtime = atol(timet) - afterbysrc_ipc[i].utime;

                    /* Reset counter if it's expired */

                    if ( after_oldtime > rulestruct[rule_position].after_seconds ||
                            afterbysrc_ipc[i].count == 0 )
                        {

                            afterbysrc_ipc[i].count=1;
                            afterbysrc_ipc[i].utime = atol(timet);

                            after_log_flag = true;
                        }

                    if ( rulestruct[rule_position].after_count < afterbysrc_ipc[i].count )
                        {

                            after_log_flag = false;

                            if ( debug->debuglimits )
                                {
                                    Sagan_Log(S_NORMAL, "After SID %s by source IP address. [%s]", afterbysrc_ipc[i].sid, ip_src);
                                }

                            counters->after_total++;
                        }

                    pthread_mutex_unlock(&After_By_Src_Mutex);
                    File_Unlock(config->shm_after_by_src);

                    return(after_log_flag);

                }
        }


    /* If not found,  add it to the array */

    if ( Clean_IPC_Object(AFTER_BY_SRC) == 0 )
        {

            File_Lock(config->shm_after_by_src);
            pthread_mutex_lock(&After_By_Src_Mutex);

            memcpy(afterbysrc_ipc[counters_ipc->after_count_by_src].ipsrc, ip_src_bits, sizeof(afterbysrc_ipc[counters_ipc->after_count_by_src].ipsrc));
            strlcpy(afterbysrc_ipc[counters_ipc->after_count_by_src].sid, rulestruct[rule_position].s_sid, sizeof(afterbysrc_ipc[counters_ipc->after_count_by_src].sid));
            NULL == selector ? afterbysrc_ipc[counters_ipc->after_count_by_src].selector[0] = '\0' : strlcpy(afterbysrc_ipc[counters_ipc->after_count_by_src].selector, selector, MAXSELECTOR);
            afterbysrc_ipc[counters_ipc->after_count_by_src].count = 1;
            afterbysrc_ipc[counters_ipc->after_count_by_src].utime = atol(timet);
            afterbysrc_ipc[counters_ipc->after_count_by_src].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_src++;

            pthread_mutex_unlock(&After_By_Src_Mutex);
            File_Unlock(config->shm_after_by_src);

        }

    return(true);
}

/************************/
/* After by Destination */
/************************/

sbool After_By_Dst ( int rule_position, char *ip_dst, unsigned char *ip_dst_bits, char *selector )
{

    sbool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    for (i = 0; i < counters_ipc->after_count_by_dst; i++ )
        {

            if ( 0 == memcmp(afterbydst_ipc[i].ipdst, ip_dst, sizeof(afterbydst_ipc[i].ipdst)) &&
                    !strcmp(afterbydst_ipc[i].sid, rulestruct[rule_position].s_sid ) &&
                    (NULL == selector || 0 == strcmp(selector, afterbydst_ipc[i].selector)) )
                {

                    File_Lock(config->shm_after_by_dst);
                    pthread_mutex_lock(&After_By_Dst_Mutex);

                    afterbydst_ipc[i].count++;
                    afterbydst_ipc[i].total_count++;

                    after_oldtime = atol(timet) - afterbydst_ipc[i].utime;

                    if ( after_oldtime > rulestruct[rule_position].after_seconds ||
                            afterbydst_ipc[i].count == 0 )
                        {

                            afterbydst_ipc[i].count=1;
                            afterbydst_ipc[i].utime = atol(timet);
                            after_log_flag = true;
                        }

                    if ( rulestruct[rule_position].after_count < afterbydst_ipc[i].count )
                        {

                            after_log_flag = false;

                            if ( debug->debuglimits )
                                {
                                    Sagan_Log(S_NORMAL, "After SID %s by destination IP address. [%s]", afterbydst_ipc[i].sid, ip_dst);
                                }

                            counters->after_total++;
                        }

                    pthread_mutex_unlock(&After_By_Dst_Mutex);
                    File_Unlock(config->shm_after_by_dst);

                    return(after_log_flag);

                }
        }


    /* If not found,  add it to the array */

    if ( Clean_IPC_Object(AFTER_BY_DST) == 0 )
        {

            File_Lock(config->shm_after_by_dst);
            pthread_mutex_lock(&After_By_Dst_Mutex);

            memcpy(afterbydst_ipc[counters_ipc->after_count_by_dst].ipdst, ip_dst_bits, sizeof(afterbydst_ipc[counters_ipc->after_count_by_dst].ipdst));
            strlcpy(afterbydst_ipc[counters_ipc->after_count_by_dst].sid, rulestruct[rule_position].s_sid, sizeof(afterbydst_ipc[counters_ipc->after_count_by_dst].sid));
            NULL == selector ? afterbydst_ipc[counters_ipc->after_count_by_dst].selector[0] = '\0' : strlcpy(afterbydst_ipc[counters_ipc->after_count_by_dst].selector, selector, MAXSELECTOR);
            afterbydst_ipc[counters_ipc->after_count_by_dst].count = 1;
            afterbydst_ipc[counters_ipc->after_count_by_dst].utime = atol(timet);
            afterbydst_ipc[counters_ipc->after_count_by_dst].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_dst++;

            pthread_mutex_unlock(&After_By_Dst_Mutex);
            File_Unlock(config->shm_after_by_dst);

        }

    return(true);

}

/*********************/
/* After by username */
/*********************/

sbool After_By_Username( int rule_position, char *normalize_username, char *selector )
{

    sbool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching username / sid */

    for (i = 0; i < counters_ipc->after_count_by_username; i++ )
        {
            // Short circuit if no selector match
            if (
                (NULL == selector && afterbyusername_ipc[i].selector[0] != '\0') ||
                (NULL != selector && 0 != strcmp(selector, afterbyusername_ipc[i].selector))
            )
                {

                    continue;
                }


            if ( !strcmp(afterbyusername_ipc[i].username, normalize_username) &&
                    !strcmp(afterbyusername_ipc[i].sid, rulestruct[rule_position].s_sid))
                {

                    File_Lock(config->shm_after_by_username);
                    pthread_mutex_lock(&After_By_Username_Mutex);

                    afterbyusername_ipc[i].count++;
                    afterbyusername_ipc[i].total_count++;

                    after_oldtime = atol(timet) - afterbyusername_ipc[i].utime;

                    if ( after_oldtime > rulestruct[rule_position].after_seconds ||
                            afterbysrc_ipc[i].count == 0 )
                        {

                            afterbyusername_ipc[i].count=1;
                            afterbyusername_ipc[i].utime = atol(timet);

                            after_log_flag = true;
                        }

                    if ( rulestruct[rule_position].after_count < afterbyusername_ipc[i].count )
                        {
                            after_log_flag = false;

                            if ( debug->debuglimits )
                                {
                                    Sagan_Log(S_NORMAL, "After SID %s by_username. [%s]", afterbyusername_ipc[i].sid, normalize_username);
                                }

                            counters->after_total++;

                        }

                    pthread_mutex_unlock(&After_By_Username_Mutex);
                    File_Unlock(config->shm_after_by_username);

                    return(after_log_flag);

                }
        }

    /* If not found, add to the username array */

    if ( Clean_IPC_Object(AFTER_BY_DST) == 0 )
        {

            File_Lock(config->shm_after_by_username);
            pthread_mutex_lock(&After_By_Username_Mutex);

            strlcpy(afterbyusername_ipc[counters_ipc->after_count_by_username].username, normalize_username, sizeof(afterbyusername_ipc[counters_ipc->after_count_by_username].username));
            strlcpy(afterbyusername_ipc[counters_ipc->after_count_by_username].sid, rulestruct[rule_position].s_sid, sizeof(afterbyusername_ipc[counters_ipc->after_count_by_username].sid));
            NULL == selector ? afterbyusername_ipc[counters_ipc->after_count_by_username].selector[0] = '\0' : strlcpy(afterbyusername_ipc[counters_ipc->after_count_by_username].selector, selector, MAXSELECTOR);
            afterbyusername_ipc[counters_ipc->after_count_by_username].count = 1;
            afterbyusername_ipc[counters_ipc->after_count_by_username].utime = atol(timet);
            afterbyusername_ipc[counters_ipc->after_count_by_username].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_username++;

            pthread_mutex_unlock(&After_By_Username_Mutex);
            File_Unlock(config->shm_after_by_username);
        }

    return(true);

} /* End of After */

/***************************/
/* After by source IP port */
/***************************/

sbool After_By_SrcPort( int rule_position, uint32_t ip_srcport_u32, char *selector )
{

    sbool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);


    for (i = 0; i < counters_ipc->after_count_by_srcport; i++ )
        {
            // Short circuit if no selector match
            if (
                (NULL == selector && afterbysrcport_ipc[i].selector[0] != '\0') ||
                (NULL != selector && 0 != strcmp(selector, afterbysrcport_ipc[i].selector))
            )
                {

                    continue;
                }

            if ( afterbysrcport_ipc[i].ipsrcport == ip_srcport_u32 &&
                    !strcmp(afterbysrcport_ipc[i].sid, rulestruct[rule_position].s_sid ))
                {

                    File_Lock(config->shm_after_by_srcport);
                    pthread_mutex_lock(&After_By_Src_Port_Mutex);

                    afterbysrcport_ipc[i].count++;
                    afterbysrcport_ipc[i].total_count++;

                    after_oldtime = atol(timet) - afterbysrcport_ipc[i].utime;

                    if ( after_oldtime > rulestruct[rule_position].after_seconds ||
                            afterbysrc_ipc[i].count == 0 )
                        {

                            afterbysrcport_ipc[i].count=1;
                            afterbysrcport_ipc[i].utime = atol(timet);
                            after_log_flag = true;
                        }

                    if ( rulestruct[rule_position].after_count < afterbysrcport_ipc[i].count )
                        {
                            after_log_flag = false;

                            if ( debug->debuglimits )
                                {
                                    Sagan_Log(S_NORMAL, "After SID %s by source IP port. [%d]", afterbysrcport_ipc[i].sid, ip_srcport_u32);
                                }

                            counters->after_total++;
                        }

                    pthread_mutex_unlock(&After_By_Src_Port_Mutex);
                    File_Unlock(config->shm_after_by_srcport);

                    return(after_log_flag);

                }
        }

    /* If not found,  add it to the array */

    if ( Clean_IPC_Object(AFTER_BY_SRCPORT) == 0 )
        {

            File_Lock(config->shm_after_by_srcport);
            pthread_mutex_lock(&After_By_Src_Port_Mutex);

            afterbysrcport_ipc[counters_ipc->after_count_by_srcport].ipsrcport = ip_srcport_u32;
            strlcpy(afterbysrcport_ipc[counters_ipc->after_count_by_srcport].sid, rulestruct[rule_position].s_sid, sizeof(afterbysrcport_ipc[counters_ipc->after_count_by_srcport].sid));
            NULL == selector ? afterbysrcport_ipc[counters_ipc->after_count_by_srcport].selector[0] = '\0' : strlcpy(afterbysrcport_ipc[counters_ipc->after_count_by_srcport].selector, selector, MAXSELECTOR);
            afterbysrcport_ipc[counters_ipc->after_count_by_srcport].count = 1;
            afterbysrcport_ipc[counters_ipc->after_count_by_srcport].utime = atol(timet);
            afterbysrcport_ipc[counters_ipc->after_count_by_srcport].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_srcport++;

            pthread_mutex_unlock(&After_By_Src_Port_Mutex);
            File_Unlock(config->shm_after_by_srcport);

        }

    return(true);

}

/********************************/
/* After by destination IP port */
/********************************/

sbool After_By_DstPort( int rule_position, uint32_t ip_dstport_u32, char *selector )
{

    sbool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uintmax_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);


    for (i = 0; i < counters_ipc->after_count_by_dstport; i++ )
        {
            // Short circuit if no selector match
            if (
                (NULL == selector && afterbydstport_ipc[i].selector[0] != '\0') ||
                (NULL != selector && 0 != strcmp(selector, afterbydstport_ipc[i].selector))
            )
                {

                    continue;
                }

            if ( afterbydstport_ipc[i].ipdstport == ip_dstport_u32 &&
                    !strcmp(afterbydstport_ipc[i].sid, rulestruct[rule_position].s_sid ))
                {

                    File_Lock(config->shm_after_by_dstport);
                    pthread_mutex_lock(&After_By_Dst_Port_Mutex);

                    afterbydstport_ipc[i].count++;
                    afterbydstport_ipc[i].total_count++;

                    after_oldtime = atol(timet) - afterbydstport_ipc[i].utime;

                    if ( after_oldtime > rulestruct[rule_position].after_seconds ||
                            afterbysrc_ipc[i].count == 0 )
                        {

                            afterbydstport_ipc[i].count=1;
                            afterbydstport_ipc[i].utime = atol(timet);
                            after_log_flag = true;

                        }

                    if ( rulestruct[rule_position].after_count < afterbydstport_ipc[i].count )
                        {
                            after_log_flag = false;

                            if ( debug->debuglimits )
                                {
                                    Sagan_Log(S_NORMAL, "After SID %s by destination IP port. [%d]", afterbydstport_ipc[i].sid, ip_dstport_u32);
                                }

                            counters->after_total++;
                        }

                    pthread_mutex_unlock(&After_By_Dst_Port_Mutex);
                    File_Unlock(config->shm_after_by_dstport);

                    return(after_log_flag);

                }
        }

    /* If not found,  add it to the array */

    if ( Clean_IPC_Object(AFTER_BY_DSTPORT) == 0 )
        {

            File_Lock(config->shm_after_by_dstport);
            pthread_mutex_lock(&After_By_Dst_Port_Mutex);

            afterbydstport_ipc[counters_ipc->after_count_by_dstport].ipdstport = ip_dstport_u32;
            strlcpy(afterbydstport_ipc[counters_ipc->after_count_by_dstport].sid, rulestruct[rule_position].s_sid, sizeof(afterbydstport_ipc[counters_ipc->after_count_by_dstport].sid));
            NULL == selector ? afterbydstport_ipc[counters_ipc->after_count_by_dstport].selector[0] = '\0' : strlcpy(afterbydstport_ipc[counters_ipc->after_count_by_dstport].selector, selector, MAXSELECTOR);
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].count = 1;
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].utime = atol(timet);
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_dstport++;

            pthread_mutex_unlock(&After_By_Dst_Port_Mutex);
            File_Unlock(config->shm_after_by_dstport);

        }

    return(true);

}
