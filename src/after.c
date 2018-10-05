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
pthread_mutex_t After2_Mutex=PTHREAD_MUTEX_INITIALIZER;


struct after_by_src_ipc *afterbysrc_ipc;
struct after_by_dst_ipc *afterbydst_ipc;
struct after_by_srcport_ipc *afterbysrcport_ipc;
struct after_by_dstport_ipc *afterbydstport_ipc;
struct after_by_username_ipc *afterbyusername_ipc;

struct _After2_IPC *After2_IPC;

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct _Sagan_IPC_Counters *counters_ipc;

bool After2 ( int rule_position, char *ip_src, char *ip_dst, char *username, char *selector, char *syslog_message )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uint64_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    char src_tmp[MAXIP] = { 0 };
    char dst_tmp[MAXIP] = { 0 };
    char string1_tmp[MAX_USERNAME_SIZE] = { 0 };

    char hash_string[128] = { 0 };
    char debug_string[64] = { 0 };

    uint32_t hash;

    bool after_log_flag = true;
    string1_tmp[1] = '\0';

    if ( rulestruct[rule_position].after2_method_src == true )
        {
            strlcpy(src_tmp, ip_src, sizeof(src_tmp));
        }

    if ( rulestruct[rule_position].after2_method_dst == true )
        {
            strlcpy(dst_tmp, ip_dst, sizeof(dst_tmp));
        }

    if ( rulestruct[rule_position].after2_method_username == true && username != NULL )
        {
            strlcpy(string1_tmp, username, sizeof(string1_tmp));
        }

    snprintf(hash_string, sizeof(hash_string), "%s|%s|%s", src_tmp, dst_tmp, string1_tmp);

    hash = Djb2_Hash( hash_string );

    for (i = 0; i < counters_ipc->after2_count; i++ )
        {

            if ( hash == After2_IPC[i].hash &&
                    !strcmp(After2_IPC[i].sid, rulestruct[rule_position].s_sid) &&
                    ( selector == NULL || !strcmp(selector, afterbysrc_ipc[i].selector)) )
                {

                    File_Lock(config->shm_after2);
                    pthread_mutex_lock(&After2_Mutex);

                    After2_IPC[i].count++;
                    After2_IPC[i].total_count++;

                    after_oldtime = atol(timet) - After2_IPC[i].utime;

                    strlcpy(After2_IPC[i].syslog_message, syslog_message, sizeof(After2_IPC[i].syslog_message));
                    strlcpy(After2_IPC[i].signature_msg, rulestruct[rule_position].s_msg, sizeof(After2_IPC[i].signature_msg));

                    /* Reset counter if it's expired */

                    if ( after_oldtime > rulestruct[rule_position].after2_seconds ||
                            After2_IPC[i].count == 0 )
                        {

                            After2_IPC[i].count=1;
                            After2_IPC[i].utime = atol(timet);

                            after_log_flag = true;
                        }


                    if ( rulestruct[rule_position].after2_count < After2_IPC[i].count )
                        {

                            after_log_flag = false;

                            if ( debug->debuglimits )
                                {

                                    if ( After2_IPC[i].after2_method_src == true )
                                        {
                                            strlcat(debug_string, "by_src ", sizeof(debug_string));
                                        }

                                    if ( After2_IPC[i].after2_method_dst == true )
                                        {
                                            strlcat(debug_string, "by_dst ", sizeof(debug_string));
                                        }

                                    if ( After2_IPC[i].after2_method_username == true )
                                        {
                                            strlcat(debug_string, "username ", sizeof(debug_string));
                                        }

                                    Sagan_Log(NORMAL, "After SID %s. Tracking by %s[Hash: %lu]", After2_IPC[i].sid, debug_string, hash);

                                }

                            counters->after_total++;
                        }

                    pthread_mutex_unlock(&After2_Mutex);
                    File_Unlock(config->shm_after2);

                    return(after_log_flag);
                }

        }


    /* If not found add it to the array */

    if ( Clean_IPC_Object(AFTER2) == 0 )
        {

            File_Lock(config->shm_after2);
            pthread_mutex_lock(&After2_Mutex);

            After2_IPC[counters_ipc->after2_count].hash = hash;

            selector == NULL ? After2_IPC[counters_ipc->after2_count].selector[0] = '\0' : strlcpy(After2_IPC[counters_ipc->after2_count].selector, selector, MAXSELECTOR);

            After2_IPC[counters_ipc->after2_count].count = 1;
            After2_IPC[counters_ipc->after2_count].utime = atol(timet);
            After2_IPC[counters_ipc->after2_count].expire = rulestruct[rule_position].after2_seconds;

            After2_IPC[counters_ipc->after2_count].after2_method_src = rulestruct[rule_position].after2_method_src;
            After2_IPC[counters_ipc->after2_count].after2_method_dst = rulestruct[rule_position].after2_method_dst;
            After2_IPC[counters_ipc->after2_count].after2_method_username = rulestruct[rule_position].after2_method_username;

            strlcpy(After2_IPC[counters_ipc->after2_count].ip_src, src_tmp, sizeof(After2_IPC[counters_ipc->after2_count].ip_src));
            strlcpy(After2_IPC[counters_ipc->after2_count].ip_dst, dst_tmp, sizeof(After2_IPC[counters_ipc->after2_count].ip_dst));
            strlcpy(After2_IPC[counters_ipc->after2_count].string1, string1_tmp, sizeof(After2_IPC[counters_ipc->after2_count].string1));

            strlcpy(After2_IPC[counters_ipc->after2_count].sid, rulestruct[rule_position].s_sid, sizeof(After2_IPC[counters_ipc->after2_count].sid));
            strlcpy(After2_IPC[counters_ipc->after2_count].syslog_message, syslog_message, sizeof(After2_IPC[counters_ipc->after2_count].syslog_message));
            strlcpy(After2_IPC[counters_ipc->after2_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(After2_IPC[counters_ipc->after2_count].signature_msg));

            counters_ipc->after2_count++;

            pthread_mutex_unlock(&After2_Mutex);
            File_Unlock(config->shm_after2);
        }

    return(true);
}

/*******************/
/* After by source */
/*******************/

bool After_By_Src ( int rule_position, char *ip_src, unsigned char *ip_src_bits, char *selector, char *syslog_message )
{

    bool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uint64_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    for (i = 0; i < counters_ipc->after_count_by_src; i++ )
        {

            if ( !memcmp(afterbysrc_ipc[i].ipsrc, ip_src_bits, sizeof(afterbysrc_ipc[i].ipsrc)) &&
                    !strcmp(afterbysrc_ipc[i].sid, rulestruct[rule_position].s_sid) &&
                    ( selector == NULL || !strcmp(selector, afterbysrc_ipc[i].selector)) )
                {

                    File_Lock(config->shm_after_by_src);
                    pthread_mutex_lock(&After_By_Src_Mutex);

                    afterbysrc_ipc[i].count++;
                    afterbysrc_ipc[i].total_count++;

                    after_oldtime = atol(timet) - afterbysrc_ipc[i].utime;

                    strlcpy(afterbysrc_ipc[i].syslog_message, syslog_message, sizeof(afterbysrc_ipc[i].syslog_message));
                    strlcpy(afterbysrc_ipc[i].signature_msg, rulestruct[rule_position].s_msg, sizeof(afterbysrc_ipc[i].signature_msg));


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
                                    Sagan_Log(NORMAL, "After SID %s by source IP address. [%s]", afterbysrc_ipc[i].sid, ip_src);
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
            selector == NULL ? afterbysrc_ipc[counters_ipc->after_count_by_src].selector[0] = '\0' : strlcpy(afterbysrc_ipc[counters_ipc->after_count_by_src].selector, selector, MAXSELECTOR);
            afterbysrc_ipc[counters_ipc->after_count_by_src].count = 1;
            afterbysrc_ipc[counters_ipc->after_count_by_src].utime = atol(timet);
            afterbysrc_ipc[counters_ipc->after_count_by_src].expire = rulestruct[rule_position].after_seconds;

            strlcpy(afterbysrc_ipc[counters_ipc->after_count_by_src].syslog_message, syslog_message, sizeof(afterbysrc_ipc[counters_ipc->after_count_by_src].syslog_message));
            strlcpy(afterbysrc_ipc[counters_ipc->after_count_by_src].signature_msg, rulestruct[rule_position].s_msg, sizeof(afterbysrc_ipc[counters_ipc->after_count_by_src].signature_msg));

            counters_ipc->after_count_by_src++;

            pthread_mutex_unlock(&After_By_Src_Mutex);
            File_Unlock(config->shm_after_by_src);

        }

    return(true);
}

/************************/
/* After by Destination */
/************************/

bool After_By_Dst ( int rule_position, char *ip_dst, unsigned char *ip_dst_bits, char *selector, char *syslog_message )
{

    bool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uint64_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    for (i = 0; i < counters_ipc->after_count_by_dst; i++ )
        {

            if ( !memcmp(afterbydst_ipc[i].ipdst, ip_dst_bits, sizeof(afterbydst_ipc[i].ipdst)) &&
                    !strcmp(afterbydst_ipc[i].sid, rulestruct[rule_position].s_sid ) &&
                    ( selector == NULL || !strcmp(selector, afterbydst_ipc[i].selector)) )
                {

                    File_Lock(config->shm_after_by_dst);
                    pthread_mutex_lock(&After_By_Dst_Mutex);

                    afterbydst_ipc[i].count++;
                    afterbydst_ipc[i].total_count++;

                    after_oldtime = atol(timet) - afterbydst_ipc[i].utime;

                    strlcpy(afterbydst_ipc[i].syslog_message, syslog_message, sizeof(afterbydst_ipc[i].syslog_message));
                    strlcpy(afterbydst_ipc[i].signature_msg, rulestruct[rule_position].s_msg, sizeof(afterbydst_ipc[i].signature_msg));

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
                                    Sagan_Log(NORMAL, "After SID %s by destination IP address. [%s]", afterbydst_ipc[i].sid, ip_dst);
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
            selector == NULL ? afterbydst_ipc[counters_ipc->after_count_by_dst].selector[0] = '\0' : strlcpy(afterbydst_ipc[counters_ipc->after_count_by_dst].selector, selector, MAXSELECTOR);
            afterbydst_ipc[counters_ipc->after_count_by_dst].count = 1;
            afterbydst_ipc[counters_ipc->after_count_by_dst].utime = atol(timet);
            afterbydst_ipc[counters_ipc->after_count_by_dst].expire = rulestruct[rule_position].after_seconds;

            strlcpy(afterbydst_ipc[counters_ipc->after_count_by_dst].syslog_message, syslog_message, sizeof(afterbydst_ipc[counters_ipc->after_count_by_dst].syslog_message));
            strlcpy(afterbydst_ipc[counters_ipc->after_count_by_dst].signature_msg, rulestruct[rule_position].s_msg, sizeof(afterbydst_ipc[counters_ipc->after_count_by_dst].signature_msg));


            counters_ipc->after_count_by_dst++;

            pthread_mutex_unlock(&After_By_Dst_Mutex);
            File_Unlock(config->shm_after_by_dst);

        }

    return(true);

}

/*********************/
/* After by username */
/*********************/

bool After_By_Username( int rule_position, char *normalize_username, char *selector, char *syslog_message )
{

    bool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uint64_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /* Check array for matching username / sid */

    for (i = 0; i < counters_ipc->after_count_by_username; i++ )
        {
            /* Short circuit if no selector match */


            if ( ( selector == NULL && afterbyusername_ipc[i].selector[0] != '\0') ||
                    ( selector != NULL && strcmp(selector, afterbyusername_ipc[i].selector) != 0 ))
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

                    strlcpy(afterbyusername_ipc[i].syslog_message, syslog_message, sizeof(afterbyusername_ipc[i].syslog_message));
                    strlcpy(afterbyusername_ipc[i].signature_msg, rulestruct[rule_position].s_msg, sizeof(afterbyusername_ipc[i].signature_msg));

                    /* Reset counter if it's expired */

                    if ( after_oldtime > rulestruct[rule_position].after_seconds ||
                            afterbyusername_ipc[i].count == 0 )
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
                                    Sagan_Log(NORMAL, "After SID %s by_username. [%s]", afterbyusername_ipc[i].sid, normalize_username);
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
            selector == NULL ? afterbyusername_ipc[counters_ipc->after_count_by_username].selector[0] = '\0' : strlcpy(afterbyusername_ipc[counters_ipc->after_count_by_username].selector, selector, MAXSELECTOR);
            afterbyusername_ipc[counters_ipc->after_count_by_username].count = 1;
            afterbyusername_ipc[counters_ipc->after_count_by_username].utime = atol(timet);
            afterbyusername_ipc[counters_ipc->after_count_by_username].expire = rulestruct[rule_position].after_seconds;

            strlcpy(afterbyusername_ipc[counters_ipc->after_count_by_username].syslog_message, syslog_message, sizeof(afterbyusername_ipc[counters_ipc->after_count_by_username].syslog_message));
            strlcpy(afterbyusername_ipc[counters_ipc->after_count_by_username].signature_msg, rulestruct[rule_position].s_msg, sizeof(afterbyusername_ipc[counters_ipc->after_count_by_username].signature_msg));

            counters_ipc->after_count_by_username++;

            pthread_mutex_unlock(&After_By_Username_Mutex);
            File_Unlock(config->shm_after_by_username);
        }

    return(true);

} /* End of After */

/***************************/
/* After by source IP port */
/***************************/

bool After_By_SrcPort( int rule_position, uint32_t ip_srcport_u32, char *selector )
{

    bool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uint64_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);


    for (i = 0; i < counters_ipc->after_count_by_srcport; i++ )
        {
            /* Short circuit if no selector match */

            if (
                ( selector == NULL && afterbysrcport_ipc[i].selector[0] != '\0') ||
                ( selector != NULL  && 0 != strcmp(selector, afterbysrcport_ipc[i].selector))
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
                                    Sagan_Log(NORMAL, "After SID %s by source IP port. [%d]", afterbysrcport_ipc[i].sid, ip_srcport_u32);
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
            selector == NULL ? afterbysrcport_ipc[counters_ipc->after_count_by_srcport].selector[0] = '\0' : strlcpy(afterbysrcport_ipc[counters_ipc->after_count_by_srcport].selector, selector, MAXSELECTOR);
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

bool After_By_DstPort( int rule_position, uint32_t ip_dstport_u32, char *selector )
{

    bool after_log_flag = true;

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;

    uint64_t after_oldtime;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);


    for (i = 0; i < counters_ipc->after_count_by_dstport; i++ )
        {
            /* Short circuit if no selector match */

            if (
                ( selector == NULL && afterbydstport_ipc[i].selector[0] != '\0') ||
                ( selector != NULL  && 0 != strcmp(selector, afterbydstport_ipc[i].selector))
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
                                    Sagan_Log(NORMAL, "After SID %s by destination IP port. [%d]", afterbydstport_ipc[i].sid, ip_dstport_u32);
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
            selector == NULL ? afterbydstport_ipc[counters_ipc->after_count_by_dstport].selector[0] = '\0' : strlcpy(afterbydstport_ipc[counters_ipc->after_count_by_dstport].selector, selector, MAXSELECTOR);
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].count = 1;
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].utime = atol(timet);
            afterbydstport_ipc[counters_ipc->after_count_by_dstport].expire = rulestruct[rule_position].after_seconds;

            counters_ipc->after_count_by_dstport++;

            pthread_mutex_unlock(&After_By_Dst_Port_Mutex);
            File_Unlock(config->shm_after_by_dstport);

        }

    return(true);

}
