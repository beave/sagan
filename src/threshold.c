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

/* threshold.c - Logic for "threshold" in rules */

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
#include "threshold.h"
#include "ipc.h"

pthread_mutex_t Thresh2_Mutex=PTHREAD_MUTEX_INITIALIZER;

extern struct _Threshold2_IPC *Threshold2_IPC;
extern struct _Sagan_IPC_Counters *counters_ipc;

extern struct _SaganCounters *counters;
extern struct _Rule_Struct *rulestruct;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;

/***********************/
/* Threshold2          */
/***********************/

bool Threshold2 ( int rule_position, char *ip_src, uint32_t src_port, char *ip_dst,  uint32_t dst_port, char *username, char *syslog_message )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    bool thresh_log_flag = false;

    uint64_t thresh_oldtime = 0;
    uint64_t current_time = 0;

    int i;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    char src_tmp[MAXIP] = { 0 };
    char dst_tmp[MAXIP] = { 0 };
    char username_tmp[MAX_USERNAME_SIZE] = { 0 };
    uint32_t dst_port_tmp = 0;
    uint32_t src_port_tmp = 0;

    char hash_string[128] = { 0 };
    char debug_string[64] = { 0 };

    uint32_t hash;

    current_time = atoi(timet);

    username_tmp[0] = '\0';

    if ( rulestruct[rule_position].threshold2_method_src == true )
        {
            strlcpy(src_tmp, ip_src, sizeof(src_tmp));
        }

    if ( rulestruct[rule_position].threshold2_method_dst == true )
        {
            strlcpy(dst_tmp, ip_dst, sizeof(dst_tmp));
        }

    if ( rulestruct[rule_position].threshold2_method_username == true && username != NULL )
        {
            strlcpy(username_tmp, username, sizeof(username_tmp));
        }

    if ( rulestruct[rule_position].threshold2_method_srcport == true )
        {
            src_port_tmp = src_port;
        }

    if ( rulestruct[rule_position].threshold2_method_dstport == true )
        {
            dst_port_tmp = dst_port;
        }

    snprintf(hash_string, sizeof(hash_string), "%s|%d|%s|%d|%s", src_tmp, src_port_tmp, dst_tmp, dst_port_tmp, username_tmp);

    hash = Djb2_Hash( hash_string );

    for (i = 0; i < counters_ipc->thresh2_count; i++ )
        {

            if ( hash == Threshold2_IPC[i].hash && Threshold2_IPC[i].sid == rulestruct[rule_position].s_sid )
                {

                    File_Lock(config->shm_thresh2);
                    pthread_mutex_lock(&Thresh2_Mutex);

                    Threshold2_IPC[i].count++;

                    if ( rulestruct[rule_position].threshold2_type == THRESHOLD_SUPPRESS )
                        {
                            thresh_oldtime = current_time - Threshold2_IPC[i].utime;
                            Threshold2_IPC[i].utime = current_time;
                        }

                    else if ( rulestruct[rule_position].threshold2_type == THRESHOLD_LIMIT )
                        {
                            thresh_oldtime = current_time - Threshold2_IPC[i].utime;
                        }


                    strlcpy(Threshold2_IPC[i].syslog_message, syslog_message, sizeof(Threshold2_IPC[i].syslog_message));
                    strlcpy(Threshold2_IPC[i].signature_msg, rulestruct[rule_position].s_msg, sizeof(Threshold2_IPC[i].signature_msg));

                    if ( thresh_oldtime > rulestruct[rule_position].threshold2_seconds )
                        {
                            Threshold2_IPC[i].count=1;
                            Threshold2_IPC[i].utime = current_time;  /* Reset the time */
                            thresh_log_flag = false;
                        }

                    if ( rulestruct[rule_position].threshold2_count < Threshold2_IPC[i].count )
                        {
                            thresh_log_flag = true;

                            if ( debug->debuglimits )
                                {

                                    if ( Threshold2_IPC[i].threshold2_method_src == true )
                                        {
                                            strlcat(debug_string, "by_src ", sizeof(debug_string));
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_dst == true )
                                        {
                                            strlcat(debug_string, "by_dst ", sizeof(debug_string));
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_username == true )
                                        {
                                            strlcat(debug_string, "by_username ", sizeof(debug_string));
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_srcport == true )
                                        {
                                            strlcat(debug_string, "by_srcport ", sizeof(debug_string));
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_dstport == true )
                                        {
                                            strlcat(debug_string, "by_dstport ", sizeof(debug_string));
                                        }

                                    Sagan_Log(NORMAL, "Threshold SID %" PRIu64 ". Tracking by %s[%d: Hash: %lu]", Threshold2_IPC[i].sid, debug_string, i, hash);

                                }

                            counters->threshold_total++;
                        }

                    pthread_mutex_unlock(&Thresh2_Mutex);
                    File_Unlock(config->shm_thresh2);

                    return(thresh_log_flag);

                }

        }

    /* If not found,  add it to the array */

    if ( Clean_IPC_Object(THRESHOLD2) == 0 )
        {

            File_Lock(config->shm_thresh2);
            pthread_mutex_lock(&Thresh2_Mutex);

            Threshold2_IPC[counters_ipc->thresh2_count].hash = hash;

            Threshold2_IPC[counters_ipc->thresh2_count].count = 1;
            Threshold2_IPC[counters_ipc->thresh2_count].utime = current_time;
            Threshold2_IPC[counters_ipc->thresh2_count].expire = rulestruct[rule_position].threshold2_seconds;
            Threshold2_IPC[counters_ipc->thresh2_count].sid = rulestruct[rule_position].s_sid;
            Threshold2_IPC[counters_ipc->thresh2_count].target_count =rulestruct[rule_position].threshold2_count;
            Threshold2_IPC[counters_ipc->thresh2_count].threshold2_method_src = rulestruct[rule_position].threshold2_method_src;
            Threshold2_IPC[counters_ipc->thresh2_count].threshold2_method_dst = rulestruct[rule_position].threshold2_method_dst;
            Threshold2_IPC[counters_ipc->thresh2_count].threshold2_method_username = rulestruct[rule_position].threshold2_method_username;

            strlcpy(Threshold2_IPC[counters_ipc->thresh2_count].ip_src, src_tmp, sizeof(Threshold2_IPC[counters_ipc->thresh2_count].ip_src));
            Threshold2_IPC[counters_ipc->thresh2_count].src_port = src_port_tmp;

            strlcpy(Threshold2_IPC[counters_ipc->thresh2_count].ip_dst, dst_tmp, sizeof(Threshold2_IPC[counters_ipc->thresh2_count].ip_dst));
            Threshold2_IPC[counters_ipc->thresh2_count].dst_port = dst_port_tmp;

            strlcpy(Threshold2_IPC[counters_ipc->thresh2_count].username, username_tmp, sizeof(Threshold2_IPC[counters_ipc->thresh2_count].username));

            strlcpy(Threshold2_IPC[counters_ipc->thresh2_count].syslog_message, syslog_message, sizeof(Threshold2_IPC[counters_ipc->thresh2_count].syslog_message));
            strlcpy(Threshold2_IPC[counters_ipc->thresh2_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(Threshold2_IPC[counters_ipc->thresh2_count].signature_msg));

            counters_ipc->thresh2_count++;

            pthread_mutex_unlock(&Thresh2_Mutex);
            File_Unlock(config->shm_thresh2);
        }

    return(false);

}

