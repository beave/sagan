/* $Id$ */
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

/* ipc.c
 *
 * This allows Sagan to share data with other Sagan processes. This is for
 * Inter-process communications (IPC).
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "version.h"
#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "util-time.h"
#include "ipc.h"
#include "xbit-mmap.h"

#include "processors/track-clients.h"

struct _Sagan_IPC_Counters *counters_ipc;
struct _Sagan_IPC_Xbit *xbit_ipc;

struct _SaganConfig *config;

pthread_mutex_t CounterMutex;

pthread_mutex_t After_By_Src_Mutex;
pthread_mutex_t After_By_Dst_Mutex;
pthread_mutex_t After_By_Src_Port_Mutex;
pthread_mutex_t After_By_Dst_Port_Mutex;
pthread_mutex_t After_By_Username_Mutex;

pthread_mutex_t Thresh_By_Src_Mutex;
pthread_mutex_t Thresh_By_Dst_Mutex;
pthread_mutex_t Thresh_By_Src_Port_Mutex;
pthread_mutex_t Thresh_By_Dst_Port_Mutex;
pthread_mutex_t Thresh_By_Username_Mutex;

pthread_mutex_t Xbit_Mutex;

struct thresh_by_src_ipc *threshbysrc_ipc;
struct thresh_by_dst_ipc *threshbydst_ipc;
struct thresh_by_dstport_ipc *threshbydstport_ipc;
struct thresh_by_srcport_ipc *threshbysrcport_ipc;
struct thresh_by_username_ipc *threshbyusername_ipc;

struct after_by_src_ipc *afterbysrc_ipc;
struct after_by_dst_ipc *afterbydst_ipc;
struct after_by_srcport_ipc *afterbysrcport_ipc;
struct after_by_dstport_ipc *afterbydstport_ipc;
struct after_by_username_ipc *afterbyusername_ipc;

struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;

struct _SaganDebug *debug;

/*****************************************************************************
 * Clean_IPC_Object - If the max IPC is hit,  we attempt to "clean" out
 * any stale IPC entries.
 *****************************************************************************/

sbool Clean_IPC_Object( int type )
{

    time_t t;
    struct tm *now;

    int i;
    int utime = 0;
    int new_count = 0;
    int old_count = 0;

    char timet[20];

    if ( debug->debugipc ) {
        Sagan_Log(S_DEBUG, "[%s, %d line] Cleaning IPC data. Type: %d", __FILE__, __LINE__, type);
    }

    /* Afterbysrc_IPC */

    if ( type == AFTER_BY_SRC && config->max_after_by_src < counters_ipc->after_count_by_src ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        File_Lock(config->shm_after_by_src);
        pthread_mutex_lock(&After_By_Src_Mutex);

        struct after_by_src_ipc *temp_afterbysrc_ipc;
        temp_afterbysrc_ipc = malloc(sizeof(struct after_by_src_ipc) * config->max_after_by_src);

        memset(temp_afterbysrc_ipc, 0, sizeof(sizeof(struct after_by_src_ipc) * config->max_after_by_src));

        old_count = counters_ipc->after_count_by_src;

        for (i = 0; i < counters_ipc->after_count_by_src; i++) {
            if ( (utime - afterbysrc_ipc[i].utime) < afterbysrc_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Afterbysrc_IPC : Keeping %u.", __FILE__, __LINE__, afterbysrc_ipc[i].ipsrc);
                }

                temp_afterbysrc_ipc[new_count].ipsrc = afterbysrc_ipc[i].ipsrc;
                temp_afterbysrc_ipc[new_count].count = afterbysrc_ipc[i].count;
                temp_afterbysrc_ipc[new_count].utime = afterbysrc_ipc[i].utime;
                temp_afterbysrc_ipc[new_count].expire = afterbysrc_ipc[i].expire;
                strlcpy(temp_afterbysrc_ipc[new_count].sid, afterbysrc_ipc[i].sid, sizeof(temp_afterbysrc_ipc[new_count].sid));
                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                afterbysrc_ipc[i].ipsrc = temp_afterbysrc_ipc[i].ipsrc;
                afterbysrc_ipc[i].count = temp_afterbysrc_ipc[i].count;
                afterbysrc_ipc[i].utime = temp_afterbysrc_ipc[i].utime;
                afterbysrc_ipc[i].expire = temp_afterbysrc_ipc[i].expire;
                strlcpy(afterbysrc_ipc[i].sid, temp_afterbysrc_ipc[i].sid, sizeof(afterbysrc_ipc[i].sid));
            }

            counters_ipc->after_count_by_src = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean after_by_src.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_afterbysrc_ipc);
            pthread_mutex_unlock(&After_By_Src_Mutex);
            File_Unlock(config->shm_after_by_src);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for after_by_src", __FILE__, __LINE__, new_count, old_count);
        free(temp_afterbysrc_ipc);

        pthread_mutex_unlock(&After_By_Src_Mutex);
        File_Unlock(config->shm_after_by_src);
        return(0);

    }

    /* Afterbydst_IPC */

    else if ( type == AFTER_BY_DST && config->max_after_by_dst < counters_ipc->after_count_by_dst ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_after_by_dst);
        pthread_mutex_lock(&After_By_Dst_Mutex);

        struct after_by_dst_ipc *temp_afterbydst_ipc;
        temp_afterbydst_ipc = malloc(sizeof(struct after_by_dst_ipc) * config->max_after_by_dst);

        memset(temp_afterbydst_ipc, 0, sizeof(sizeof(struct after_by_dst_ipc) * config->max_after_by_dst));

        old_count = counters_ipc->after_count_by_dst;

        for (i = 0; i < counters_ipc->after_count_by_dst; i++) {
            if ( (utime - afterbydst_ipc[i].utime) < afterbydst_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Afterbydst_IPC : Keeping %u.", __FILE__, __LINE__, afterbydst_ipc[i].ipdst);
                }

                temp_afterbydst_ipc[new_count].ipdst = afterbydst_ipc[i].ipdst;
                temp_afterbydst_ipc[new_count].count = afterbydst_ipc[i].count;
                temp_afterbydst_ipc[new_count].utime = afterbydst_ipc[i].utime;
                temp_afterbydst_ipc[new_count].expire = afterbydst_ipc[i].expire;
                strlcpy(temp_afterbydst_ipc[new_count].sid, afterbydst_ipc[i].sid, sizeof(temp_afterbydst_ipc[new_count].sid));
                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                afterbydst_ipc[i].ipdst = temp_afterbydst_ipc[i].ipdst;
                afterbydst_ipc[i].count = temp_afterbydst_ipc[i].count;
                afterbydst_ipc[i].utime = temp_afterbydst_ipc[i].utime;
                afterbydst_ipc[i].expire = temp_afterbydst_ipc[i].expire;
                strlcpy(afterbydst_ipc[i].sid, temp_afterbydst_ipc[i].sid, sizeof(afterbydst_ipc[i].sid));
            }

            counters_ipc->after_count_by_dst = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean after_by_dst.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_afterbydst_ipc);
            pthread_mutex_unlock(&After_By_Dst_Mutex);
            File_Unlock(config->shm_after_by_dst);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for after_by_dst", __FILE__, __LINE__, new_count, old_count);
        free(temp_afterbydst_ipc);

        pthread_mutex_unlock(&After_By_Dst_Mutex);
        File_Unlock(config->shm_after_by_dst);
        return(0);

    }


    /* Afterbysrcport_IPC */

    else if ( type == AFTER_BY_SRCPORT && config->max_after_by_srcport < counters_ipc->after_count_by_srcport ) {
        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_after_by_srcport);
        pthread_mutex_lock(&After_By_Src_Port_Mutex);

        struct after_by_srcport_ipc *temp_afterbysrcport_ipc;
        temp_afterbysrcport_ipc = malloc(sizeof(struct after_by_srcport_ipc) * config->max_after_by_srcport);

        memset(temp_afterbysrcport_ipc, 0, sizeof(sizeof(struct after_by_srcport_ipc) * config->max_after_by_srcport));

        old_count = counters_ipc->after_count_by_srcport;

        for (i = 0; i < counters_ipc->after_count_by_srcport; i++) {
            if ( (utime - afterbysrcport_ipc[i].utime) < afterbysrcport_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Afterbysrcport_IPC : Keeping %u.", __FILE__, __LINE__, afterbysrcport_ipc[i].ipsrcport);
                }

                temp_afterbysrcport_ipc[new_count].ipsrcport = afterbysrcport_ipc[i].ipsrcport;
                temp_afterbysrcport_ipc[new_count].count = afterbysrcport_ipc[i].count;
                temp_afterbysrcport_ipc[new_count].utime = afterbysrcport_ipc[i].utime;
                temp_afterbysrcport_ipc[new_count].expire = afterbysrcport_ipc[i].expire;
                strlcpy(temp_afterbysrcport_ipc[new_count].sid, afterbysrcport_ipc[i].sid, sizeof(temp_afterbysrcport_ipc[new_count].sid));
                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                afterbysrcport_ipc[i].ipsrcport = temp_afterbysrcport_ipc[i].ipsrcport;
                afterbysrcport_ipc[i].count = temp_afterbysrcport_ipc[i].count;
                afterbysrcport_ipc[i].utime = temp_afterbysrcport_ipc[i].utime;
                afterbysrcport_ipc[i].expire = temp_afterbysrcport_ipc[i].expire;
                strlcpy(afterbysrcport_ipc[i].sid, temp_afterbysrcport_ipc[i].sid, sizeof(afterbysrcport_ipc[i].sid));
            }

            counters_ipc->after_count_by_srcport = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean after_by_srcport.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_afterbysrcport_ipc);
            pthread_mutex_unlock(&After_By_Src_Port_Mutex);
            File_Unlock(config->shm_after_by_srcport);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for after_by_srcport", __FILE__, __LINE__, new_count, old_count);
        free(temp_afterbysrcport_ipc);

        pthread_mutex_unlock(&After_By_Src_Port_Mutex);
        File_Unlock(config->shm_after_by_srcport);
        return(0);

    }


    /* Afterbydstport_IPC */

    else if ( type == AFTER_BY_DSTPORT && config->max_after_by_dstport < counters_ipc->after_count_by_dstport ) {
        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_after_by_dstport);
        pthread_mutex_lock(&After_By_Dst_Port_Mutex);

        struct after_by_dstport_ipc *temp_afterbydstport_ipc;
        temp_afterbydstport_ipc = malloc(sizeof(struct after_by_dstport_ipc) * config->max_after_by_dstport);

        memset(temp_afterbydstport_ipc, 0, sizeof(sizeof(struct after_by_dstport_ipc) * config->max_after_by_dstport));

        old_count = counters_ipc->after_count_by_dstport;

        for (i = 0; i < counters_ipc->after_count_by_dstport; i++) {
            if ( (utime - afterbydstport_ipc[i].utime) < afterbydstport_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Afterbydstport_IPC : Keeping %u.", __FILE__, __LINE__, afterbydstport_ipc[i].ipdstport);
                }

                temp_afterbydstport_ipc[new_count].ipdstport = afterbydstport_ipc[i].ipdstport;
                temp_afterbydstport_ipc[new_count].count = afterbydstport_ipc[i].count;
                temp_afterbydstport_ipc[new_count].utime = afterbydstport_ipc[i].utime;
                temp_afterbydstport_ipc[new_count].expire = afterbydstport_ipc[i].expire;
                strlcpy(temp_afterbydstport_ipc[new_count].sid, afterbydstport_ipc[i].sid, sizeof(temp_afterbydstport_ipc[new_count].sid));
                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                afterbydstport_ipc[i].ipdstport = temp_afterbydstport_ipc[i].ipdstport;
                afterbydstport_ipc[i].count = temp_afterbydstport_ipc[i].count;
                afterbydstport_ipc[i].utime = temp_afterbydstport_ipc[i].utime;
                afterbydstport_ipc[i].expire = temp_afterbydstport_ipc[i].expire;
                strlcpy(afterbydstport_ipc[i].sid, temp_afterbydstport_ipc[i].sid, sizeof(afterbydstport_ipc[i].sid));
            }

            counters_ipc->after_count_by_dstport = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean after_by_dstport.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_afterbydstport_ipc);
            pthread_mutex_unlock(&After_By_Dst_Port_Mutex);
            File_Unlock(config->shm_after_by_dstport);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for after_by_dstport", __FILE__, __LINE__, new_count, old_count);
        free(temp_afterbydstport_ipc);

        pthread_mutex_unlock(&After_By_Dst_Port_Mutex);
        File_Unlock(config->shm_after_by_dstport);
        return(0);

    }

    /* AfterbyUsername_IPC */

    else if ( type == AFTER_BY_USERNAME && config->max_after_by_username < counters_ipc->after_count_by_username ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_after_by_username);
        pthread_mutex_lock(&After_By_Username_Mutex);

        struct after_by_username_ipc *temp_afterbyusername_ipc;
        temp_afterbyusername_ipc = malloc(sizeof(struct after_by_username_ipc) * config->max_after_by_username);

        memset(temp_afterbyusername_ipc, 0, sizeof(sizeof(struct after_by_username_ipc) * config->max_after_by_username));

        old_count = counters_ipc->after_count_by_username;

        for (i = 0; i < counters_ipc->after_count_by_username; i++) {
            if ( (utime - afterbyusername_ipc[i].utime) < afterbyusername_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Afterbyusername_IPC : Keeping '%s'.", __FILE__, __LINE__, afterbyusername_ipc[i].username);
                }

                temp_afterbyusername_ipc[new_count].count = afterbyusername_ipc[i].count;
                temp_afterbyusername_ipc[new_count].utime = afterbyusername_ipc[i].utime;
                temp_afterbyusername_ipc[new_count].expire = afterbyusername_ipc[i].expire;
                strlcpy(temp_afterbyusername_ipc[new_count].sid, afterbyusername_ipc[i].sid, sizeof(temp_afterbyusername_ipc[new_count].sid));
                strlcpy(temp_afterbyusername_ipc[new_count].username, afterbyusername_ipc[i].username, sizeof(temp_afterbyusername_ipc[new_count].username));

                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                afterbyusername_ipc[i].count = temp_afterbyusername_ipc[i].count;
                afterbyusername_ipc[i].utime = temp_afterbyusername_ipc[i].utime;
                afterbyusername_ipc[i].expire = temp_afterbyusername_ipc[i].expire;
                strlcpy(afterbyusername_ipc[i].sid, temp_afterbyusername_ipc[i].sid, sizeof(afterbyusername_ipc[i].sid));
                strlcpy(afterbyusername_ipc[i].username, temp_afterbyusername_ipc[i].username, sizeof(afterbyusername_ipc[i].username));
            }

            counters_ipc->after_count_by_username = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean after_by_username.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_afterbyusername_ipc);
            pthread_mutex_unlock(&After_By_Username_Mutex);
            File_Unlock(config->shm_after_by_username);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for after_by_username", __FILE__, __LINE__, new_count, old_count);
        free(temp_afterbyusername_ipc);

        pthread_mutex_unlock(&After_By_Username_Mutex);
        File_Unlock(config->shm_after_by_username);
        return(0);
    }

    /* Threshbysrc_IPC */

    else if ( type == THRESH_BY_SRC && config->max_threshold_by_src < counters_ipc->thresh_count_by_src ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_thresh_by_src);
        pthread_mutex_lock(&Thresh_By_Src_Mutex);

        struct thresh_by_src_ipc *temp_threshbysrc_ipc;
        temp_threshbysrc_ipc = malloc(sizeof(struct thresh_by_src_ipc) * config->max_threshold_by_src);

        memset(temp_threshbysrc_ipc, 0, sizeof(sizeof(struct thresh_by_src_ipc) * config->max_threshold_by_src));

        old_count = counters_ipc->thresh_count_by_src;

        for (i = 0; i < counters_ipc->thresh_count_by_src; i++) {
            if ( (utime - threshbysrc_ipc[i].utime) < threshbysrc_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Threshbysrc_IPC : Keeping %u.", __FILE__, __LINE__, threshbysrc_ipc[i].ipsrc);
                }

                temp_threshbysrc_ipc[new_count].ipsrc = threshbysrc_ipc[i].ipsrc;
                temp_threshbysrc_ipc[new_count].count = threshbysrc_ipc[i].count;
                temp_threshbysrc_ipc[new_count].utime = threshbysrc_ipc[i].utime;
                temp_threshbysrc_ipc[new_count].expire = threshbysrc_ipc[i].expire;
                strlcpy(temp_threshbysrc_ipc[new_count].sid, threshbysrc_ipc[i].sid, sizeof(temp_threshbysrc_ipc[new_count].sid));
                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                threshbysrc_ipc[i].ipsrc = temp_threshbysrc_ipc[i].ipsrc;
                threshbysrc_ipc[i].count = temp_threshbysrc_ipc[i].count;
                threshbysrc_ipc[i].utime = temp_threshbysrc_ipc[i].utime;
                threshbysrc_ipc[i].expire = temp_threshbysrc_ipc[i].expire;
                strlcpy(threshbysrc_ipc[i].sid, temp_threshbysrc_ipc[i].sid, sizeof(threshbysrc_ipc[i].sid));
            }

            counters_ipc->thresh_count_by_src = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean thresh_by_src.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_threshbysrc_ipc);
            pthread_mutex_unlock(&Thresh_By_Src_Mutex);
            File_Unlock(config->shm_thresh_by_src);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for thresh_by_src", __FILE__, __LINE__, new_count, old_count);
        free(temp_threshbysrc_ipc);

        pthread_mutex_unlock(&Thresh_By_Src_Mutex);
        File_Unlock(config->shm_thresh_by_src);
        return(0);

    }


    /* Threshbydst_IPC */

    else if ( type == THRESH_BY_SRC && config->max_threshold_by_dst < counters_ipc->thresh_count_by_dst ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_thresh_by_dst);
        pthread_mutex_lock(&Thresh_By_Dst_Mutex);

        struct thresh_by_dst_ipc *temp_threshbydst_ipc;
        temp_threshbydst_ipc = malloc(sizeof(struct thresh_by_dst_ipc) * config->max_threshold_by_dst);

        memset(temp_threshbydst_ipc, 0, sizeof(sizeof(struct thresh_by_dst_ipc) * config->max_threshold_by_dst));

        old_count = counters_ipc->thresh_count_by_dst;

        for (i = 0; i < counters_ipc->thresh_count_by_dst; i++) {
            if ( (utime - threshbydst_ipc[i].utime) < threshbydst_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Threshbydst_IPC : Keeping %u.", __FILE__, __LINE__, threshbydst_ipc[i].ipdst);
                }

                temp_threshbydst_ipc[new_count].ipdst = threshbydst_ipc[i].ipdst;
                temp_threshbydst_ipc[new_count].count = threshbydst_ipc[i].count;
                temp_threshbydst_ipc[new_count].utime = threshbydst_ipc[i].utime;
                temp_threshbydst_ipc[new_count].expire = threshbydst_ipc[i].expire;
                strlcpy(temp_threshbydst_ipc[new_count].sid, threshbydst_ipc[i].sid, sizeof(temp_threshbydst_ipc[new_count].sid));
                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                threshbydst_ipc[i].ipdst = temp_threshbydst_ipc[i].ipdst;
                threshbydst_ipc[i].count = temp_threshbydst_ipc[i].count;
                threshbydst_ipc[i].utime = temp_threshbydst_ipc[i].utime;
                threshbydst_ipc[i].expire = temp_threshbydst_ipc[i].expire;
                strlcpy(threshbydst_ipc[i].sid, temp_threshbydst_ipc[i].sid, sizeof(threshbydst_ipc[i].sid));
            }

            counters_ipc->thresh_count_by_dst = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean thresh_by_dst.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_threshbydst_ipc);
            pthread_mutex_unlock(&Thresh_By_Dst_Mutex);
            File_Unlock(config->shm_thresh_by_dst);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for thresh_by_dst", __FILE__, __LINE__, new_count, old_count);
        free(temp_threshbydst_ipc);

        pthread_mutex_unlock(&Thresh_By_Dst_Mutex);
        File_Unlock(config->shm_thresh_by_dst);
        return(0);

    }


    /* Threshbysrcport_IPC */

    else if ( type == THRESH_BY_SRCPORT && config->max_threshold_by_srcport < counters_ipc->thresh_count_by_srcport ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_thresh_by_srcport);
        pthread_mutex_lock(&Thresh_By_Src_Port_Mutex);

        struct thresh_by_srcport_ipc *temp_threshbysrcport_ipc;
        temp_threshbysrcport_ipc = malloc(sizeof(struct thresh_by_srcport_ipc) * config->max_threshold_by_srcport);

        memset(temp_threshbysrcport_ipc, 0, sizeof(sizeof(struct thresh_by_srcport_ipc) * config->max_threshold_by_srcport));

        old_count = counters_ipc->thresh_count_by_srcport;

        for (i = 0; i < counters_ipc->thresh_count_by_src; i++) {
            if ( (utime - threshbysrc_ipc[i].utime) < threshbysrc_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Threshbysrcport_IPC : Keeping %u.", __FILE__, __LINE__, threshbysrcport_ipc[i].ipsrcport);
                }

                temp_threshbysrcport_ipc[new_count].ipsrcport = threshbysrcport_ipc[i].ipsrcport;
                temp_threshbysrcport_ipc[new_count].count = threshbysrcport_ipc[i].count;
                temp_threshbysrcport_ipc[new_count].utime = threshbysrcport_ipc[i].utime;
                temp_threshbysrcport_ipc[new_count].expire = threshbysrcport_ipc[i].expire;
                strlcpy(temp_threshbysrcport_ipc[new_count].sid, threshbysrcport_ipc[i].sid, sizeof(temp_threshbysrcport_ipc[new_count].sid));
                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                threshbysrcport_ipc[i].ipsrcport = temp_threshbysrcport_ipc[i].ipsrcport;
                threshbysrcport_ipc[i].count = temp_threshbysrcport_ipc[i].count;
                threshbysrcport_ipc[i].utime = temp_threshbysrcport_ipc[i].utime;
                threshbysrcport_ipc[i].expire = temp_threshbysrcport_ipc[i].expire;
                strlcpy(threshbysrcport_ipc[i].sid, temp_threshbysrcport_ipc[i].sid, sizeof(threshbysrcport_ipc[i].sid));
            }

            counters_ipc->thresh_count_by_srcport = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean thresh_by_srcport.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_threshbysrcport_ipc);
            pthread_mutex_unlock(&Thresh_By_Src_Port_Mutex);
            File_Unlock(config->shm_thresh_by_src);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for thresh_by_srcport", __FILE__, __LINE__, new_count, old_count);
        free(temp_threshbysrcport_ipc);

        pthread_mutex_unlock(&Thresh_By_Src_Port_Mutex);
        File_Unlock(config->shm_thresh_by_srcport);
        return(0);

    }


    /* Threshbydstport_IPC */

    else if ( type == THRESH_BY_DSTPORT && config->max_threshold_by_dstport < counters_ipc->thresh_count_by_dstport ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_thresh_by_dstport);
        pthread_mutex_lock(&Thresh_By_Dst_Port_Mutex);

        struct thresh_by_dstport_ipc *temp_threshbydstport_ipc;
        temp_threshbydstport_ipc = malloc(sizeof(struct thresh_by_dstport_ipc) * config->max_threshold_by_dstport);

        memset(temp_threshbydstport_ipc, 0, sizeof(sizeof(struct thresh_by_dstport_ipc) * config->max_threshold_by_dstport));

        old_count = counters_ipc->thresh_count_by_dstport;

        for (i = 0; i < counters_ipc->thresh_count_by_dst; i++) {
            if ( (utime - threshbydst_ipc[i].utime) < threshbydst_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Threshbydstport_IPC : Keeping %u.", __FILE__, __LINE__, threshbydstport_ipc[i].ipdstport);
                }

                temp_threshbydstport_ipc[new_count].ipdstport = threshbydstport_ipc[i].ipdstport;
                temp_threshbydstport_ipc[new_count].count = threshbydstport_ipc[i].count;
                temp_threshbydstport_ipc[new_count].utime = threshbydstport_ipc[i].utime;
                temp_threshbydstport_ipc[new_count].expire = threshbydstport_ipc[i].expire;
                strlcpy(temp_threshbydstport_ipc[new_count].sid, threshbydstport_ipc[i].sid, sizeof(temp_threshbydstport_ipc[new_count].sid));
                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                threshbydstport_ipc[i].ipdstport = temp_threshbydstport_ipc[i].ipdstport;
                threshbydstport_ipc[i].count = temp_threshbydstport_ipc[i].count;
                threshbydstport_ipc[i].utime = temp_threshbydstport_ipc[i].utime;
                threshbydstport_ipc[i].expire = temp_threshbydstport_ipc[i].expire;
                strlcpy(threshbydstport_ipc[i].sid, temp_threshbydstport_ipc[i].sid, sizeof(threshbydstport_ipc[i].sid));
            }

            counters_ipc->thresh_count_by_dstport = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean thresh_by_dstport.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_threshbydstport_ipc);
            pthread_mutex_unlock(&Thresh_By_Dst_Port_Mutex);
            File_Unlock(config->shm_thresh_by_dst);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for thresh_by_dstport", __FILE__, __LINE__, new_count, old_count);
        free(temp_threshbydstport_ipc);

        pthread_mutex_unlock(&Thresh_By_Dst_Port_Mutex);
        File_Unlock(config->shm_thresh_by_dstport);
        return(0);

    }

    /* ThreshbyUsername_IPC */

    else if ( type == THRESH_BY_USERNAME && config->max_threshold_by_username < counters_ipc->thresh_count_by_username ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_thresh_by_username);
        pthread_mutex_lock(&Thresh_By_Username_Mutex);

        struct thresh_by_username_ipc *temp_threshbyusername_ipc;
        temp_threshbyusername_ipc = malloc(sizeof(struct thresh_by_username_ipc) * config->max_threshold_by_username);

        memset(temp_threshbyusername_ipc, 0, sizeof(sizeof(struct thresh_by_username_ipc) * config->max_threshold_by_username));

        old_count = counters_ipc->thresh_count_by_username;

        for (i = 0; i < counters_ipc->thresh_count_by_username; i++) {
            if ( (utime - threshbyusername_ipc[i].utime) < threshbyusername_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Afterbyusername_IPC : Keeping '%s'.", __FILE__, __LINE__, threshbyusername_ipc[i].username);
                }

                temp_threshbyusername_ipc[new_count].count = threshbyusername_ipc[i].count;
                temp_threshbyusername_ipc[new_count].utime = threshbyusername_ipc[i].utime;
                temp_threshbyusername_ipc[new_count].expire = threshbyusername_ipc[i].expire;
                strlcpy(temp_threshbyusername_ipc[new_count].sid, threshbyusername_ipc[i].sid, sizeof(temp_threshbyusername_ipc[new_count].sid));
                strlcpy(temp_threshbyusername_ipc[new_count].username, threshbyusername_ipc[i].username, sizeof(temp_threshbyusername_ipc[new_count].username));

                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                threshbyusername_ipc[i].count = temp_threshbyusername_ipc[i].count;
                threshbyusername_ipc[i].utime = temp_threshbyusername_ipc[i].utime;
                threshbyusername_ipc[i].expire = temp_threshbyusername_ipc[i].expire;
                strlcpy(threshbyusername_ipc[i].sid, temp_threshbyusername_ipc[i].sid, sizeof(threshbyusername_ipc[i].sid));
                strlcpy(threshbyusername_ipc[i].username, temp_threshbyusername_ipc[i].username, sizeof(threshbyusername_ipc[i].username));
            }

            counters_ipc->thresh_count_by_username = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean thresh_by_username.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_threshbyusername_ipc);
            pthread_mutex_unlock(&Thresh_By_Username_Mutex);
            File_Unlock(config->shm_thresh_by_username);
            return(1);

        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for thresh_by_username", __FILE__, __LINE__, new_count, old_count);
        free(temp_threshbyusername_ipc);

        pthread_mutex_unlock(&Thresh_By_Username_Mutex);
        File_Unlock(config->shm_thresh_by_username);
        return(0);
    }

    /* Xbit_IPC */

    else if ( type == XBIT && config->max_xbits < counters_ipc->xbit_count ) {

        t = time(NULL);
        now=localtime(&t);
        strftime(timet, sizeof(timet), "%s",  now);
        utime = atol(timet);

        new_count = 0;
        old_count = 0;

        File_Lock(config->shm_xbit);
        pthread_mutex_lock(&Xbit_Mutex);

        struct _Sagan_IPC_Xbit *temp_xbit_ipc;
        temp_xbit_ipc = malloc(sizeof(struct _Sagan_IPC_Xbit) * config->max_xbits);

        memset(temp_xbit_ipc, 0, sizeof(sizeof(struct _Sagan_IPC_Xbit) * config->max_xbits));

        old_count = counters_ipc->xbit_count;

        for (i = 0; i < counters_ipc->xbit_count; i++) {
            if ( (utime - xbit_ipc[i].xbit_expire) < xbit_ipc[i].expire ) {

                if ( debug->debugipc ) {
                    Sagan_Log(S_DEBUG, "[%s, %d line] Flowbot_IPC : Keeping '%s'.", __FILE__, __LINE__, xbit_ipc[i].ip_src, xbit_ipc[i].ip_dst);
                }

                temp_xbit_ipc[new_count].xbit_state = xbit_ipc[i].xbit_state;
                temp_xbit_ipc[new_count].ip_src = xbit_ipc[i].ip_src;
                temp_xbit_ipc[new_count].ip_dst = xbit_ipc[i].ip_dst;
                temp_xbit_ipc[new_count].xbit_expire = xbit_ipc[i].xbit_expire;
                temp_xbit_ipc[new_count].expire = xbit_ipc[i].expire;
                strlcpy(temp_xbit_ipc[new_count].xbit_name, xbit_ipc[i].xbit_name, sizeof(temp_xbit_ipc[new_count].xbit_name));

                new_count++;
            }
        }

        if ( new_count > 0 ) {
            for ( i = 0; i < new_count; i++ ) {
                xbit_ipc[i].xbit_state = temp_xbit_ipc[i].xbit_state;
                xbit_ipc[i].ip_src = temp_xbit_ipc[i].ip_src;
                xbit_ipc[i].ip_dst = temp_xbit_ipc[i].ip_dst;
                xbit_ipc[i].xbit_expire = temp_xbit_ipc[i].xbit_expire;
                xbit_ipc[i].expire = temp_xbit_ipc[i].expire;
                strlcpy(xbit_ipc[i].xbit_name, temp_xbit_ipc[i].xbit_name, sizeof(xbit_ipc[i].xbit_name));
            }

            counters_ipc->xbit_count = new_count;

        } else {

            Sagan_Log(S_WARN, "[%s, line %d] Could not clean _Sagan_IPC_Xbit.  Nothing to remove!", __FILE__, __LINE__);
            free(temp_xbit_ipc);
            pthread_mutex_unlock(&Xbit_Mutex);
            File_Unlock(config->shm_xbit);
            return(1);
        }

        Sagan_Log(S_NORMAL, "[%s, line %d] Kept %d elements out of %d for _Sagan_IPC_Xbit.", __FILE__, __LINE__, new_count, old_count);
        free(temp_xbit_ipc);

        pthread_mutex_unlock(&Xbit_Mutex);
        File_Unlock(config->shm_xbit);
        return(0);

    }

    return(0);

}
/*****************************************************************************
 * IPC_Check_Object - If "counters" have been reset,   we want to
 * recreate the other objects (hence the unlink).  This function tests for
 * this case
 *****************************************************************************/

void IPC_Check_Object(char *tmp_object_check, sbool new_counters, char *object_name)
{

    struct stat object_check;

    if ( ( stat(tmp_object_check, &object_check) == 0 ) && new_counters == 1 ) {
        if ( unlink(tmp_object_check) == -1 ) {
            Sagan_Log(S_ERROR, "[%s, line %d] Could not unlink %s memory object! [%s]", __FILE__, __LINE__, object_name, strerror(errno));
        }

        Sagan_Log(S_NORMAL, "* Stale %s memory object found & unlinked.", object_name);
    }
}

/*****************************************************************************
 * IPC_Init - Create (if needed) or map to an IPC object.
 *****************************************************************************/

void IPC_Init(void)
{

    /* If we have a "new" counters shared memory object,  but other "old" data,  we need to remove
     * the "old" data!  The counters need to stay in sync with the other data objects! */

    sbool new_counters = 0;
    sbool new_object = 0;
    int i;

    char tmp_object_check[255];
    char time_buf[80];

    /* For convert 32 bit IP to octet */

    struct in_addr ip_addr_src;
    struct in_addr ip_addr_dst;

    Sagan_Log(S_NORMAL, "Initializing shared memory objects.");
    Sagan_Log(S_NORMAL, "---------------------------------------------------------------------------");

    /* Init counters first.  Need to track all other share memory objects */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, COUNTERS_IPC_FILE);

    if ((config->shm_counters = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ Counters shared object (new).");
        new_counters = 1;

    }

    else if ((config->shm_counters = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for counters. [%s:%s]", __FILE__, __LINE__, tmp_object_check, strerror(errno));
    } else {
        Sagan_Log(S_NORMAL, "- Counters shared object (reload)");
    }


    if ( ftruncate(config->shm_counters, sizeof(_Sagan_IPC_Counters)) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate counters. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( counters_ipc = mmap(0, sizeof(_Sagan_IPC_Counters), (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_counters, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for counters object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    /* Xbit memory object */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, XBIT_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "xbit");

    if ((config->shm_xbit = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ Xbit shared object (new).");
        new_object=1;
    }

    else if ((config->shm_xbit = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for xbit (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
    }

    if ( ftruncate(config->shm_xbit, sizeof(_Sagan_IPC_Xbit) * config->max_xbits ) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate xbit. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( xbit_ipc = mmap(0, sizeof(_Sagan_IPC_Xbit) * config->max_xbits, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_xbit, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for xbit object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0) {
        Sagan_Log(S_NORMAL, "- Xbit shared object reloaded (%d xbits loaded / max: %d).", counters_ipc->xbit_count, config->max_xbits);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->xbit_count >= 1 ) {

        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** Xbits ***");
        Sagan_Log(S_DEBUG, "------------------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-2s| %-25s| %-16s| %-16s| %-21s| %s", "S", "Xbit name", "SRC IP", "DST IP", "Date added/modified", "Expire");
        Sagan_Log(S_DEBUG, "------------------------------------------------------------------------------------------------");


        for (i= 0; i < counters_ipc->xbit_count; i++ ) {

            ip_addr_src.s_addr = htonl(xbit_ipc[i].ip_src);
            ip_addr_dst.s_addr = htonl(xbit_ipc[i].ip_dst);

            if ( xbit_ipc[i].xbit_state == 1 ) {

                u32_Time_To_Human(xbit_ipc[i].xbit_expire, time_buf, sizeof(time_buf));

                Sagan_Log(S_DEBUG, "%-2d| %-25s| %-16s| %-16s| %-21s| %d", xbit_ipc[i].xbit_state, xbit_ipc[i].xbit_name, inet_ntoa(ip_addr_src), inet_ntoa(ip_addr_dst), time_buf, xbit_ipc[i].expire );
            }

        }
        Sagan_Log(S_DEBUG, "");
    }

    /* Threshold by source */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, THRESH_BY_SRC_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "thresh_by_src");

    if ((config->shm_thresh_by_src = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ Thresh_by_src shared object (new).");
        new_object=1;
    }

    else if ((config->shm_thresh_by_src = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for thresh_by_src (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
    }

    if ( ftruncate(config->shm_thresh_by_src, sizeof(thresh_by_src_ipc) * config->max_threshold_by_src ) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate thresh_by_src. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( threshbysrc_ipc = mmap(0, sizeof(thresh_by_src_ipc) * config->max_threshold_by_src, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh_by_src, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for thresh_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0) {
        Sagan_Log(S_NORMAL, "- Thresh_by_src shared object reloaded (%d sources loaded / max: %d).", counters_ipc->thresh_count_by_src, config->max_threshold_by_src);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->thresh_count_by_src >= 1 ) {

        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** Threshold by source ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "SRC IP", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->thresh_count_by_src; i++) {

            ip_addr_src.s_addr = htonl(threshbysrc_ipc[i].ipsrc);

            u32_Time_To_Human(threshbysrc_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16s| %-11d| %-21s| %-11s| %d", inet_ntoa(ip_addr_src), threshbysrc_ipc[i].count, time_buf, threshbysrc_ipc[i].sid, threshbysrc_ipc[i].expire);

        }

        Sagan_Log(S_DEBUG, "");
    }

    /* Threshold by destination */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, THRESH_BY_DST_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "thresh_by_dst");

    if ((config->shm_thresh_by_dst = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ Thresh_by_dst shared object (new).");
        new_object=1;
    }

    else if ((config->shm_thresh_by_dst = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for thresh_by_dst (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
    }

    if ( ftruncate(config->shm_thresh_by_dst, sizeof(thresh_by_dst_ipc) * config->max_threshold_by_dst) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate thresh_by_dst. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( threshbydst_ipc = mmap(0, sizeof(thresh_by_dst_ipc) * config->max_threshold_by_dst, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh_by_dst, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for thresh_by_dst object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0) {
        Sagan_Log(S_NORMAL, "- Thresh_by_dst shared object reloaded (%d destinations loaded / max: %d).", counters_ipc->thresh_count_by_dst, config->max_threshold_by_dst);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->thresh_count_by_dst >= 1 ) {

        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** Threshold by destination ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "DST IP", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->thresh_count_by_dst; i++) {

            ip_addr_dst.s_addr = htonl(threshbydst_ipc[i].ipdst);

            u32_Time_To_Human(threshbydst_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16s| %-11d| %-21s| %-11s| %d", inet_ntoa(ip_addr_dst), threshbydst_ipc[i].count, time_buf, threshbydst_ipc[i].sid, threshbydst_ipc[i].expire);

        }

        Sagan_Log(S_DEBUG, "");
    }


    /* Threshold by source port */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, THRESH_BY_SRCPORT_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "thresh_by_srcport");

    if ((config->shm_thresh_by_srcport = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ Thresh_by_srcport shared object (new).");
        new_object=1;
    }

    else if ((config->shm_thresh_by_srcport = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for thresh_by_srcport (%s)", __FILE__, __LINE__, strerror(errno));
    }

    if ( ftruncate(config->shm_thresh_by_srcport, sizeof(thresh_by_srcport_ipc) * config->max_threshold_by_srcport) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate thresh_by_srcport. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( threshbysrcport_ipc = mmap(0, sizeof(thresh_by_srcport_ipc) * config->max_threshold_by_srcport, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh_by_srcport, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for thresh_by_srcport object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0) {
        Sagan_Log(S_NORMAL, "- Thresh_by_srcport shared object reloaded (%d source ports loaded / max: %d).", counters_ipc->thresh_count_by_srcport, config->max_threshold_by_srcport);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->thresh_count_by_srcport >= 1 ) {

        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** Threshold by source port ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "SRCPORT IP", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->thresh_count_by_srcport; i++) {

            uint32_t srcport = htonl(threshbysrcport_ipc[i].ipsrcport);

            u32_Time_To_Human(threshbysrcport_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16d| %-11d| %-21s| %-11s| %d", srcport, threshbysrcport_ipc[i].count, time_buf, threshbysrcport_ipc[i].sid, threshbysrcport_ipc[i].expire);

        }

        Sagan_Log(S_DEBUG, "");
    }




    /* Threshold by destination port */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, THRESH_BY_DSTPORT_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "thresh_by_dstport");

    if ((config->shm_thresh_by_dstport = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ Thresh_by_dstport shared object (new).");
        new_object=1;
    }

    else if ((config->shm_thresh_by_dstport = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for thresh_by_dstport (%s)", __FILE__, __LINE__, strerror(errno));
    }

    if ( ftruncate(config->shm_thresh_by_dstport, sizeof(thresh_by_dstport_ipc) * config->max_threshold_by_dstport) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate thresh_by_dstport. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( threshbydstport_ipc = mmap(0, sizeof(thresh_by_dstport_ipc) * config->max_threshold_by_dstport, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh_by_dstport, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for thresh_by_dstport object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0) {
        Sagan_Log(S_NORMAL, "- Thresh_by_dstport shared object reloaded (%d destination ports loaded / max: %d).", counters_ipc->thresh_count_by_dstport, config->max_threshold_by_dstport);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->thresh_count_by_dstport >= 1 ) {

        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** Threshold by destination port ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "DSTPORT IP", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->thresh_count_by_dstport; i++) {

            uint32_t dstport = htonl(threshbydstport_ipc[i].ipdstport);

            u32_Time_To_Human(threshbydstport_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16d| %-11d| %-21s| %-11s| %d", dstport, threshbydstport_ipc[i].count, time_buf, threshbydstport_ipc[i].sid, threshbydstport_ipc[i].expire);

        }

        Sagan_Log(S_DEBUG, "");
    }


    /* Threshold by username */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, THRESH_BY_USERNAME_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "thresh_by_username");

    if ((config->shm_thresh_by_username = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ Thresh_by_username shared object (new).");
        new_object=1;
    }

    else if ((config->shm_thresh_by_username = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for thresh_by_username (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
    }

    if ( ftruncate(config->shm_thresh_by_username, sizeof(thresh_by_username_ipc) * config->max_threshold_by_username ) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate thresh_by_username. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( threshbyusername_ipc = mmap(0, sizeof(thresh_by_username_ipc) * config->max_threshold_by_username, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh_by_username, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for thresh_by_username object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0 ) {
        Sagan_Log(S_NORMAL, "- Thresh_by_username shared object reloaded (%d usernames loaded / max: %d).", counters_ipc->thresh_count_by_username, config->max_threshold_by_username);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->thresh_count_by_username >= 1 ) {
        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** Threshold by username ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "Username", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->thresh_count_by_username; i++) {

            u32_Time_To_Human(threshbyusername_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16s| %-11d| %-21s| %-11s| %d", threshbyusername_ipc[i].username, threshbyusername_ipc[i].count, time_buf, threshbyusername_ipc[i].sid, threshbyusername_ipc[i].expire);
        }

    }

    /* After by source */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, AFTER_BY_SRC_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "after_by_src");

    if ((config->shm_after_by_src = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ After_by_src shared object (new).");
        new_object=1;
    }

    else if ((config->shm_after_by_src = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for after_by_src (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
    }

    if ( ftruncate(config->shm_after_by_src, sizeof(after_by_src_ipc) * config->max_after_by_src ) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate after_by_src. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( afterbysrc_ipc = mmap(0, sizeof(after_by_src_ipc) * config->max_after_by_src, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after_by_src, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for after_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0 ) {
        Sagan_Log(S_NORMAL, "- After_by_src shared object reloaded (%d sources loaded / max: %d).", counters_ipc->after_count_by_src, config->max_after_by_src);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->after_count_by_src >= 1 ) {

        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** After by source ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "SRC IP", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->after_count_by_src; i++ ) {

            ip_addr_src.s_addr = htonl(afterbysrc_ipc[i].ipsrc);

            u32_Time_To_Human(afterbysrc_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16s| %-11d| %-21s| %-11s| %d", inet_ntoa(ip_addr_src), afterbysrc_ipc[i].count, time_buf, afterbysrc_ipc[i].sid, afterbysrc_ipc[i].expire);
        }

        Sagan_Log(S_DEBUG, "");
    }

    /* After by destination */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, AFTER_BY_DST_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "after_by_dst");

    if ((config->shm_after_by_dst = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ After_by_dst shared object (new).");
        new_object=1;
    }

    else if ((config->shm_after_by_dst = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for after_by_dst (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
    }

    if ( ftruncate(config->shm_after_by_dst, sizeof(after_by_dst_ipc) * config->max_after_by_dst) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate after_by_dst. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( afterbydst_ipc = mmap(0, sizeof(after_by_dst_ipc) * config->max_after_by_dst, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after_by_dst, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for after_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0 ) {
        Sagan_Log(S_NORMAL, "- After_by_dst shared object reloaded (%d destinations loaded / max: %d).", counters_ipc->after_count_by_dst, config->max_after_by_dst);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->after_count_by_dst >= 1 ) {
        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** After by destination ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "DST IP", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->after_count_by_dst; i++) {

            ip_addr_dst.s_addr = htonl(afterbydst_ipc[i].ipdst);

            u32_Time_To_Human(afterbydst_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16s| %-11d| %-21s| %-11s| %d", inet_ntoa(ip_addr_dst), afterbydst_ipc[i].count, time_buf, afterbydst_ipc[i].sid, afterbydst_ipc[i].expire);
        }

        Sagan_Log(S_DEBUG, "");
    }


    /* After by source port */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, AFTER_BY_SRCPORT_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "after_by_srcport");

    if ((config->shm_after_by_srcport = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ After_by_srcport shared object (new).");
        new_object=1;
    }

    else if ((config->shm_after_by_srcport = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for after_by_srcport (%s)", __FILE__, __LINE__, strerror(errno));
    }

    if ( ftruncate(config->shm_after_by_srcport, sizeof(after_by_srcport_ipc) * config->max_after_by_srcport) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate after_by_srcport. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( afterbysrcport_ipc = mmap(0, sizeof(after_by_srcport_ipc) * config->max_after_by_srcport, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after_by_srcport, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for after_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0 ) {
        Sagan_Log(S_NORMAL, "- After_by_srcport shared object reloaded (%d source ports loaded / max: %d).", counters_ipc->after_count_by_srcport, config->max_after_by_srcport);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->after_count_by_srcport >= 1 ) {
        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** After by source port ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "SRCPORT", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->after_count_by_srcport; i++) {

            uint32_t srcport = htonl(afterbysrcport_ipc[i].ipsrcport);

            u32_Time_To_Human(afterbysrcport_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16d| %-11d| %-21s| %-11s| %d", srcport, afterbysrcport_ipc[i].count, time_buf, afterbysrcport_ipc[i].sid, afterbysrcport_ipc[i].expire);
        }

        Sagan_Log(S_DEBUG, "");
    }


    /* After by destination port */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, AFTER_BY_DSTPORT_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "after_by_dstport");

    if ((config->shm_after_by_dstport = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ After_by_dstport shared object (new).");
        new_object=1;
    }

    else if ((config->shm_after_by_dstport = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for after_by_dstport (%s)", __FILE__, __LINE__, strerror(errno));
    }

    if ( ftruncate(config->shm_after_by_dstport, sizeof(after_by_dstport_ipc) * config->max_after_by_dstport) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate after_by_dstport. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( afterbydstport_ipc = mmap(0, sizeof(after_by_dstport_ipc) * config->max_after_by_dstport, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after_by_dstport, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for after_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0 ) {
        Sagan_Log(S_NORMAL, "- After_by_dstport shared object reloaded (%d destinations ports loaded / max: %d).", counters_ipc->after_count_by_dstport, config->max_after_by_dstport);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->after_count_by_dstport >= 1 ) {
        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** After by destination port ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "DSTPORT", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->after_count_by_dstport; i++) {

            uint32_t dstport = htonl(afterbydstport_ipc[i].ipdstport);

            u32_Time_To_Human(afterbydstport_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16d| %-11d| %-21s| %-11s| %d", dstport, afterbydstport_ipc[i].count, time_buf, afterbydstport_ipc[i].sid, afterbydstport_ipc[i].expire);
        }

        Sagan_Log(S_DEBUG, "");
    }

    /* After by username */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, AFTER_BY_USERNAME_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "after_by_username");

    if ((config->shm_after_by_username = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
        Sagan_Log(S_NORMAL, "+ After_by_username shared object (new).");
        new_object=1;
    }

    else if ((config->shm_after_by_username = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for after_by_username (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
    }

    if ( ftruncate(config->shm_after_by_username, sizeof(after_by_username_ipc) * config->max_after_by_username ) != 0 ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate after_by_username. [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if (( afterbyusername_ipc = mmap(0, sizeof(after_by_username_ipc) * config->max_after_by_username, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after_by_username, 0)) == MAP_FAILED ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for after_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
    }

    if ( new_object == 0 ) {
        Sagan_Log(S_NORMAL, "- After_by_username shared object reloaded (%d usernames loaded / max: %d).", counters_ipc->after_count_by_username, config->max_after_by_username);
    }

    new_object = 0;

    if ( debug->debugipc && counters_ipc->after_count_by_username >= 1 ) {
        Sagan_Log(S_DEBUG, "");
        Sagan_Log(S_DEBUG, "*** After by username ***");
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
        Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "Username", "Counter","Date added/modified", "SID", "Expire" );
        Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

        for ( i = 0; i < counters_ipc->after_count_by_username; i++) {

            u32_Time_To_Human(afterbyusername_ipc[i].utime, time_buf, sizeof(time_buf));

            Sagan_Log(S_DEBUG, "%-16s| %-11d| %-21s| %-11s| %d", afterbyusername_ipc[i].username, afterbyusername_ipc[i].count, time_buf, afterbyusername_ipc[i].sid, afterbyusername_ipc[i].expire);
        }

        Sagan_Log(S_DEBUG, "");
    }

    /* Client tracking */

    if ( config->sagan_track_clients_flag ) {

        snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, CLIENT_TRACK_IPC_FILE);

        IPC_Check_Object(tmp_object_check, new_counters, "_Sagan_Track_Clients_IPC");

        if ((config->shm_track_clients = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 ) {
            Sagan_Log(S_NORMAL, "+ Sagan_track_clients shared object (new).");
            new_object=1;

            /* Reset any track_clients_client_count's to 0! */

            File_Lock(config->shm_counters);
            counters_ipc->track_clients_client_count = 0;
            counters_ipc->track_clients_down = 0;
            File_Unlock(config->shm_counters);

        } else if ((config->shm_track_clients = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 1 ) {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot open() for Sagan_track_clients (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
        }


        if ( ftruncate(config->shm_track_clients, sizeof(_Sagan_Track_Clients_IPC) * config->max_track_clients ) != 0 ) {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to ftruncate _Sagan_Track_Clients_IPC. [%s]", __FILE__, __LINE__, strerror(errno));
        }

        if (( SaganTrackClients_ipc = mmap(0, sizeof(_Sagan_Track_Clients_IPC) * config->max_track_clients, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_track_clients, 0)) == MAP_FAILED ) {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for _Sagan_Track_Clients_IPC! [%s]", __FILE__, __LINE__, strerror(errno));
        }


        if ( new_object == 0 ) {
            Sagan_Log(S_NORMAL, "- Sagan_track_clients shared object reloaded (%d clients loaded / max: %d).", counters_ipc->track_clients_client_count, config->max_track_clients);
        }

        new_object = 0;
        /*
            if ( debug->debugipc && counters_ipc->track_client_count >= 1 )
                {
                    Sagan_Log(S_DEBUG, "");
                    Sagan_Log(S_DEBUG, "*** After by username ***");
                    Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");
                    Sagan_Log(S_DEBUG, "%-16s| %-11s| %-21s| %-11s| %s", "Username", "Counter","Date added/modified", "SID", "Expire" );
                    Sagan_Log(S_DEBUG, "--------------------------------------------------------------------------------------");

                    for ( i = 0; i < counters_ipc->after_count_by_username; i++)
                        {

        	    u32_Time_To_Human(afterbyusername_ipc[i].utime, time_buf, sizeof(time_buf));

                            Sagan_Log(S_DEBUG, "%-16s| %-11d| %-21s| %-11s| %d", afterbyusername_ipc[i].username, afterbyusername_ipc[i].count, time_buf, afterbyusername_ipc[i].sid, afterbyusername_ipc[i].expire);
                        }

                    Sagan_Log(S_DEBUG, "");
                }

        */



    }

}
