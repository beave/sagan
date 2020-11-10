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
#include "flexbit-mmap.h"
#include "xbit-mmap.h"

#include "processors/track-clients.h"

struct _Sagan_IPC_Counters *counters_ipc;

extern struct _SaganConfig *config;

extern pthread_mutex_t After2_Mutex;
extern pthread_mutex_t Thresh2_Mutex;
extern pthread_mutex_t Flexbit_Mutex;
extern pthread_mutex_t Xbit_Mutex;

struct _After2_IPC *After2_IPC;
struct _Threshold2_IPC *Threshold2_IPC;
struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;
struct _Sagan_IPC_Flexbit *flexbit_ipc;
struct _Sagan_IPC_Xbit *Xbit_IPC;

extern struct _SaganDebug *debug;

/*****************************************************************************
 * Clean_IPC_Object - If the max IPC is hit,  we attempt to "clean" out
 * any stale IPC entries.
 *****************************************************************************/

bool Clean_IPC_Object( int type )
{

    if ( type == AFTER2 && config->max_after2 < counters_ipc->after2_count )
        {

            time_t t;
            struct tm *now;

            int i;
            int utime = 0;
            int new_count = 0;
            int old_count = 0;

            char timet[20];

            t = time(NULL);
            now=localtime(&t);
            strftime(timet, sizeof(timet), "%s",  now);
            utime = atol(timet);

            if ( debug->debugipc )
                {
                    Sagan_Log(DEBUG, "[%s, %d line] Cleaning IPC data. Type: %d", __FILE__, __LINE__, type);
                }

            File_Lock(config->shm_after2);
            pthread_mutex_lock(&After2_Mutex);

            struct _After2_IPC *Temp_After2_IPC;
            Temp_After2_IPC = malloc(sizeof(struct _After2_IPC) * config->max_after2);
            memset(Temp_After2_IPC, 0, sizeof(sizeof(struct _After2_IPC) * config->max_after2));

            old_count = counters_ipc->after2_count;

            for (i = 0; i < counters_ipc->after2_count; i++)
                {

                    if ( (utime - After2_IPC[i].utime) < After2_IPC[i].expire )
                        {

                            if ( debug->debugipc )
                                {
                                    Sagan_Log(DEBUG, "[%s, %d line] After2_IPC : Keeping %lu.", __FILE__, __LINE__, After2_IPC[i].hash);
                                }

                            Temp_After2_IPC[new_count].hash = After2_IPC[i].hash;
                            Temp_After2_IPC[new_count].count = After2_IPC[i].count;
                            Temp_After2_IPC[new_count].utime = After2_IPC[i].utime;
                            Temp_After2_IPC[new_count].expire = After2_IPC[i].expire;
                            Temp_After2_IPC[new_count].sid = After2_IPC[i].sid;
                            new_count++;

                        }
                }


            if ( new_count > 0 )
                {
                    for ( i = 0; i < new_count; i++ )
                        {
                            After2_IPC[i].hash = Temp_After2_IPC[i].hash;
                            After2_IPC[i].count = Temp_After2_IPC[i].count;
                            After2_IPC[i].utime = Temp_After2_IPC[i].utime;
                            After2_IPC[i].expire = Temp_After2_IPC[i].expire;
                            After2_IPC[i].sid =  Temp_After2_IPC[i].sid;
                        }

                    counters_ipc->after2_count = new_count;

                }
            else
                {

                    Sagan_Log(WARN, "[%s, line %d] Could not clean After2_IPC.  Nothing to remove!", __FILE__, __LINE__);
                    free(Temp_After2_IPC);
                    pthread_mutex_unlock(&After2_Mutex);
                    File_Unlock(config->shm_after2);
                    return(1);

                }

            Sagan_Log(NORMAL, "[%s, line %d] Kept %d elements out of %d for After2_IPC", __FILE__, __LINE__, new_count, old_count);
            free(Temp_After2_IPC);

            pthread_mutex_unlock(&After2_Mutex);
            File_Unlock(config->shm_after2);
            return(0);
        }

    /* Threshold2 */

    else if ( type == THRESHOLD2 && config->max_threshold2 < counters_ipc->thresh2_count )
        {

            time_t t;
            struct tm *now;

            int i;
            int utime = 0;
            int new_count = 0;
            int old_count = 0;

            char timet[20];

            t = time(NULL);
            now=localtime(&t);
            strftime(timet, sizeof(timet), "%s",  now);
            utime = atol(timet);

            new_count = 0;
            old_count = 0;

            File_Lock(config->shm_thresh2);
            pthread_mutex_lock(&Thresh2_Mutex);

            struct _Threshold2_IPC *Temp_Threshold2_IPC;
            Temp_Threshold2_IPC = malloc(sizeof(struct _Threshold2_IPC) * config->max_threshold2);

            memset(Temp_Threshold2_IPC, 0, sizeof(sizeof(struct _Threshold2_IPC) * config->max_threshold2));

            old_count = counters_ipc->thresh2_count;

            for (i = 0; i < counters_ipc->thresh2_count; i++)
                {
                    if ( (utime - Threshold2_IPC[i].utime) < Threshold2_IPC[i].expire )
                        {

                            if ( debug->debugipc )
                                {
                                    Sagan_Log(DEBUG, "[%s, %d line] Threshold2_IPC : Keeping %lu.", __FILE__, __LINE__, Threshold2_IPC[i].hash);
                                }

                            Temp_Threshold2_IPC[new_count].hash = Threshold2_IPC[i].hash;
                            Temp_Threshold2_IPC[new_count].count = Threshold2_IPC[i].count;
                            Temp_Threshold2_IPC[new_count].utime = Threshold2_IPC[i].utime;
                            Temp_Threshold2_IPC[new_count].expire = Threshold2_IPC[i].expire;
                            Temp_Threshold2_IPC[new_count].sid = Threshold2_IPC[i].sid;

                            new_count++;

                        }
                }

            if ( new_count > 0 )
                {
                    for ( i = 0; i < new_count; i++ )
                        {
                            Threshold2_IPC[i].hash = Temp_Threshold2_IPC[i].hash;
                            Threshold2_IPC[i].count = Temp_Threshold2_IPC[i].count;
                            Threshold2_IPC[i].utime = Temp_Threshold2_IPC[i].utime;
                            Threshold2_IPC[i].expire = Temp_Threshold2_IPC[i].expire;
                            Threshold2_IPC[i].sid =  Temp_Threshold2_IPC[i].sid;
                        }

                    counters_ipc->thresh2_count = new_count;

                }
            else
                {

                    Sagan_Log(WARN, "[%s, line %d] Could not clean Threshold2_IPC.  Nothing to remove!", __FILE__, __LINE__);
                    free(Temp_Threshold2_IPC);
                    pthread_mutex_unlock(&Thresh2_Mutex);
                    File_Unlock(config->shm_thresh2);
                    return(1);
                }

            Sagan_Log(NORMAL, "[%s, line %d] Kept %d elements out of %d for Threshold2_IPC", __FILE__, __LINE__, new_count, old_count);
            free(Temp_Threshold2_IPC);

            pthread_mutex_unlock(&Thresh2_Mutex);
            File_Unlock(config->shm_thresh2);
            return(0);

        }

    /* Flexbit_IPC */

    else if ( type == FLEXBIT && config->max_flexbits < counters_ipc->flexbit_count )
        {

            time_t t;
            struct tm *now;

            int i;
            int utime = 0;
            int new_count = 0;
            int old_count = 0;

            char timet[20];

            t = time(NULL);
            now=localtime(&t);
            strftime(timet, sizeof(timet), "%s",  now);
            utime = atol(timet);

            new_count = 0;
            old_count = 0;

            File_Lock(config->shm_flexbit);
            pthread_mutex_lock(&Flexbit_Mutex);

            struct _Sagan_IPC_Flexbit *temp_flexbit_ipc;
            temp_flexbit_ipc = malloc(sizeof(struct _Sagan_IPC_Flexbit) * config->max_flexbits);

            memset(temp_flexbit_ipc, 0, sizeof(sizeof(struct _Sagan_IPC_Flexbit) * config->max_flexbits));

            old_count = counters_ipc->flexbit_count;

            for (i = 0; i < counters_ipc->flexbit_count; i++)
                {
                    if ( (utime - flexbit_ipc[i].flexbit_expire) < flexbit_ipc[i].expire )
                        {

                            if ( debug->debugipc )
                                {
                                    Sagan_Log(DEBUG, "[%s, %d line] Flexbit_IPC : Keeping [0x%.08X%.08X%.08X%.08X -> 0x%.08X%.08X%.08X%.08X].", __FILE__, __LINE__,
                                              htonl(((unsigned int *)&flexbit_ipc[i].ip_src)[0]),
                                              htonl(((unsigned int *)&flexbit_ipc[i].ip_src)[1]),
                                              htonl(((unsigned int *)&flexbit_ipc[i].ip_src)[2]),
                                              htonl(((unsigned int *)&flexbit_ipc[i].ip_src)[3]),
                                              htonl(((unsigned int *)&flexbit_ipc[i].ip_dst)[0]),
                                              htonl(((unsigned int *)&flexbit_ipc[i].ip_dst)[1]),
                                              htonl(((unsigned int *)&flexbit_ipc[i].ip_dst)[2]),
                                              htonl(((unsigned int *)&flexbit_ipc[i].ip_dst)[3]));
                                }

                            temp_flexbit_ipc[new_count].flexbit_state = flexbit_ipc[i].flexbit_state;
                            memcpy(temp_flexbit_ipc[new_count].ip_src, flexbit_ipc[i].ip_src, sizeof(flexbit_ipc[i].ip_src));
                            memcpy(temp_flexbit_ipc[new_count].ip_dst, flexbit_ipc[i].ip_dst, sizeof(flexbit_ipc[i].ip_dst));
                            temp_flexbit_ipc[new_count].flexbit_expire = flexbit_ipc[i].flexbit_expire;
                            temp_flexbit_ipc[new_count].expire = flexbit_ipc[i].expire;
                            strlcpy(temp_flexbit_ipc[new_count].flexbit_name, flexbit_ipc[i].flexbit_name, sizeof(temp_flexbit_ipc[new_count].flexbit_name));

                            new_count++;
                        }
                }

            if ( new_count > 0 )
                {
                    for ( i = 0; i < new_count; i++ )
                        {
                            flexbit_ipc[i].flexbit_state = temp_flexbit_ipc[i].flexbit_state;
                            memcpy(temp_flexbit_ipc[i].ip_src, temp_flexbit_ipc[i].ip_src, sizeof(temp_flexbit_ipc[i].ip_src));
                            memcpy(temp_flexbit_ipc[i].ip_dst, temp_flexbit_ipc[i].ip_dst, sizeof(temp_flexbit_ipc[i].ip_dst));
                            flexbit_ipc[i].flexbit_expire = temp_flexbit_ipc[i].flexbit_expire;
                            flexbit_ipc[i].expire = temp_flexbit_ipc[i].expire;
                            strlcpy(flexbit_ipc[i].flexbit_name, temp_flexbit_ipc[i].flexbit_name, sizeof(flexbit_ipc[i].flexbit_name));
                        }

                    counters_ipc->flexbit_count = new_count;

                }
            else
                {

                    Sagan_Log(WARN, "[%s, line %d] Could not clean _Sagan_IPC_Flexbit.  Nothing to remove!", __FILE__, __LINE__);
                    free(temp_flexbit_ipc);
                    pthread_mutex_unlock(&Flexbit_Mutex);
                    File_Unlock(config->shm_flexbit);
                    return(1);
                }

            Sagan_Log(NORMAL, "[%s, line %d] Kept %d elements out of %d for _Sagan_IPC_Flexbit.", __FILE__, __LINE__, new_count, old_count);
            free(temp_flexbit_ipc);

            pthread_mutex_unlock(&Flexbit_Mutex);
            File_Unlock(config->shm_flexbit);
            return(0);

        }

    else if ( type == XBIT && config->max_xbits < counters_ipc->xbit_count && config->xbit_storage == XBIT_STORAGE_MMAP )
        {


            int old_count = 0;
            int new_count = 0;

            int i = 0;

            File_Lock(config->shm_xbit);
            pthread_mutex_lock(&Xbit_Mutex);

            struct _Sagan_IPC_Xbit *temp_xbit_ipc;
            temp_xbit_ipc = malloc(sizeof(struct _Sagan_IPC_Xbit) * config->max_xbits);
            memset(temp_xbit_ipc, 0, sizeof(sizeof(struct _Sagan_IPC_Xbit) * config->max_xbits));

            old_count = counters_ipc->xbit_count;

            for (i = 0; i < counters_ipc->xbit_count; i++)
                {

                    if ( Xbit_IPC[i].xbit_expire != 0 && Xbit_IPC[i].xbit_expire >= Return_Epoch() )
                        {

                            strlcpy(temp_xbit_ipc[new_count].xbit_name, Xbit_IPC[i].xbit_name, sizeof(temp_xbit_ipc[new_count].xbit_name));
                            strlcpy(temp_xbit_ipc[new_count].syslog_message, Xbit_IPC[i].syslog_message, sizeof(temp_xbit_ipc[new_count].syslog_message));
                            strlcpy(temp_xbit_ipc[new_count].signature_msg, Xbit_IPC[i].signature_msg, sizeof(temp_xbit_ipc[new_count].signature_msg));

                            temp_xbit_ipc[new_count].xbit_hash = Xbit_IPC[i].xbit_hash;
                            temp_xbit_ipc[new_count].xbit_name_hash = Xbit_IPC[i].xbit_name_hash;
                            temp_xbit_ipc[new_count].xbit_expire = Xbit_IPC[i].xbit_expire;
                            temp_xbit_ipc[new_count].expire = Xbit_IPC[i].expire;
                            temp_xbit_ipc[new_count].sid =  Xbit_IPC[i].sid;

                            new_count++;

                        }
                }

            if ( new_count > 0 )
                {

                    for ( i = 0; i < new_count; i++ )
                        {

                            strlcpy(Xbit_IPC[i].xbit_name, temp_xbit_ipc[new_count].xbit_name, sizeof(Xbit_IPC[i].xbit_name));
                            strlcpy(Xbit_IPC[i].syslog_message, temp_xbit_ipc[new_count].syslog_message, sizeof(Xbit_IPC[i].syslog_message));
                            strlcpy(Xbit_IPC[i].signature_msg, temp_xbit_ipc[new_count].signature_msg, sizeof(Xbit_IPC[i].signature_msg));

                            Xbit_IPC[i].xbit_hash = temp_xbit_ipc[new_count].xbit_hash;
                            Xbit_IPC[i].xbit_name_hash = temp_xbit_ipc[new_count].xbit_name_hash;
                            Xbit_IPC[i].xbit_expire = temp_xbit_ipc[new_count].xbit_expire;
                            Xbit_IPC[i].expire = temp_xbit_ipc[new_count].expire;
                            Xbit_IPC[i].sid = temp_xbit_ipc[new_count].sid;

                        }

                    counters_ipc->xbit_count = new_count;

                }
            else
                {

                    Sagan_Log(WARN, "[%s, line %d] Could not clean _Sagan_IPC_Xbit.  Nothing to remove!", __FILE__, __LINE__);
                    free(temp_xbit_ipc);
                    pthread_mutex_unlock(&Xbit_Mutex);
                    File_Unlock(config->shm_xbit);
                    return(1);

                }

            Sagan_Log(NORMAL, "[%s, line %d] Kept %d xbits out of %d for _Sagan_IPC_Xbit.", __FILE__, __LINE__, new_count, old_count);
            free(temp_xbit_ipc);

            File_Unlock(config->shm_xbit);
            pthread_mutex_unlock(&Xbit_Mutex);

        }

    return(0);

}

/*****************************************************************************
 * IPC_Check_Object - If "counters" have been reset,   we want to
 * recreate the other objects (hence the unlink).  This function tests for
 * this case
 *****************************************************************************/

void IPC_Check_Object(char *tmp_object_check, bool new_counters, char *object_name)
{

    struct stat object_check;

    if ( ( stat(tmp_object_check, &object_check) == 0 ) && new_counters == 1 )
        {
            if ( unlink(tmp_object_check) == -1 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Could not unlink %s memory object! [%s]", __FILE__, __LINE__, object_name, strerror(errno));
                }

            Sagan_Log(NORMAL, "* Stale %s memory object found & unlinked.", object_name);
        }
}

/*****************************************************************************
 * IPC_Init - Create (if needed) or map to an IPC object.
 *****************************************************************************/

void IPC_Init(void)
{

    /* If we have a "new" counters shared memory object,  but other "old" data,  we need to remove
     * the "old" data!  The counters need to stay in sync with the other data objects! */

    bool new_counters = 0;
    bool new_object = 0;

    char tmp_object_check[255] = { 0 };

    Sagan_Log(NORMAL, "Initializing shared memory objects.");
    Sagan_Log(NORMAL, "---------------------------------------------------------------------------");

    /* Init counters first.  Need to track all other share memory objects */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, COUNTERS_IPC_FILE);

    if ((config->shm_counters = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(NORMAL, "+ Counters shared object (new).");
            new_counters = 1;

        }

    else if ((config->shm_counters = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open() for counters. [%s:%s]", __FILE__, __LINE__, tmp_object_check, strerror(errno));
        }
    else
        {
            Sagan_Log(NORMAL, "- Counters shared object (reload)");
        }

    config->shm_counters_status = true;

    if ( ftruncate(config->shm_counters, sizeof(_Sagan_IPC_Counters)) != 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to ftruncate counters. [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if (( counters_ipc = mmap(0, sizeof(_Sagan_IPC_Counters), (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_counters, 0)) == MAP_FAILED )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory for counters object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    /* Make sure we are using the correct mmap() version/format */

    if ( new_counters == 1 )
        {
            /* Write mmap() version */
            counters_ipc->version = MMAP_VERSION;
        }
    else
        {
            if ( counters_ipc->version != MMAP_VERSION )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Incorrect mmap version. Was looking for %.1f but got %d. Removed your mmap files and restart!", __FILE__, __LINE__, MMAP_VERSION, counters_ipc->version );
                }
        }

    /* xbit memory object - File based mmap() */

    if ( config->xbit_storage == XBIT_STORAGE_MMAP )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, XBIT_IPC_FILE);

            IPC_Check_Object(tmp_object_check, new_counters, "xbit");

            if ((config->shm_xbit = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
                {
                    Sagan_Log(NORMAL, "+ Xbit shared object (new).");
                    new_object=1;
                }

            else if ((config->shm_xbit = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Cannot open() for xbit (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
                }

            config->shm_xbit_status = true;

            if ( ftruncate(config->shm_xbit, sizeof(_Sagan_IPC_Xbit) * config->max_xbits ) != 0 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to ftruncate xbit. [%s]", __FILE__, __LINE__, strerror(errno));
                }

            if (( Xbit_IPC = mmap(0, sizeof(_Sagan_IPC_Xbit) * config->max_xbits, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_xbit, 0)) == MAP_FAILED )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Error allocating memory for xbit object! [%s]", __FILE__, __LINE__, strerror(errno));
                }

            if ( new_object == 0)
                {
                    Sagan_Log(NORMAL, "- Xbit shared object reloaded (%d xbits loaded / max: %d).", counters_ipc->xbit_count, config->max_xbits);
                }

            new_object = 0;

        }
    else      /* if ( config->flexbit_storage == XBIT_STORAGE_MMAP ) */
        {

            Sagan_Log(NORMAL, "- Xbit shared object (Objects stored in Redis)");

        }


    /* Flexbit memory object - File based mmap() */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, FLEXBIT_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "flexbit");

    if ((config->shm_flexbit = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(NORMAL, "+ Flexbit shared object (new).");
            new_object=1;
        }

    else if ((config->shm_flexbit = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open() for flexbit (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
        }

    config->shm_flexbit_status = true;

    if ( ftruncate(config->shm_flexbit, sizeof(_Sagan_IPC_Flexbit) * config->max_flexbits ) != 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to ftruncate flexbit. [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if (( flexbit_ipc = mmap(0, sizeof(_Sagan_IPC_Flexbit) * config->max_flexbits, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_flexbit, 0)) == MAP_FAILED )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory for flexbit object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if ( new_object == 0)
        {
            Sagan_Log(NORMAL, "- Flexbit shared object reloaded (%d flexbits loaded / max: %d).", counters_ipc->flexbit_count, config->max_flexbits);
        }

    new_object = 0;

    /* Threshold2 */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, THRESHOLD2_IPC_FILE);

    IPC_Check_Object(tmp_object_check, new_counters, "thresh2");

    if ((config->shm_thresh2 = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(NORMAL, "+ Threshold shared object (new).");
            new_object=1;
        }


    else if ((config->shm_thresh2 = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open() for thresh2 (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
        }

    config->shm_thresh2_status = true;

    if ( ftruncate(config->shm_thresh2, sizeof(_Threshold2_IPC) * config->max_threshold2 ) != 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to ftruncate thresh2. [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if (( Threshold2_IPC = mmap(0, sizeof(_Threshold2_IPC) * config->max_threshold2, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh2, 0)) == MAP_FAILED )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory for _Threshold2_IPC object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if ( new_object == 0 )
        {
            Sagan_Log(NORMAL, "- Threshold shared object reloaded (%d sources loaded / max: %d).", counters_ipc->thresh2_count, config->max_threshold2);
        }

    new_object = 0;

    /* After2 */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, AFTER2_IPC_FILE);


    IPC_Check_Object(tmp_object_check, new_counters, "after2");


    if ((config->shm_after2 = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(NORMAL, "+ After shared object (new).");
            new_object=1;
        }

    else if ((config->shm_after2 = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open() for after2 (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
        }

    config->shm_after2_status = true;

    if ( ftruncate(config->shm_after2, sizeof(_After2_IPC) * config->max_after2 ) != 0 )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to ftruncate after2. [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if (( After2_IPC = mmap(0, sizeof(_After2_IPC) * config->max_after2, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after2, 0)) == MAP_FAILED )
        {
            Sagan_Log(ERROR, "[%s, line %d] Error allocating memory for _After2_IPC object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    if ( new_object == 0 )
        {
            Sagan_Log(NORMAL, "- After shared object reloaded (%d sources loaded / max: %d).", counters_ipc->after2_count, config->max_after2);
        }


    new_object = 0;

    /* Client tracking */

    if ( config->sagan_track_clients_flag )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", config->ipc_directory, CLIENT_TRACK_IPC_FILE);

            IPC_Check_Object(tmp_object_check, new_counters, "_Sagan_Track_Clients_IPC");

            if ((config->shm_track_clients = open(tmp_object_check, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
                {
                    Sagan_Log(NORMAL, "+ Sagan_track_clients shared object (new).");
                    new_object=1;

                }
            else if ((config->shm_track_clients = open(tmp_object_check, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 1 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Cannot open() for Sagan_track_clients (%s:%s)", __FILE__, __LINE__, tmp_object_check, strerror(errno));
                }

            config->shm_track_clients_status = true;

            if ( ftruncate(config->shm_track_clients, sizeof(_Sagan_Track_Clients_IPC) * config->max_track_clients ) != 0 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to ftruncate _Sagan_Track_Clients_IPC. [%s]", __FILE__, __LINE__, strerror(errno));
                }

            if (( SaganTrackClients_ipc = mmap(0, sizeof(_Sagan_Track_Clients_IPC) * config->max_track_clients, (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_track_clients, 0)) == MAP_FAILED )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Error allocating memory for _Sagan_Track_Clients_IPC! [%s]", __FILE__, __LINE__, strerror(errno));
                }

            if ( new_object == 0 )
                {
                    Sagan_Log(NORMAL, "- Sagan_track_clients shared object reloaded (%d clients loaded / max: %d).", counters_ipc->track_clients_client_count, config->max_track_clients);
                }

            new_object = 0;

        }

}
