/* $Id$ */
/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-ipc.c
 *
 * This allows Sagan to share data with other Sagan processes. This is for
 * Inter-process communications (IPC).
 *
 */


#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>

#include "version.h"
#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "sagan-ipc.h"
#include "sagan-flowbit.h"


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

struct _Sagan_IPC_Counters *counters_ipc;
struct _Sagan_IPC_Flowbit *flowbit_ipc;

struct _SaganConfig *config;

struct thresh_by_src_ipc *threshbysrc_ipc;
struct thresh_by_dst_ipc *threshbydst_ipc;
struct thresh_by_username_ipc *threshbyusername_ipc;

struct after_by_src_ipc *afterbysrc_ipc;
struct after_by_dst_ipc *afterbydst_ipc;
struct after_by_username_ipc *afterbyusername_ipc;

pthread_mutex_t *ThreshMutexSrc_IPC;
pthread_mutex_t *ThreshMutexDst_IPC;
pthread_mutex_t *ThreshMutexUsername_IPC;

pthread_mutex_t *AfterMutexSrc_IPC;
pthread_mutex_t *AfterMutexDst_IPC;
pthread_mutex_t *AfterMutexUsername_IPC;

pthread_mutex_t *FlowbitMutex_IPC;
pthread_mutex_t *CountersMutex_IPC;

void Sagan_IPC_Check_Object(char *tmp_object_check, sbool new_counters, char *object_name)
{

    struct stat object_check;

    if ( ( stat(tmp_object_check, &object_check) == 0 ) && new_counters == 1 )
        {
            if ( unlink(tmp_object_check) == -1 )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Could not unlink %s memory object! [%s]", __FILE__, __LINE__, object_name, strerror(errno));
                }

            Sagan_Log(S_NORMAL, "* Stale %s memory object found & unlinked.", object_name);
        }
}


void Sagan_IPC_Init(void)
{

    pthread_mutexattr_t IPC_Attr;
    pthread_mutexattr_setpshared(&IPC_Attr, PTHREAD_PROCESS_SHARED);

    /* If we have a "new" counters shared memory object,  but other "old" data,  we need to remove
     * the "old" data!  The counters need to stay in sync with the other data objects! */

    sbool new_counters = 0;
    sbool new_object = 0; 

    char tmp_object_check[255];

    Sagan_Log(S_NORMAL, "Initializing shared memory objects.");
    Sagan_Log(S_NORMAL, "---------------------------------------------------------------------------");

    /* Init counters first.  Need to track all other share memory objects */

    if ((config->shm_counters = shm_open(COUNTERS_IPC_FILE, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(S_NORMAL, "+ Counters shared object (new).");
            new_counters = 1;

        }

    else if ((config->shm_counters = shm_open(COUNTERS_IPC_FILE, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot shm_open() for counters (%s)", __FILE__, __LINE__, strerror(errno));
        }
    else
        {
            Sagan_Log(S_NORMAL, "- Counters shared object (reload)");
        }


    ftruncate(config->shm_counters, sizeof(_Sagan_IPC_Counters));

    if (( counters_ipc = mmap(0, sizeof(_Sagan_IPC_Counters) , (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_counters, 0)) == MAP_FAILED )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for counters object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    CountersMutex_IPC = (pthread_mutex_t *)(counters_ipc + sizeof(pthread_mutex_t));
//    pthread_mutexattr_setpshared(&IPC_Attr, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(CountersMutex_IPC, &IPC_Attr);
//    pthread_mutexattr_destroy(&Counters_IPC_Attr);

    /* Flowbit memory object */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s%s", SHM_LOCATION, FLOWBIT_IPC_FILE);

    Sagan_IPC_Check_Object(tmp_object_check, new_counters, "flowbit");

    if ((config->shm_flowbit = shm_open(FLOWBIT_IPC_FILE, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(S_NORMAL, "+ Flowbit shared object (new).");
	    new_object=1;
        }

    else if ((config->shm_flowbit = shm_open(FLOWBIT_IPC_FILE, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot shm_open() for flowbit (%s)", __FILE__, __LINE__, strerror(errno));
        }

    ftruncate(config->shm_flowbit, sizeof(_Sagan_IPC_Flowbit));

     if (( flowbit_ipc = mmap(0, sizeof(_Sagan_IPC_Flowbit) , (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_flowbit, 0)) == MAP_FAILED )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for flowbit object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    FlowbitMutex_IPC = (pthread_mutex_t *)(flowbit_ipc + sizeof(pthread_mutex_t));
    pthread_mutex_init(FlowbitMutex_IPC, &IPC_Attr);

    if ( new_object == 0) 
    	{
        Sagan_Log(S_NORMAL, "- Flowbit shared object reloaded (%d flowbits loaded).", counters_ipc->flowbit_count);
	}

    new_object = 0; 

    /* Threshold by source */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s%s", SHM_LOCATION, THRESH_BY_SRC_IPC_FILE);

    Sagan_IPC_Check_Object(tmp_object_check, new_counters, "thresh_by_src");

    if ((config->shm_thresh_by_src = shm_open(THRESH_BY_SRC_IPC_FILE, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(S_NORMAL, "+ Thresh_by_src shared object (new).");
	    new_object=1;
        }

    else if ((config->shm_thresh_by_src = shm_open(THRESH_BY_SRC_IPC_FILE, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot shm_open() for thresh_by_src (%s)", __FILE__, __LINE__, strerror(errno));
        }

    ftruncate(config->shm_thresh_by_src, sizeof(thresh_by_src_ipc) );

    if (( threshbysrc_ipc = mmap(0, sizeof(thresh_by_src_ipc) , (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh_by_src, 0)) == MAP_FAILED )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for thresh_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    ThreshMutexSrc_IPC = (pthread_mutex_t *)(threshbysrc_ipc + sizeof(pthread_mutex_t));
    pthread_mutex_init(ThreshMutexSrc_IPC, &IPC_Attr);

    if ( new_object == 0)
        {
	Sagan_Log(S_NORMAL, "- Thresh_by_src shared object reloaded (%d sources loaded).", counters_ipc->thresh_count_by_src);
	}

    new_object = 0; 

    /* Threshold by destination */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s%s", SHM_LOCATION, THRESH_BY_DST_IPC_FILE);

    Sagan_IPC_Check_Object(tmp_object_check, new_counters, "thresh_by_dst");

    if ((config->shm_thresh_by_dst = shm_open(THRESH_BY_DST_IPC_FILE, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(S_NORMAL, "+ Thresh_by_dst shared object (new).");
	    new_object=1;
        }

    else if ((config->shm_thresh_by_dst = shm_open(THRESH_BY_DST_IPC_FILE, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot shm_open() for thresh_by_dst (%s)", __FILE__, __LINE__, strerror(errno));
        }

    ftruncate(config->shm_thresh_by_dst, sizeof(thresh_by_dst_ipc));

    if (( threshbydst_ipc = mmap(0, sizeof(thresh_by_dst_ipc) , (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh_by_dst, 0)) == MAP_FAILED )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for thresh_by_dst object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    ThreshMutexDst_IPC = (pthread_mutex_t *)(threshbydst_ipc + sizeof(pthread_mutex_t));
    pthread_mutex_init(ThreshMutexDst_IPC, &IPC_Attr);

    if ( new_object == 0)
        {
	Sagan_Log(S_NORMAL, "- Thresh_by_dst shared object reloaded (%d destinations loaded).", counters_ipc->thresh_count_by_dst);
	}

    new_object = 0;

    /* Threshold by username */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s%s", SHM_LOCATION, THRESH_BY_USERNAME_IPC_FILE);

    Sagan_IPC_Check_Object(tmp_object_check, new_counters, "thresh_by_username");

    if ((config->shm_thresh_by_username = shm_open(THRESH_BY_USERNAME_IPC_FILE, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(S_NORMAL, "+ Thresh_by_username shared object (new).");
	    new_object=1;
        }

    else if ((config->shm_thresh_by_username = shm_open(THRESH_BY_USERNAME_IPC_FILE, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot shm_open() for thresh_by_username (%s)", __FILE__, __LINE__, strerror(errno));
        }

    ftruncate(config->shm_thresh_by_username, sizeof(thresh_by_username_ipc));

    if (( threshbyusername_ipc = mmap(0, sizeof(thresh_by_username_ipc) , (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_thresh_by_username, 0)) == MAP_FAILED )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for thresh_by_username object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    ThreshMutexUsername_IPC = (pthread_mutex_t *)(threshbyusername_ipc + sizeof(pthread_mutex_t));
    pthread_mutex_init(ThreshMutexUsername_IPC, &IPC_Attr);

    if ( new_object == 0 )
        {
	Sagan_Log(S_NORMAL, "- Thresh_by_username shared object reloaded (%d usernames loaded).", counters_ipc->thresh_count_by_username);
	}

    new_object = 0; 

    /* After by source */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s%s", SHM_LOCATION, AFTER_BY_SRC_IPC_FILE);

    Sagan_IPC_Check_Object(tmp_object_check, new_counters, "after_by_src");

    if ((config->shm_after_by_src = shm_open(AFTER_BY_SRC_IPC_FILE, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(S_NORMAL, "+ After_by_src shared object (new).");
	    new_object=1;
        }

    else if ((config->shm_after_by_src = shm_open(AFTER_BY_SRC_IPC_FILE, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot shm_open() for after_by_src (%s)", __FILE__, __LINE__, strerror(errno));
        }

    ftruncate(config->shm_after_by_src, sizeof(after_by_src_ipc));

    if (( afterbysrc_ipc = mmap(0, sizeof(after_by_src_ipc) , (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after_by_src, 0)) == MAP_FAILED )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for after_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    AfterMutexSrc_IPC = (pthread_mutex_t *)(afterbysrc_ipc + sizeof(pthread_mutex_t));
    pthread_mutex_init(AfterMutexSrc_IPC, &IPC_Attr);

    if ( new_object == 0 )
        {
	Sagan_Log(S_NORMAL, "- After_by_src shared object reloaded (%d sources loaded).", counters_ipc->after_count_by_src);
	}
    
    new_object = 0; 

    /* After by destination */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s%s", SHM_LOCATION, AFTER_BY_DST_IPC_FILE);

    Sagan_IPC_Check_Object(tmp_object_check, new_counters, "after_by_dst");

    if ((config->shm_after_by_dst = shm_open(AFTER_BY_DST_IPC_FILE, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(S_NORMAL, "+ After_by_dst shared object (new).");
	    new_object=1;
        }

    else if ((config->shm_after_by_dst = shm_open(AFTER_BY_DST_IPC_FILE, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot shm_open() for after_by_dst (%s)", __FILE__, __LINE__, strerror(errno));
        }

    ftruncate(config->shm_after_by_dst, sizeof(after_by_dst_ipc));


    if (( afterbydst_ipc = mmap(0, sizeof(after_by_dst_ipc) , (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after_by_dst, 0)) == MAP_FAILED )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for after_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    AfterMutexDst_IPC = (pthread_mutex_t *)(afterbydst_ipc + sizeof(pthread_mutex_t));
    pthread_mutex_init(AfterMutexDst_IPC, &IPC_Attr);

    if ( new_object == 0 )
        {
	Sagan_Log(S_NORMAL, "- After_by_dst shared object reloaded (%d destinations loaded).", counters_ipc->after_count_by_dst);
	}
 
    new_object = 0;

    /* After by username */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s%s", SHM_LOCATION, AFTER_BY_USERNAME_IPC_FILE);

    Sagan_IPC_Check_Object(tmp_object_check, new_counters, "after_by_username");

    if ((config->shm_after_by_username = shm_open(AFTER_BY_USERNAME_IPC_FILE, (O_CREAT | O_EXCL | O_RDWR), (S_IREAD | S_IWRITE))) > 0 )
        {
            Sagan_Log(S_NORMAL, "+ After_by_username shared object (new).");
	    new_object=1;
        }

    else if ((config->shm_after_by_username = shm_open(AFTER_BY_USERNAME_IPC_FILE, (O_CREAT | O_RDWR), (S_IREAD | S_IWRITE))) < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot shm_open() for after_by_username (%s)", __FILE__, __LINE__, strerror(errno));
        }

    ftruncate(config->shm_after_by_username, sizeof(after_by_username_ipc));

    if (( afterbyusername_ipc = mmap(0, sizeof(after_by_username_ipc) , (PROT_READ | PROT_WRITE), MAP_SHARED, config->shm_after_by_username, 0)) == MAP_FAILED )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Error allocating memory for after_by_src object! [%s]", __FILE__, __LINE__, strerror(errno));
        }

    AfterMutexUsername_IPC = (pthread_mutex_t *)(afterbydst_ipc + sizeof(pthread_mutex_t));
    pthread_mutex_init(AfterMutexUsername_IPC, &IPC_Attr);

    if ( new_object == 0 )
        {
	Sagan_Log(S_NORMAL, "- After_by_username shared object reloaded (%d usernames loaded).", counters_ipc->after_count_by_username);
	}

}
