/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Adam Hall <ahall@quadrantsec.com>
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

/* sagan-track-clients.c
*
* Simple pre-processors that keeps track of reporting syslog clients/agents.
* This is based off the IP address the clients,  not based on normalization.
* If a client/agent hasn't sent a syslog/event message in X minutes,  then
* generate an alert.
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-track-clients.h"
#include "sagan-config.h"

struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;
struct _Sagan_IPC_Counters *counters_ipc;

struct _SaganConfig *config;

/****************************************************************************
 * Sagan_Track_Clients - Main routine to "tracks" via IPC/memory IPs that
 * are reporting or not.
 ****************************************************************************/

int Sagan_Track_Clients ( uint32_t host_u32 )
{

    char utime_tmp[20] = { 0 };
    time_t t;
    struct tm *now;
    int i;
    int tracking_flag=0;
    uint64_t utime_u64;

    t = time(NULL);
    now=localtime(&t);
    strftime(utime_tmp, sizeof(utime_tmp), "%s",  now);
    utime_u64 = atol(utime_tmp);

    /*************************/
    /** Record Clients Here **/
    /*************************/

    for (i=0; i<counters_ipc->track_clients_client_count; i++)
        {
            if ( SaganTrackClients_ipc[i].host_u32 == host_u32 )
                {

                    Sagan_File_Lock(config->shm_track_clients);
                    SaganTrackClients_ipc[i].utime = utime_u64;
                    SaganTrackClients_ipc[i].expire = config->pp_sagan_track_clients * 60;
                    Sagan_File_Unlock(config->shm_track_clients);
                    return(0);
                }
        }

    if ( counters_ipc->track_clients_client_count < config->max_track_clients )
        {
            Sagan_File_Lock(config->shm_track_clients);
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].host_u32 = host_u32;
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].utime = utime_u64;
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].status = 0;
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].expire = config->pp_sagan_track_clients * 60;
            Sagan_File_Unlock(config->shm_track_clients);

            Sagan_File_Lock(config->shm_counters);
            counters_ipc->track_clients_client_count++;
            Sagan_File_Unlock(config->shm_counters);
            return(0);

        }
    else
        {

            Sagan_Log(S_WARN, "[%s, line %d] Client tracking has reached it's max! (%d).  Increase 'track_clients' in your configuration!", __FILE__, __LINE__, config->max_track_clients);

        }
} /* CLose sagan_track_clients */
