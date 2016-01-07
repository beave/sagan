/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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
#include "sagan-send-alert.h"
#include "sagan-track-clients.h"
#include "sagan-config.h"

struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;
struct _Sagan_IPC_Counters *counters_ipc;

struct _SaganConfig *config;
struct _Sagan_Processor_Info *processor_info_track_client = NULL;
struct _Sagan_Proc_Syslog *SaganProcSyslog;

/****************************************************************************
 * Sagan_Track_Clients_Init - Initialize shared memory object for the
 * tracking client processor to use
 ****************************************************************************/

void Sagan_Track_Clients_Init ( void )
{

    processor_info_track_client = malloc(sizeof(struct _Sagan_Processor_Info));

    if ( processor_info_track_client == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for processor_info_track_client. Abort!", __FILE__, __LINE__);
        }

    memset(processor_info_track_client, 0, sizeof(_Sagan_Processor_Info));

    processor_info_track_client->processor_name         =       PROCESSOR_NAME;
    processor_info_track_client->processor_generator_id =       PROCESSOR_GENERATOR_ID;
    processor_info_track_client->processor_name         =       PROCESSOR_NAME;
    processor_info_track_client->processor_facility     =       PROCESSOR_FACILITY;
    processor_info_track_client->processor_priority     =       PROCESSOR_PRIORITY;
    processor_info_track_client->processor_pri          =       PROCESSOR_PRI;
    processor_info_track_client->processor_class        =       PROCESSOR_CLASS;
    processor_info_track_client->processor_tag          =       PROCESSOR_TAG;
    processor_info_track_client->processor_rev          =       PROCESSOR_REV;

}

/****************************************************************************
 * Sagan_Track_Clients - Main routine to "tracks" via IPC/memory IPs that
 * are reporting or not.
 ****************************************************************************/

int Sagan_Track_Clients ( uint32_t host_u32 )
{

    struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL = NULL;

    int alertid;
    int i;

    sbool tracking_flag=0;

    char *tmp_ip = NULL;

    long utimetmp;
    char utime_tmp[20] = { 0 };
    time_t t;
    struct tm *now;

    uint64_t utime_u64;

    t = time(NULL);
    now=localtime(&t);
    strftime(utime_tmp, sizeof(utime_tmp), "%s",  now);
    utime_u64 = atol(utime_tmp);

    struct in_addr ip_addr_syslog;

    /* We populate this later for output plugins */

    SaganProcSyslog_LOCAL = malloc(sizeof(struct _Sagan_Proc_Syslog));

    if ( SaganProcSyslog_LOCAL == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    /* Look through "known" system */

    for (i=0; i<counters_ipc->track_clients_client_count; i++)
        {

            if ( SaganTrackClients_ipc[i].host_u32 == host_u32 )
                {

                    tracking_flag = 1;

                    /* Logs being received */

                    if ( SaganTrackClients_ipc[i].status == 1 )
                        {

                            /* Update status and seen time */

                            Sagan_File_Lock(config->shm_track_clients);
                            SaganTrackClients_ipc[i].utime = utime_u64;
                            SaganTrackClients_ipc[i].status = 0;
                            Sagan_File_Unlock(config->shm_track_clients);

                            /* Update counters */

                            Sagan_File_Lock(config->shm_counters);
                            counters_ipc->track_clients_down--;
                            Sagan_File_Unlock(config->shm_counters);

                            tmp_ip = Bit2IP(host_u32);	/* Call this here,  so we don't repeatedly */

                            Sagan_Log(S_WARN, "[Processor: %s] Logs being received from %s again.",  PROCESSOR_NAME, tmp_ip );

                            /* Populate SaganProcSyslog_LOCAL for output plugins */

                            strlcpy(SaganProcSyslog_LOCAL->syslog_host, tmp_ip, sizeof(SaganProcSyslog_LOCAL->syslog_host));
                            strlcpy(SaganProcSyslog_LOCAL->syslog_facility, PROCESSOR_FACILITY, sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                            strlcpy(SaganProcSyslog_LOCAL->syslog_priority, PROCESSOR_PRIORITY, sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                            strlcpy(SaganProcSyslog_LOCAL->syslog_level, "info", sizeof(SaganProcSyslog_LOCAL->syslog_level));
                            strlcpy(SaganProcSyslog_LOCAL->syslog_tag, "00", sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                            strlcpy(SaganProcSyslog_LOCAL->syslog_program, PROCESSOR_NAME, sizeof(SaganProcSyslog_LOCAL->syslog_program));

                            snprintf(SaganProcSyslog_LOCAL->syslog_date, sizeof(SaganProcSyslog_LOCAL->syslog_date), "%s", Sagan_Return_Date(utime_u64));
                            snprintf(SaganProcSyslog_LOCAL->syslog_time, sizeof(SaganProcSyslog_LOCAL->syslog_time), "%s", Sagan_Return_Time(utime_u64));
                            snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message)-1, "The IP address %s was previous reported as being down or not sending logs.  The system appears to be sending logs again", tmp_ip );

                            alertid=101;		/* See gen-msg.map */

                            /* Send alert to output plugins */

                            Sagan_Send_Alert(SaganProcSyslog_LOCAL,
                                             processor_info_track_client,
                                             SaganProcSyslog_LOCAL->syslog_host,
                                             config->sagan_host,
                                             "\0",
                                             "\0",
                                             config->sagan_proto,
                                             alertid,
                                             config->sagan_port,
                                             config->sagan_port,
                                             0);

                        }
                    else
                        {

                            /**** System is found but hasn't been seen! ****/

                            if ( ( utime_u64 - SaganTrackClients_ipc[i].utime ) > config->pp_sagan_track_clients * 60 )
                                {

                                    /* Update status and utime */

                                    Sagan_File_Lock(config->shm_track_clients);
                                    SaganTrackClients_ipc[i].utime = utime_u64;
                                    SaganTrackClients_ipc[i].status = 1;
                                    Sagan_File_Unlock(config->shm_track_clients);

                                    /* Update counters */

                                    Sagan_File_Lock(config->shm_counters);
                                    counters_ipc->track_clients_down++;
                                    Sagan_File_Unlock(config->shm_counters);

                                    tmp_ip = Bit2IP(host_u32);	/* Do this now,  so we don't have to keep recalling Bit2IP */

                                    Sagan_Log(S_WARN, "[Processor: %s] Logs have not been seen from %s for %d minute(s).", PROCESSOR_NAME, tmp_ip, config->pp_sagan_track_clients);

                                    /* Populate SaganProcSyslog_LOCAL for output plugins */

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, tmp_ip, sizeof(SaganProcSyslog_LOCAL->syslog_host));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_facility, PROCESSOR_FACILITY, sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_priority, PROCESSOR_PRIORITY, sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_level, "info", sizeof(SaganProcSyslog_LOCAL->syslog_level));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_tag, "00", sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, PROCESSOR_NAME, sizeof(SaganProcSyslog_LOCAL->syslog_program));

                                    snprintf(SaganProcSyslog_LOCAL->syslog_date, sizeof(SaganProcSyslog_LOCAL->syslog_date), "%s", Sagan_Return_Date(utime_u64));
                                    snprintf(SaganProcSyslog_LOCAL->syslog_time, sizeof(SaganProcSyslog_LOCAL->syslog_time), "%s", Sagan_Return_Time(utime_u64));
                                    snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message)-1, "Sagan has not recieved any logs from the IP address %s in over %d minute(s). This could be an indication that the system is down.", tmp_ip, config->pp_sagan_track_clients);

                                    alertid=100;	/* See gen-msg.map  */

                                    /* Send alert to output plugins */

                                    Sagan_Send_Alert(SaganProcSyslog_LOCAL,
                                                     processor_info_track_client,
                                                     SaganProcSyslog_LOCAL->syslog_host,
                                                     config->sagan_host,
                                                     "\0",
                                                     "\0",
                                                     config->sagan_proto,
                                                     alertid,
                                                     config->sagan_port,
                                                     config->sagan_port,
                                                     0);

                                }  /* End of existing utime check */

                        } /* End of else */
                } /* End of "if" */
        }  /* End for 'for' loop */


    /**** If the system is not in the array,  this is the first time we've seen it.  Add it to the array ****/

    if ( tracking_flag == 0)
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

        }

    free(SaganProcSyslog_LOCAL);
    return(0);

}
