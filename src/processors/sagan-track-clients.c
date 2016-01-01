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

//int Sagan_Track_Clients ( _SaganProcSyslog *SaganProcSyslog_LOCAL )

int Sagan_Track_Clients ( uint32_t host_u32 )
{

    int alertid;

    char  timet[20] = { 0 };
    time_t t;
    struct tm *now;

    int i;
    sbool tracking_flag=0;

    long utimetmp;

    char tmp[256];

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    struct in_addr ip_addr_syslog;


    for (i=0; i<counters_ipc->track_clients_client_count; i++)
        {

            if ( SaganTrackClients_ipc[i].host_u32 == host_u32 )
                {

                    Sagan_File_Lock(config->shm_track_clients);
                    SaganTrackClients_ipc[i].utime = atol(timet);
                    Sagan_File_Unlock(config->shm_track_clients);

                    /* Logs being received */

                    if ( SaganTrackClients_ipc[i].status == 1 )
                        {


                            Sagan_File_Lock(config->shm_counters);
                            counters_ipc->track_clients_down--;
                            Sagan_File_Unlock(config->shm_counters);

                            Sagan_Log(S_WARN, "[Processor: %s] Logs being received from %s again.",  PROCESSOR_NAME, Bit2IP(host_u32) ); // SaganProcSyslog_LOCAL->syslog_host);

                            snprintf(tmp, sizeof(tmp)-1, "The IP address %s was previous reported as being down or not sending logs.  The system appears to be sending logs again", Bit2IP(host_u32) );

                            alertid=101;

                            Sagan_File_Lock(config->shm_track_clients);
                            SaganTrackClients_ipc[i].status = 0;
                            Sagan_File_Unlock(config->shm_track_clients);

//                            Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info_track_client, SaganProcSyslog_LOCAL->syslog_host, config->sagan_host, "\0", "\0", config->sagan_proto, alertid, config->sagan_port, config->sagan_port, 0);
                        }

                    tracking_flag=1;
                }

            utimetmp = SaganTrackClients_ipc[i].utime ;

            /* Logs stop being received */

            if ( ( SaganTrackClients_ipc[i].status == 0 && atol(timet) - utimetmp >  config->pp_sagan_track_clients * 60 ) )
                {

                    Sagan_File_Lock(config->shm_counters);
                    counters_ipc->track_clients_down++;
                    Sagan_File_Unlock(config->shm_counters);

                    Sagan_Log(S_WARN, "[Processor: %s] Logs have not been seen from %s for %d minute(s).", PROCESSOR_NAME, Bit2IP(host_u32), config->pp_sagan_track_clients);

                    snprintf(tmp, sizeof(tmp)-1, "Sagan has not recieved any logs from the IP address %s in over %d minute(s). This could be an indication that the system is down.", Bit2IP(host_u32), config->pp_sagan_track_clients);

                    alertid=100;

                    Sagan_File_Lock(config->shm_track_clients);
                    SaganTrackClients_ipc[i].status = 1;
                    Sagan_File_Unlock(config->shm_track_clients);

                    /*
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
                    				     */


                }

        }

    if ( tracking_flag == 0)
        {

            Sagan_File_Lock(config->shm_track_clients);

            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].host_u32 = host_u32;
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].utime = atol(timet);
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].status = 0;

            Sagan_File_Unlock(config->shm_track_clients);

            Sagan_File_Lock(config->shm_counters);
            counters_ipc->track_clients_client_count++;
            Sagan_File_Unlock(config->shm_counters);

        }

    return(0);
}

