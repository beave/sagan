/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Adam Hall <ahall@quadrantsec.com>
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

/* track-clients.c
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
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "geoip.h"
#include "send-alert.h"
#include "util-time.h"

#include "processors/track-clients.h"

pthread_mutex_t IPCTrackClientCounter=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t IPCTrackClientsStatus=PTHREAD_MUTEX_INITIALIZER;

struct _Sagan_Processor_Info *processor_info_track_client = NULL;
struct _Sagan_Proc_Syslog *SaganProcSyslog;
extern struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;
extern struct _Sagan_IPC_Counters *counters_ipc;

extern struct _SaganConfig *config;

/****************************************************************************
 * Sagan_Track_Clients - Main routine to "tracks" via IPC/memory IPs that
 * are reporting or not.
 ****************************************************************************/


void Track_Clients ( char *host )
{

    char utime_tmp[20] = { 0 };
    time_t t;
    struct tm *now;
    int i;
    uint64_t utime_u64;
    unsigned char hostbits[MAXIPBIT] = { 0 };

    t = time(NULL);
    now=localtime(&t);
    strftime(utime_tmp, sizeof(utime_tmp), "%s",  now);
    utime_u64 = atol(utime_tmp);
    int expired_time = config->pp_sagan_track_clients * 60;

    IP2Bit(host, hostbits);

    /********************************************/
    /** Record update tracking if record exsist */
    /********************************************/

    pthread_mutex_lock(&IPCTrackClientCounter);
    File_Lock(config->shm_track_clients);

    for (i=0; i<counters_ipc->track_clients_client_count; i++)
        {
            if ( !memcmp(SaganTrackClients_ipc[i].hostbits, hostbits, MAXIPBIT ) )
                {

                    SaganTrackClients_ipc[i].utime = utime_u64;
                    SaganTrackClients_ipc[i].expire = expired_time;

                    File_Unlock(config->shm_track_clients);
                    pthread_mutex_unlock(&IPCTrackClientCounter);

                    return;
                }
        }

    if ( counters_ipc->track_clients_client_count < config->max_track_clients )
        {
            memcpy(SaganTrackClients_ipc[counters_ipc->track_clients_client_count].hostbits, hostbits, sizeof(hostbits));
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].utime = utime_u64;
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].status = 0;
            SaganTrackClients_ipc[counters_ipc->track_clients_client_count].expire = expired_time;

            File_Lock(config->shm_counters);

            counters_ipc->track_clients_client_count++;

            File_Unlock(config->shm_counters);
            File_Unlock(config->shm_track_clients);

            pthread_mutex_unlock(&IPCTrackClientCounter);

            return;

        }
    else
        {

            File_Unlock(config->shm_track_clients);
            pthread_mutex_unlock(&IPCTrackClientCounter);

            Sagan_Log(WARN, "[%s, line %d] Client tracking has reached it's max! (%d).  Increase 'track_clients' in your configuration!", __FILE__, __LINE__, config->max_track_clients);

        }

} /* Close sagan_track_clients */

/****************************************************************************
 * Sagan_Track_Clients_Init - Initialize shared memory object for the
 * tracking client processor to use
 ****************************************************************************/

void Track_Clients_Thread_Init ( void )
{

    processor_info_track_client = malloc(sizeof(struct _Sagan_Processor_Info));

    if ( processor_info_track_client == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for processor_info_track_client. Abort!", __FILE__, __LINE__);
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
 * Sagan_Report_Clients - Main routine to "report" via IPC/memory IPs that
 * are reporting or not.
 ****************************************************************************/

void Track_Clients_Thread ( void )
{

    /* GeoIP struct for Send_Alert */

    struct _GeoIP *GeoIP = NULL;
    GeoIP = malloc(sizeof(struct _GeoIP));

    if ( GeoIP == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _GeoIP (DEST). Abort!", __FILE__, __LINE__);
        }

    memset(GeoIP, 0, sizeof(_GeoIP));
    memcpy(GeoIP->country, "NONE", 4);

    for(;;)
        {

#ifdef HAVE_SYS_PRCTL_H
            (void)SetThreadName("SaganClientTrck");
#endif

            struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL = NULL;

            int alertid;
            int i;

            const char *tmp_ip = NULL;

            char utime_tmp[20] = { 0 };
            time_t t;
            struct tm *now;

            uint64_t utime_u32;

            struct timeval tp;

            t = time(NULL);
            now=localtime(&t);
            strftime(utime_tmp, sizeof(utime_tmp), "%s",  now);
            utime_u32 = atol(utime_tmp);

            int expired_time = config->pp_sagan_track_clients * 60;

            /* We populate this later for output plugins */

            SaganProcSyslog_LOCAL = malloc(sizeof(struct _Sagan_Proc_Syslog));

            if ( SaganProcSyslog_LOCAL == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog_LOCAL. Abort!", __FILE__, __LINE__);
                }

            /*********************************/
            /* Look through "known" system   */
            /*********************************/

            for (i=0; i<counters_ipc->track_clients_client_count; i++)
                {

                    /* Check if host is in a down state */

                    if ( SaganTrackClients_ipc[i].status == 1 )
                        {

                            /* If host was done, verify host last seen time is still not an expired time */

                            if ( ( utime_u32 - SaganTrackClients_ipc[i].utime ) < expired_time )
                                {

                                    /* Update status and seen time */

                                    pthread_mutex_lock(&IPCTrackClientsStatus);

                                    File_Lock(config->shm_track_clients);

                                    SaganTrackClients_ipc[i].status = 0;

                                    /* Update counters */

                                    File_Lock(config->shm_counters);

                                    counters_ipc->track_clients_down--;

                                    File_Unlock(config->shm_counters);
                                    File_Unlock(config->shm_track_clients);

                                    pthread_mutex_unlock(&IPCTrackClientsStatus);


                                    tmp_ip = Bit2IP(SaganTrackClients_ipc[i].hostbits, NULL, 0);

                                    Sagan_Log(WARN, "[Processor: %s] Logs are being received from %s again.",  PROCESSOR_NAME, tmp_ip );

                                    /* Populate SaganProcSyslog_LOCAL for output plugins */

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, tmp_ip, sizeof(SaganProcSyslog_LOCAL->syslog_host));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_facility, PROCESSOR_FACILITY, sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_priority, PROCESSOR_PRIORITY, sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_level, "info", sizeof(SaganProcSyslog_LOCAL->syslog_level));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_tag, "00", sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, PROCESSOR_NAME, sizeof(SaganProcSyslog_LOCAL->syslog_program));

                                    Return_Date(utime_u32, SaganProcSyslog_LOCAL->syslog_date, sizeof(SaganProcSyslog_LOCAL->syslog_date));
                                    Return_Time(utime_u32, SaganProcSyslog_LOCAL->syslog_time, sizeof(SaganProcSyslog_LOCAL->syslog_time));

                                    snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message)-1, "The IP address %s was previously not sending logs. The system appears to be sending logs again at %s", tmp_ip, ctime(&SaganTrackClients_ipc[i].utime) );

                                    alertid=101;		/* See gen-msg.map */

                                    gettimeofday(&tp, 0);

                                    /* Send alert to output plugins */

                                    Send_Alert(SaganProcSyslog_LOCAL,
                                               "null",
                                               processor_info_track_client,
                                               SaganProcSyslog_LOCAL->syslog_host,
                                               config->sagan_host,
                                               NULL,
                                               NULL,
                                               config->sagan_proto,
                                               alertid,
                                               config->sagan_port,
                                               config->sagan_port,
                                               0, tp, NULL, 0, GeoIP, GeoIP);
                                } /* End last seen check time */

                        }
                    else
                        {

                            /**** Check if last seen time of host has exceeded track time meaning it's down! ****/

                            if ( ( utime_u32 - SaganTrackClients_ipc[i].utime ) >= expired_time )
                                {

                                    /* Update status and utime */

                                    pthread_mutex_lock(&IPCTrackClientsStatus);

                                    File_Lock(config->shm_track_clients);

                                    SaganTrackClients_ipc[i].status = 1;

                                    /* Update counters */

                                    File_Lock(config->shm_counters);

                                    counters_ipc->track_clients_down++;

                                    File_Unlock(config->shm_counters);
                                    File_Unlock(config->shm_track_clients);

                                    pthread_mutex_unlock(&IPCTrackClientsStatus);

                                    tmp_ip = Bit2IP(SaganTrackClients_ipc[i].hostbits, NULL, 0);

                                    Sagan_Log(WARN, "[Processor: %s] Logs have not been seen from %s for %d minute(s).", PROCESSOR_NAME, tmp_ip, config->pp_sagan_track_clients);

                                    /* Populate SaganProcSyslog_LOCAL for output plugins */

                                    strlcpy(SaganProcSyslog_LOCAL->syslog_host, tmp_ip, sizeof(SaganProcSyslog_LOCAL->syslog_host));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_facility, PROCESSOR_FACILITY, sizeof(SaganProcSyslog_LOCAL->syslog_facility));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_priority, PROCESSOR_PRIORITY, sizeof(SaganProcSyslog_LOCAL->syslog_priority));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_level, "info", sizeof(SaganProcSyslog_LOCAL->syslog_level));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_tag, "00", sizeof(SaganProcSyslog_LOCAL->syslog_tag));
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_program, PROCESSOR_NAME, sizeof(SaganProcSyslog_LOCAL->syslog_program));

                                    Return_Date(utime_u32, SaganProcSyslog_LOCAL->syslog_date, sizeof(SaganProcSyslog_LOCAL->syslog_date));
                                    Return_Time(utime_u32, SaganProcSyslog_LOCAL->syslog_time, sizeof(SaganProcSyslog_LOCAL->syslog_time));

                                    snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message)-1, "Sagan has not recieved any logs from the IP address %s in over %d minute(s). Last log was seen at %s. This could be an indication that the system is down.", tmp_ip, config->pp_sagan_track_clients, ctime(&SaganTrackClients_ipc[i].utime) );

                                    alertid=100;	/* See gen-msg.map  */

                                    gettimeofday(&tp, 0);


                                    /* Send alert to output plugins */

                                    Send_Alert(SaganProcSyslog_LOCAL,
                                               "null",
                                               processor_info_track_client,
                                               SaganProcSyslog_LOCAL->syslog_host,
                                               config->sagan_host,
                                               NULL,
                                               NULL,
                                               config->sagan_proto,
                                               alertid,
                                               config->sagan_port,
                                               config->sagan_port,
                                               0, tp, NULL, 0, GeoIP, GeoIP);

                                }  /* End of existing utime check */

                        } /* End of else */

                }  /* End for 'for' loop */
            free(SaganProcSyslog_LOCAL);
            sleep(60);

        } /* End Ifinite Loop */

} /* End Sagan_report_clients */
