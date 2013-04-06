/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
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

#include "sagan.h"
#include "sagan-track-clients.h"

struct _Sagan_Track_Clients *SaganTrackClients;
struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;

pthread_mutex_t SaganProcTrackClientsMutex=PTHREAD_MUTEX_INITIALIZER;

struct _Sagan_Proc_Syslog *SaganProcSyslog;
int proc_cpu_msgslot;


int sagan_track_clients ( _SaganProcSyslog *SaganProcSyslog_LOCAL ) {

int alertid;

char  timet[20];
time_t t;
struct tm *now;

int i;
sbool tracking_flag=0;

long utimetmp; 

t = time(NULL);
now=localtime(&t);
strftime(timet, sizeof(timet), "%s",  now);

/* Maybe Move ? */
struct _Sagan_Processor_Info *processor_info = NULL;
processor_info = malloc(sizeof(struct _Sagan_Processor_Info));
memset(processor_info, 0, sizeof(_Sagan_Processor_Info));

processor_info->processor_name		=	PROCESSOR_NAME;
processor_info->processor_generator_id	=	PROCESSOR_GENERATOR_ID;
processor_info->processor_name		=	PROCESSOR_NAME;
processor_info->processor_facility	=	PROCESSOR_FACILITY;
processor_info->processor_priority	=	PROCESSOR_PRIORITY;
processor_info->processor_pri		=	PROCESSOR_PRI;
processor_info->processor_class		=	PROCESSOR_CLASS;
processor_info->processor_tag		=	PROCESSOR_TAG;
processor_info->processor_rev		=	PROCESSOR_REV;

for (i=0; i<counters->track_clients_client_count; i++) { 


    if (!strcmp(SaganProcSyslog_LOCAL->syslog_host, SaganTrackClients[i].host)) { 

    	pthread_mutex_lock(&SaganProcTrackClientsMutex); 

        SaganTrackClients[i].utime = atol(timet);

	if ( SaganTrackClients[i].status == 1 ) { 
	   
	   Sagan_Log(2, "[Processor: %s] Logs being received from %s again.",  PROCESSOR_NAME, SaganTrackClients[i].host);
	   snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), "The IP address %s was previous reported as being down or not receiving logs.  The system appears to be sending logs again", SaganTrackClients[i].host);
	   counters->track_clients_down--; 

	   alertid=101;
	   SaganTrackClients[i].status = 0;
	   Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info, SaganTrackClients[i].host, config->sagan_host, config->sagan_proto, alertid);
	   }

	pthread_mutex_unlock(&SaganProcTrackClientsMutex);
	tracking_flag=1;
	}

	utimetmp = SaganTrackClients[i].utime ; 

	//if ( atol(timet) - SaganTrackClients[i].utime >  config->pp_sagan_track_clients * 60 && SaganTrackClients[i].status == 0 ) { 
	if ( atol(timet) - utimetmp >  config->pp_sagan_track_clients * 60 && SaganTrackClients[i].status == 0 ) {

	   counters->track_clients_down++; 

	   Sagan_Log(2, "[Processor: %s] Logs have not been seen from %s for %d minute(s).", PROCESSOR_NAME, SaganTrackClients[i].host, config->pp_sagan_track_clients);
   	   snprintf(SaganProcSyslog_LOCAL->syslog_message, sizeof(SaganProcSyslog_LOCAL->syslog_message), "Sagan has not recieved any logs from the IP address %s in over %d minute(s). This could be an indication that the system is down.", SaganTrackClients[i].host, config->pp_sagan_track_clients);

	   alertid=100;

	   pthread_mutex_lock(&SaganProcTrackClientsMutex);
	   SaganTrackClients[i].status = 1;
	   pthread_mutex_unlock(&SaganProcTrackClientsMutex);

	   Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info, SaganTrackClients[i].host, config->sagan_host, config->sagan_proto, alertid);
	   }

}

if ( tracking_flag == 0) { 
   
   pthread_mutex_lock(&SaganProcTrackClientsMutex);

   SaganTrackClients = (_Sagan_Track_Clients *) realloc(SaganTrackClients, (counters->track_clients_client_count+1) * sizeof(_Sagan_Track_Clients));
   snprintf(SaganTrackClients[counters->track_clients_client_count].host, sizeof(SaganTrackClients[counters->track_clients_client_count].host), "%s", SaganProcSyslog_LOCAL->syslog_host);
   SaganTrackClients[counters->track_clients_client_count].utime = atol(timet);
   SaganTrackClients[counters->track_clients_client_count].status = 0;
   counters->track_clients_client_count++;
   pthread_mutex_unlock(&SaganProcTrackClientsMutex);

  }

return(0);
}

