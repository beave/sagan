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

#define PROCESSOR_NAME "Sagan_Track_Clients"
#define PROCESSOR_FACILITY "daemon"
#define PROCESSOR_PRIORITY "warning"
#define PROCESSOR_PRI 1
#define PROCESSOR_CLASS "None"
#define PROCESSOR_REV "0"
#define PROCESSOR_TAG NULL
#define PROCESSOR_GENERATOR_ID 100

typedef struct _Sagan_Track_Clients _Sagan_Track_Clients;
struct _Sagan_Track_Clients  {
char    host[64];
uint64_t utime;
sbool   status;
};


int sagan_track_clients ( _SaganProcSyslog * );
