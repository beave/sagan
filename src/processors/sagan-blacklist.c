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
#include <math.h>
#include "sagan.h"
#include "sagan-blacklist.h"
#include "sagan-liblognorm.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _Sagan_Blacklist *SaganBlacklist;

#ifdef HAVE_LIBLOGNORM
struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm = NULL;
#endif


int Sagan_Blacklist_Load ( void ) {

FILE *blacklist;
char *tok=NULL;
char *tmpmask=NULL;
int mask=0;

char *iprange=NULL;

char blacklistbuf[1024] = { 0 };

counters->blacklist_count=0;

if (( blacklist = fopen(config->blacklist_file, "r" )) == NULL ) {
   Sagan_Log(2, "[%s, line %d] No blacklist ignore list to load (%s)", __FILE__, __LINE__, config->blacklist_file);
   config->blacklist_flag=0;
   return(0);
   }

while(fgets(blacklistbuf, 1024, blacklist) != NULL) {

     /* Skip comments and blank linkes */

     if (blacklistbuf[0] == '#' || blacklistbuf[0] == 10 || blacklistbuf[0] == ';' || blacklistbuf[0] == 32) {
     continue;

     } else {

     /* Allocate memory for references,  not comments */
     SaganBlacklist = (_Sagan_Blacklist *) realloc(SaganBlacklist, (counters->blacklist_count+1) * sizeof(_Sagan_Blacklist));

     iprange = strtok_r(blacklistbuf, "/", &tok);
     tmpmask = strtok_r(NULL, "/", &tok);
     mask = atoi(tmpmask); 

     /* Should do better error checking? */

     if ( iprange == NULL ) Sagan_Log(1, "[%s, line %d] Invalid range in %s file", __FILE__, __LINE__, config->blacklist_file);
     if ( mask == 0 ) Sagan_Log(1, "[%s, line %d] Invalid mask in %s file", __FILE__, __LINE__, config->blacklist_file);

     /* Record lower and upper range based on the /CIDR.  We then use ip2bit(ipaddr) to determine
      * if it's within the blacklist range. 
      *
      * Idea came from "ashitpro"
      * http://bytes.com/topic/c/answers/765104-determining-whether-given-ip-exist-cidr-ip-range
      *
      */
     
     SaganBlacklist[counters->blacklist_count].u32_lower = ip2bit(iprange);
     SaganBlacklist[counters->blacklist_count].u32_higher = SaganBlacklist[counters->blacklist_count].u32_lower + (pow(2,32-mask)-1); 
     counters->blacklist_count++;
     }
  }

return(0);
}


int Sagan_Blacklist( _SaganProcSyslog *SaganProcSyslog_LOCAL ) { 

int i=0; 
int b=0; 

char ipaddr[16] = { 0 }; 

char *ipaddrptr=NULL;

uint32_t u32_ipaddr;
char *ip_src = NULL;
char *ip_dst = NULL;

#ifdef HAVE_LIBLOGNORM
SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));
memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));

SaganNormalizeLiblognorm = sagan_normalize_liblognorm(SaganProcSyslog_LOCAL->syslog_message);
ip_src = SaganNormalizeLiblognorm->ip_src;
ip_dst = SaganNormalizeLiblognorm->ip_dst;
free(SaganNormalizeLiblognorm);
#endif

if ( ip_src != NULL ) { 
   u32_ipaddr = ip2bit(ip_src);
   if ( u32_ipaddr > SaganBlacklist[b].u32_lower && u32_ipaddr < SaganBlacklist[b].u32_higher || u32_ipaddr == SaganBlacklist[b].u32_lower ) {
      Sagan_Blacklist_Send_Alert(SaganProcSyslog_LOCAL, ip_src, SaganProcSyslog_LOCAL->syslog_host, 17);
      }
}

if ( ip_dst != NULL ) {
   u32_ipaddr = ip2bit(ip_dst);
   if ( u32_ipaddr > SaganBlacklist[b].u32_lower && u32_ipaddr < SaganBlacklist[b].u32_higher || u32_ipaddr == SaganBlacklist[b].u32_lower ) {
      Sagan_Blacklist_Send_Alert(SaganProcSyslog_LOCAL, SaganProcSyslog_LOCAL->syslog_host, ip_dst, 17);
      }
}

if ( ip_src != NULL || ip_dst != NULL ) return(0); 		/* No need to parse_ip() */

for (i=1; i < config->blacklist_parse_depth+1; i++) { 

      snprintf(ipaddr, sizeof(ipaddr), "%s", parse_ip(SaganProcSyslog_LOCAL->syslog_message, i));

       if (strcmp(ipaddr, "0")) {

          u32_ipaddr = ip2bit(ipaddr);

	   for (b=0; b < counters->blacklist_count; b++) { 

	       /* The || catches /32 masks */

	       if ( u32_ipaddr > SaganBlacklist[b].u32_lower && u32_ipaddr < SaganBlacklist[b].u32_higher || u32_ipaddr == SaganBlacklist[b].u32_lower ) { 

	          if ( i%2 == 0 ) 
		     {
		     ipaddrptr = ipaddr;
		     Sagan_Blacklist_Send_Alert(SaganProcSyslog_LOCAL, SaganProcSyslog_LOCAL->syslog_host, ipaddrptr, 17);
		     } else { 
		     ipaddrptr = ipaddr;
		     Sagan_Blacklist_Send_Alert(SaganProcSyslog_LOCAL, ipaddrptr, SaganProcSyslog_LOCAL->syslog_host, 17);
		     }
		  }
	   }

        } else { 

           if ( i == 0 ) break;         /* If we're on the first position and fail to find a valid IP
                                           there's no point going to position 2, 3, 4 ...  */
	}
    }
 
}

void Sagan_Blacklist_Send_Alert ( _SaganProcSyslog *SaganProcSyslog_LOCAL, char *ip_src, char*ip_dst, int proto  ) {
char tmp[64] = { 0 };

        struct _Sagan_Event *SaganProcessorEvent = NULL;
        SaganProcessorEvent = malloc(sizeof(struct _Sagan_Event));
        memset(SaganProcessorEvent, 0, sizeof(_SaganEvent));

//        SaganProcessorEvent->f_msg = generator_msg;
	SaganProcessorEvent->f_msg = "Address in blacklist";	
        SaganProcessorEvent->message = SaganProcSyslog_LOCAL->syslog_message;

        SaganProcessorEvent->program         =       BLACKLIST_PROCESSOR_NAME;
        SaganProcessorEvent->facility        =       BLACKLIST_PROCESSOR_FACILITY;
        SaganProcessorEvent->priority        =       BLACKLIST_PROCESSOR_PRIORITY;

        SaganProcessorEvent->pri             =       BLACKLIST_PROCESSOR_PRI;
        SaganProcessorEvent->class           =       BLACKLIST_PROCESSOR_CLASS;
        SaganProcessorEvent->tag             =       BLACKLIST_PROCESSOR_TAG;
        SaganProcessorEvent->rev             =       BLACKLIST_PROCESSOR_REV;

        SaganProcessorEvent->ip_src          =       ip_src;
        SaganProcessorEvent->ip_dst          =       ip_dst;
        SaganProcessorEvent->dst_port        =       config->sagan_port;
        SaganProcessorEvent->src_port        =       config->sagan_port;
        SaganProcessorEvent->found           =       0;

        snprintf(tmp, sizeof(tmp), "1");
        SaganProcessorEvent->sid             =       tmp;
        SaganProcessorEvent->time            =       SaganProcSyslog_LOCAL->syslog_time;
        SaganProcessorEvent->date            =       SaganProcSyslog_LOCAL->syslog_date;
        SaganProcessorEvent->ip_proto        =       proto;

        SaganProcessorEvent->event_time_sec  =          time(NULL);

        SaganProcessorEvent->generatorid     =       BLACKLIST_PROCESSOR_GENERATOR_ID;

        Sagan_Output ( SaganProcessorEvent );
        free(SaganProcessorEvent);
}

