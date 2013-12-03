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

/* sagan-blacklist.c 
*
* This searches log lines for IP addresses/networks that are loaded
* from a "blacklist" file.  For example,  you might search log lines for
* known bad IP/Networks.  This processor uses the CIDR format: 
* 192.168.1.1/32 (single ip) or 192.168.1.0./24.
*  
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pthread.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-blacklist.h"
#include "sagan-liblognorm.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _Sagan_Blacklist *SaganBlacklist;

struct _Sagan_Processor_Info *processor_info_blacklist = NULL;

#ifdef HAVE_LIBLOGNORM
struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm;
pthread_mutex_t Lognorm_Mutex;
#endif


int Sagan_Blacklist_Load ( void ) {

FILE *blacklist;
char *tok=NULL;
char *tmpmask=NULL;
int mask=0;
char tmp[1024] = { 0 };
char *iprange=NULL;
char blacklistbuf[1024] = { 0 };

processor_info_blacklist = malloc(sizeof(struct _Sagan_Processor_Info));
memset(processor_info_blacklist, 0, sizeof(_Sagan_Processor_Info));

processor_info_blacklist->processor_name          =       BLACKLIST_PROCESSOR_NAME;
processor_info_blacklist->processor_generator_id  =       BLACKLIST_PROCESSOR_GENERATOR_ID;
processor_info_blacklist->processor_name          =       BLACKLIST_PROCESSOR_NAME;
processor_info_blacklist->processor_facility      =       BLACKLIST_PROCESSOR_FACILITY;
processor_info_blacklist->processor_priority      =       BLACKLIST_PROCESSOR_PRIORITY;
processor_info_blacklist->processor_pri           =       BLACKLIST_PROCESSOR_PRI;
processor_info_blacklist->processor_class         =       BLACKLIST_PROCESSOR_CLASS;
processor_info_blacklist->processor_tag           =       BLACKLIST_PROCESSOR_TAG;
processor_info_blacklist->processor_rev           =       BLACKLIST_PROCESSOR_REV;

counters->blacklist_count=0;

if (( blacklist = fopen(config->blacklist_file, "r" )) == NULL ) {
   Sagan_Log(S_ERROR, "[%s, line %d] Could not load blacklist file! (%s)", __FILE__, __LINE__, config->blacklist_file);
   }

while(fgets(blacklistbuf, 1024, blacklist) != NULL) {

     /* Skip comments and blank linkes */

     if (blacklistbuf[0] == '#' || blacklistbuf[0] == 10 || blacklistbuf[0] == ';' || blacklistbuf[0] == 32) {
     continue;

     } else {

     /* Allocate memory for references,  not comments */
     SaganBlacklist = (_Sagan_Blacklist *) realloc(SaganBlacklist, (counters->blacklist_count+1) * sizeof(_Sagan_Blacklist));

     Remove_Return(blacklistbuf);

     iprange = NULL; 
     tmpmask = NULL; 

     iprange = strtok_r(blacklistbuf, "/", &tok);
     tmpmask = strtok_r(NULL, "/", &tok);

     if ( tmpmask == NULL ) { 
     /* If there is no CIDR,  then assume it's a /32 */
     strlcpy(tmp, iprange, sizeof(tmp));
     iprange = tmp; 
     mask = 32; 
     } else { 
     mask = atoi(tmpmask); 
     }

     /* Should do better error checking? */

     if ( iprange == NULL ) Sagan_Log(S_ERROR, "[%s, line %d] Invalid range in %s file", __FILE__, __LINE__, config->blacklist_file);
     if ( mask == 0 ) Sagan_Log(S_ERROR, "[%s, line %d] Invalid mask in %s file", __FILE__, __LINE__, config->blacklist_file);

     /* Record lower and upper range based on the /CIDR.  We then use IP2Bit(ipaddr) to determine
      * if it's within the blacklist range. 
      *
      * Idea came from "ashitpro"
      * http://bytes.com/topic/c/answers/765104-determining-whether-given-ip-exist-cidr-ip-range
      *
      */

     SaganBlacklist[counters->blacklist_count].u32_lower = IP2Bit(iprange);
     SaganBlacklist[counters->blacklist_count].u32_higher = SaganBlacklist[counters->blacklist_count].u32_lower + (pow(2,32-mask)-1); 
     counters->blacklist_count++;
     }
  }

return(0);
}


int Sagan_Blacklist( _SaganProcSyslog *SaganProcSyslog_LOCAL ) { 

int i=0; 
int b=0; 

char *ipaddr_found=NULL; 
char *ipaddrptr=NULL;

uint32_t u32_ipaddr;

char *ip_src = NULL;
char *ip_dst = NULL;
char ip_src_tmp[64] = { 0 }; 
char ip_dst_tmp[64] = { 0 }; 
char ip_tmp[64] = { 0 };

int   src_port = 0;
int   dst_port = 0;
int   proto = 0; 

#ifdef HAVE_LIBLOGNORM
if (config->blacklist_lognorm)  { 

pthread_mutex_lock(&Lognorm_Mutex);
sagan_normalize_liblognorm(SaganProcSyslog_LOCAL->syslog_message);
ip_src = SaganNormalizeLiblognorm->ip_src;
ip_dst = SaganNormalizeLiblognorm->ip_dst;
src_port = SaganNormalizeLiblognorm->src_port;
dst_port = SaganNormalizeLiblognorm->dst_port;

pthread_mutex_unlock(&Lognorm_Mutex);

 if ( ip_src != NULL || ip_dst != NULL ) { 

   if ( ip_src != NULL ) { 
      u32_ipaddr = IP2Bit(ip_src); 
      
      for (b=0; b < counters->blacklist_count; b++) {

	  if ( ( u32_ipaddr > SaganBlacklist[b].u32_lower && u32_ipaddr < SaganBlacklist[b].u32_higher ) || ( u32_ipaddr == SaganBlacklist[b].u32_lower ) ) {

	        counters->blacklist_hit_count++;  

		if ( config->blacklist_parse_proto ) proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);
		if ( config->blacklist_parse_proto_program ) proto = parse_proto_program(SaganProcSyslog_LOCAL->syslog_program);
		if ( proto == 0 ) proto = config->sagan_proto; 
		if ( ip_dst == NULL ) ip_dst = config->sagan_host;
		if ( src_port == 0 ) src_port = config->sagan_port;
		if ( dst_port == 0 ) dst_port = config->sagan_port;

	        Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info_blacklist, ip_src, ip_dst, config->sagan_proto, 1, src_port, dst_port);
		}
	}
 }
}

/*
if ip_src != NULL { 
  check ip_src for blacklist if so set flag
  if ip_dst != null,  check for blacklist if so set flag
  }

if flag set { 
   if ip_dst == NULL then ip_dst = config->sagan_host;

*/

if ( ip_src != NULL ) { 
   u32_ipaddr = IP2Bit(ip_src);

   for (b=0; b < counters->blacklist_count; b++) {
   if ( ( u32_ipaddr > SaganBlacklist[b].u32_lower && u32_ipaddr < SaganBlacklist[b].u32_higher ) || ( u32_ipaddr == SaganBlacklist[b].u32_lower ) ) {
      counters->blacklist_hit_count++;

      if ( config->blacklist_parse_proto ) proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);
      if ( config->blacklist_parse_proto_program ) proto = parse_proto_program(SaganProcSyslog_LOCAL->syslog_program);
      if ( proto == 0 ) proto = config->sagan_proto; 

      Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info_blacklist, ip_src, ip_tmp, config->sagan_proto, 1, config->sagan_port, config->sagan_port);
      }
   }
}

if ( ip_dst != NULL ) {
   
   u32_ipaddr = IP2Bit(ip_dst);

   for (b=0; b < counters->blacklist_count; b++) {
   if ( ( u32_ipaddr > SaganBlacklist[b].u32_lower && u32_ipaddr < SaganBlacklist[b].u32_higher ) || ( u32_ipaddr == SaganBlacklist[b].u32_lower ) ) {
      counters->blacklist_hit_count++;

      if ( config->blacklist_parse_proto ) proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);
      if ( config->blacklist_parse_proto_program ) proto = parse_proto_program(SaganProcSyslog_LOCAL->syslog_program);
      if ( proto == 0 ) proto = config->sagan_proto;

      Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info_blacklist, ip_tmp, ip_dst, config->sagan_proto, 1, config->sagan_port, config->sagan_port);
      }
   }
}


if ( config->blacklist_lognorm && (ip_src != NULL || ip_dst != NULL )) return(0); 		/* No need to parse_ip() */

}
#endif 

for (i=1; i < config->blacklist_parse_depth+1; i++) { 

      ipaddr_found = parse_ip(SaganProcSyslog_LOCAL->syslog_message, i, 1); 

       if ( ipaddr_found != NULL ) { 

       	  strlcpy(ip_tmp, ipaddr_found,  sizeof(ip_tmp));


          u32_ipaddr = IP2Bit(ip_tmp);

	   for (b=0; b < counters->blacklist_count; b++) { 

	       /* The || catches /32 masks */

	       if ( ( u32_ipaddr > SaganBlacklist[b].u32_lower && u32_ipaddr < SaganBlacklist[b].u32_higher ) || ( u32_ipaddr == SaganBlacklist[b].u32_lower ) ) { 

	          ipaddrptr = ipaddr_found;
		  counters->blacklist_hit_count++;

		  if ( config->blacklist_parse_src ) { 
		  ip_src = parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->blacklist_parse_src, 1);
		  if ( ip_src == NULL) ip_src = config->sagan_host; 
		  strlcpy(ip_src_tmp, ip_src, sizeof(ip_src_tmp));
		  }

		  if ( config->blacklist_parse_dst ) { 
		  ip_dst = parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->blacklist_parse_dst, 1);
		  if ( ip_dst == NULL ) ip_dst = SaganProcSyslog_LOCAL->syslog_host; 
		  strlcpy(ip_dst_tmp, ip_dst, sizeof(ip_dst_tmp));
		  }
		 
		  if ( config->blacklist_parse_proto ) proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);
		  if ( config->blacklist_parse_proto_program ) proto = parse_proto_program(SaganProcSyslog_LOCAL->syslog_program);
		  if ( proto == 0 ) proto = config->sagan_proto; 

		  if ( strcmp(ip_src, ip_dst ) ) ip_src = SaganProcSyslog_LOCAL->syslog_host;
		  
		  Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info_blacklist, ip_src_tmp, ip_dst_tmp, config->sagan_proto, 1, config->sagan_port, config->sagan_port);
		  }
	   }

        } else { 

           if ( i == 0 ) break;         /* If we're on the first position and fail to find a valid IP
                                           there's no point going to position 2, 3, 4 ...  */
	}
    }

return(0);
}

