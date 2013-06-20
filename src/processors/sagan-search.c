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

/* sagan-search.c 
*
* This processor takes a list of terms and searchs for them in log lines.
* For example,  a list of known malware domain names
*  
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#define _GNU_SOURCE		/* for strcasestr() */

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-search.h"
#include "sagan-liblognorm.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;

struct _Sagan_Nocase_Searchlist *SaganNocaseSearchlist;
struct _Sagan_Case_Searchlist *SaganCaseSearchlist;


int Sagan_Search_Load ( int type ) {

FILE *search;
char searchbuf[1024] = { 0 };
char tmpfile[MAXPATH];

if ( type == 1 ) { 
   snprintf(tmpfile, sizeof(tmpfile), "%s", config->search_nocase_file); 
   } else { 
   snprintf(tmpfile, sizeof(tmpfile), "%s", config->search_case_file);
   }

if (( search = fopen(tmpfile, "r" )) == NULL ) {
   Sagan_Log(1, "[%s, line %d] No search list to load (%s)", __FILE__, __LINE__, config->search_nocase_file);
   }

while(fgets(searchbuf, 1024, search) != NULL) {

     /* Skip comments and blank linkes */

     if (searchbuf[0] == '#' || searchbuf[0] == 10 || searchbuf[0] == ';' || searchbuf[0] == 32) {
     continue;

     } else {

     if ( type == 1) { 
     SaganNocaseSearchlist = (_Sagan_Nocase_Searchlist *) realloc(SaganNocaseSearchlist, (counters->search_nocase_count+1) * sizeof(_Sagan_Nocase_Searchlist));
     snprintf(SaganNocaseSearchlist[counters->search_nocase_count].search, sizeof(SaganNocaseSearchlist[counters->search_nocase_count].search), "%s", Remove_Return(searchbuf)); 
     counters->search_nocase_count++;
     } else { 
     SaganCaseSearchlist = (_Sagan_Case_Searchlist *) realloc(SaganCaseSearchlist, (counters->search_case_count+1) * sizeof(_Sagan_Case_Searchlist));
     snprintf(SaganCaseSearchlist[counters->search_case_count].search, sizeof(SaganCaseSearchlist[counters->search_case_count].search), "%s", Remove_Return(searchbuf));
     counters->search_case_count++;
     }

     }
   }

return(0);
}


void Sagan_Search (_SaganProcSyslog *SaganProcSyslog_LOCAL, int type ) {

int i; 

char f_src_ip[64] = { 0 }; 
char f_dst_ip[64] = { 0 };

char *ip_src = NULL;
char *ip_dst = NULL;

int   src_port = 0; 
int   dst_port = 0;
int   proto = 0; 

struct _Sagan_Processor_Info *processor_info = NULL;
processor_info = malloc(sizeof(struct _Sagan_Processor_Info));
memset(processor_info, 0, sizeof(_Sagan_Processor_Info));

#ifdef HAVE_LIBLOGNORM
struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm = NULL;
#endif

processor_info->processor_name          =       SEARCH_PROCESSOR_NAME;
processor_info->processor_generator_id  =       SEARCH_PROCESSOR_GENERATOR_ID;
processor_info->processor_name          =       SEARCH_PROCESSOR_NAME;
processor_info->processor_facility      =       SEARCH_PROCESSOR_FACILITY;
processor_info->processor_priority      =       SEARCH_PROCESSOR_PRIORITY;
processor_info->processor_pri           =       SEARCH_PROCESSOR_PRI;
processor_info->processor_class         =       SEARCH_PROCESSOR_CLASS;
processor_info->processor_tag           =       SEARCH_PROCESSOR_TAG;
processor_info->processor_rev           =       SEARCH_PROCESSOR_REV;

proto = config->sagan_proto; 


if ( type == 1 ) {

for (i=0; i<counters->search_nocase_count; i++) { 

if (strcasestr(SaganProcSyslog_LOCAL->syslog_message, SaganNocaseSearchlist[i].search )) { 
   
   counters->search_nocase_hit_count++;

#ifdef HAVE_LIBLOGNORM
if ( config->search_nocase_lognorm) {
   SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));
   memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));
   ip_src = SaganNormalizeLiblognorm->ip_src;
   ip_dst = SaganNormalizeLiblognorm->ip_dst;
   src_port = SaganNormalizeLiblognorm->src_port;
   dst_port = SaganNormalizeLiblognorm->dst_port;
   free(SaganNormalizeLiblognorm);
}
#endif

   if ( src_port == 0 ) src_port = config->sagan_port;
   if ( dst_port == 0 ) dst_port = config->sagan_port;


   if ( config->search_nocase_parse_src && ip_src == NULL ) { 
      snprintf(f_src_ip, sizeof(f_src_ip), "%s", parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->search_nocase_parse_src));
         if (strcmp(f_src_ip,"0")) { 
	    ip_src = f_src_ip;
	    } else { 
	    ip_src = SaganProcSyslog_LOCAL->syslog_host;
	    }
   }

   if ( config->search_nocase_parse_dst && ip_dst == NULL ) {
       snprintf(f_dst_ip, sizeof(f_dst_ip), "%s", parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->search_nocase_parse_dst));
          if (strcmp(f_dst_ip,"0")) { 
	     ip_dst = f_dst_ip;
	     } else { 
	     ip_dst = SaganProcSyslog_LOCAL->syslog_host;
	     }
   }

   if ( config->search_nocase_parse_proto ) proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);
     
   Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info, ip_src, ip_dst, proto, 1, src_port, dst_port);

   }
 }
} else { 

for (i=0; i<counters->search_case_count; i++) {

if (strstr(SaganProcSyslog_LOCAL->syslog_message, SaganCaseSearchlist[i].search )) {

   counters->search_case_hit_count++;

#ifdef HAVE_LIBLOGNORM
if ( config->search_case_lognorm) { 
   SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));
   memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));
   ip_src = SaganNormalizeLiblognorm->ip_src;
   ip_dst = SaganNormalizeLiblognorm->ip_dst;
   src_port = SaganNormalizeLiblognorm->src_port;
   dst_port = SaganNormalizeLiblognorm->dst_port;
   free(SaganNormalizeLiblognorm);
   }
#endif

   if ( src_port == 0 ) src_port = config->sagan_port;
   if ( dst_port == 0 ) dst_port = config->sagan_port;

   if ( config->search_case_parse_src ) {
      snprintf(f_src_ip, sizeof(f_src_ip), "%s", parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->search_case_parse_src));
         if (strcmp(f_src_ip,"0")) { 
	    ip_src = f_src_ip;
	    } else { 
	    ip_src = SaganProcSyslog_LOCAL->syslog_host;
	    }
   }

   if ( config->search_case_parse_dst ) {
      snprintf(f_dst_ip, sizeof(f_dst_ip), "%s", parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->search_case_parse_dst));
         if (strcmp(f_dst_ip,"0")) { 
	    ip_dst = f_dst_ip; 
	    } else { 
	    ip_dst = SaganProcSyslog_LOCAL->syslog_host;
	    }
   }

   if ( config->search_nocase_parse_proto ) proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);

   Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info, ip_src, ip_dst, config->sagan_proto, 2, src_port, dst_port);
   }
 }
}

}

