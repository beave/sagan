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
   Sagan_Log(2, "[%s, line %d] No search list to load (%s)", __FILE__, __LINE__, config->search_nocase_file);

   if ( type == 1 ) config->search_nocase_flag=0;
    else config->search_case_flag=0;

   return(0);
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

uint32_t u32_tmpip;
char *ip_tmp = NULL;

struct _Sagan_Processor_Info *processor_info = NULL;
processor_info = malloc(sizeof(struct _Sagan_Processor_Info));
memset(processor_info, 0, sizeof(_Sagan_Processor_Info));

processor_info->processor_name          =       SEARCH_PROCESSOR_NAME;
processor_info->processor_generator_id  =       SEARCH_PROCESSOR_GENERATOR_ID;
processor_info->processor_name          =       SEARCH_PROCESSOR_NAME;
processor_info->processor_facility      =       SEARCH_PROCESSOR_FACILITY;
processor_info->processor_priority      =       SEARCH_PROCESSOR_PRIORITY;
processor_info->processor_pri           =       SEARCH_PROCESSOR_PRI;
processor_info->processor_class         =       SEARCH_PROCESSOR_CLASS;
processor_info->processor_tag           =       SEARCH_PROCESSOR_TAG;
processor_info->processor_rev           =       SEARCH_PROCESSOR_REV;

/* If the IP is 127.0.0.1, we use config->sagan_host */

ip_tmp = SaganProcSyslog_LOCAL->syslog_host;
u32_tmpip = IP2Bit(SaganProcSyslog_LOCAL->syslog_host);
if ( u32_tmpip == 2130706433 ) ip_tmp = config->sagan_host;

if ( type == 1 ) {

for (i=0; i<counters->search_nocase_count; i++) { 

if (strcasestr(SaganProcSyslog_LOCAL->syslog_message, SaganNocaseSearchlist[i].search )) { 
   counters->search_nocase_hit_count++;
   Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info, SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_host, config->sagan_proto, 1);

   }
 }
} else { 

for (i=0; i<counters->search_case_count; i++) {

if (strstr(SaganProcSyslog_LOCAL->syslog_message, SaganCaseSearchlist[i].search )) {
   counters->search_case_hit_count++;
   Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info, SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_host, config->sagan_proto, 2);
   }
 }
}

}

