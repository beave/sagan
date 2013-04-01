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
     SaganCaseSearchlist = (_Sagan_Case_Searchlist *) realloc(SaganCaseSearchlist, (counters->search_nocase_count+1) * sizeof(_Sagan_Case_Searchlist));
     snprintf(SaganCaseSearchlist[counters->search_case_count].search, sizeof(SaganCaseSearchlist[counters->search_case_count].search), "%s", Remove_Return(searchbuf));
     counters->search_case_count++;
     }

     }
   }

return(0);
}


int Sagan_Search (_SaganProcSyslog *SaganProcSyslog_LOCAL, int type ) {

int i; 

if ( type == 1 ) {

for (i=0; i<counters->search_nocase_count; i++) { 

if (strcasestr(SaganProcSyslog_LOCAL->syslog_message, SaganNocaseSearchlist[i].search )) { 
   Sagan_Search_Send_Alert(SaganProcSyslog_LOCAL, 1);
   }
 }
} else { 

for (i=0; i<counters->search_case_count; i++) {

if (strstr(SaganProcSyslog_LOCAL->syslog_message, SaganCaseSearchlist[i].search )) {
   Sagan_Search_Send_Alert(SaganProcSyslog_LOCAL, 2);
   }
 }
}

}


void Sagan_Search_Send_Alert ( _SaganProcSyslog *SaganProcSyslog_LOCAL, int alertid ) { 

char tmp[64] = { 0 };
char *msg=NULL; 

        struct _Sagan_Event *SaganProcessorEvent = NULL;
        SaganProcessorEvent = malloc(sizeof(struct _Sagan_Event));
        memset(SaganProcessorEvent, 0, sizeof(_SaganEvent));

	SaganProcessorEvent->f_msg           =       Sagan_Generator_Lookup(SEARCH_PROCESSOR_GENERATOR_ID, alertid);
        SaganProcessorEvent->message         = 	     SaganProcSyslog_LOCAL->syslog_message;

        SaganProcessorEvent->program         =       SEARCH_PROCESSOR_NAME;
        SaganProcessorEvent->facility        =       SEARCH_PROCESSOR_FACILITY;
        SaganProcessorEvent->priority        =       SEARCH_PROCESSOR_PRIORITY;

        SaganProcessorEvent->pri             =       SEARCH_PROCESSOR_PRI;
        SaganProcessorEvent->class           =       SEARCH_PROCESSOR_CLASS;
        SaganProcessorEvent->tag             =       SEARCH_PROCESSOR_TAG;
        SaganProcessorEvent->rev             =       SEARCH_PROCESSOR_REV;

	SaganProcessorEvent->ip_src	     =	     SaganProcSyslog_LOCAL->syslog_host;
	SaganProcessorEvent->ip_dst          =       SaganProcSyslog_LOCAL->syslog_host;

        SaganProcessorEvent->dst_port        =       config->sagan_port; 
        SaganProcessorEvent->src_port        =       config->sagan_port;
        SaganProcessorEvent->found           =       0;

        snprintf(tmp, sizeof(tmp), "1");
        SaganProcessorEvent->sid             =       tmp;
        SaganProcessorEvent->time            =       SaganProcSyslog_LOCAL->syslog_time;
        SaganProcessorEvent->date            =       SaganProcSyslog_LOCAL->syslog_date;
        SaganProcessorEvent->ip_proto        =       config->sagan_proto;

        SaganProcessorEvent->event_time_sec  =          time(NULL);

        SaganProcessorEvent->generatorid     =       SEARCH_PROCESSOR_GENERATOR_ID;

        Sagan_Output ( SaganProcessorEvent );
        free(SaganProcessorEvent);
}


