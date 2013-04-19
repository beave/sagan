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

/* sagan-engine.c 
 *
 * Threaded ngine that looks for events & patterns * based on 
 * 'snort like' rule sets.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#define _GNU_SOURCE             /* for strcasestr() */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

#include "sagan.h"
#include "processors/sagan-engine.h"

#ifdef HAVE_LIBLOGNORM
#include "sagan-liblognorm.h"
#endif

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;


pthread_mutex_t AfterMutexSrc=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t AfterMutexDst=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t ThreshMutexSrc=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ThreshMutexDst=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t CounterMutex=PTHREAD_MUTEX_INITIALIZER;

/* Global? Was local */

struct after_by_src *afterbysrc = NULL;
struct after_by_dst *afterbydst = NULL;

int  after_count_by_src=0;
int  after_count_by_dst=0;

struct thresh_by_src *threshbysrc = NULL;
struct thresh_by_dst *threshbydst = NULL;

int  thresh_count_by_src=0;
int  thresh_count_by_dst=0;

//uint64_t thresh_oldtime_src;
//uint64_t after_oldtime_src;


pthread_t output_id[MAX_THREADS];
pthread_attr_t thread_output_attr;

int Sagan_Engine ( _SaganProcSyslog *SaganProcSyslog_LOCAL )
{

struct _Sagan_Event *SaganEvent = NULL;

#ifdef HAVE_LIBLOGNORM
struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm = NULL;
#endif

sbool after_log_flag=0;
sbool after_flag=0;

int   threadid=0;
int i=0;
int b=0; 
int z=0; 
int match=0; 
int pcrematch=0;
int rc=0; 
int ovector[PCRE_OVECCOUNT];
int  src_port;
int  dst_port;
int  proto=0;

char *ptmp;
char *tok2;
char *username = NULL;
char *uid = NULL;

char *content;
char *program;
char *facility;
char *syspri;
char *level;
char *tag;

char *ip_src = NULL;
char *ip_dst = NULL;


char tmpbuf[128];
char s_msg[1024];


char f_src_ip[MAXIP];
char f_dst_ip[MAXIP];

time_t t;
struct tm *now;
char  timet[20];

uint64_t thresh_oldtime_src;
uint64_t after_oldtime_src;

sbool thresh_flag=0;
sbool thresh_log_flag=0;

char ip_srctmp[MAXIP];
char ip_dsttmp[MAXIP];


		/* Search for matches */

		/* First we search for 'program' and such.   This way,  we don't waste CPU
		 * time with pcre/content.  */

		for(b=0; b < counters->rulecount; b++) {

                match = 0; program=""; facility=""; syspri=""; level=""; tag=""; content="";

                if ( strcmp(rulestruct[b].s_program, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_program);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                       if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_program)) match=0; 
                       ptmp = strtok_r(NULL, "|", &tok2);
                       }
                }

                if ( strcmp(rulestruct[b].s_facility, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_facility);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                      if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_facility)) match=0;
                      ptmp = strtok_r(NULL, "|", &tok2);
                      }
                }

                if ( strcmp(rulestruct[b].s_syspri, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_syspri);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                      if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_priority)) match=0;
                      ptmp = strtok_r(NULL, "|", &tok2);
                      }
                  }

                if ( strcmp(rulestruct[b].s_level, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_level);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                      if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_level)) match=0;
                       ptmp = strtok_r(NULL, "|", &tok2);
                       }
                   }

                if ( strcmp(rulestruct[b].s_tag, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_tag);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                      if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_tag)) match=0;
                      ptmp = strtok_r(NULL, "|", &tok2);
                      }
                }

		/* If there has been a match above,  or NULL on all,  then we continue with 
		 * PCRE/content search */

		/* Search via strstr (content:) */

		if ( match == 0 ) { 

		if ( rulestruct[b].content_count != 0 ) { 

		for(z=0; z<rulestruct[b].content_count; z++) {

		   /* If case insensitive */
		   if ( rulestruct[b].s_nocase == 1 ) {

		      if (rulestruct[b].content_not[z] != 1 && strcasestr(SaganProcSyslog_LOCAL->syslog_message, rulestruct[b].s_content[z])) 
		         {
			 pcrematch++;
			 } else { 
			 /* for content: ! */
			 if ( rulestruct[b].content_not[z] == 1 && !strcasestr(SaganProcSyslog_LOCAL->syslog_message, rulestruct[b].s_content[z])) pcrematch++;
			 }
		      } else { 

		   /* If case sensitive */
		   if ( rulestruct[b].content_not[z] != 1 && strstr(SaganProcSyslog_LOCAL->syslog_message, rulestruct[b].s_content[z] )) 
		      { 
		      pcrematch++;
		      } else { 
		      /* for content: ! */
		      if ( rulestruct[b].content_not[z] == 1 && !strstr(SaganProcSyslog_LOCAL->syslog_message, rulestruct[b].s_content[z])) pcrematch++;
		      }
		   }
		  }
		 }
	      
	       
	       	/* Search via PCRE */

		if ( rulestruct[b].pcre_count != 0 ) { 

		   for(z=0; z<rulestruct[b].pcre_count; z++) {
		
		   rc = pcre_exec( rulestruct[b].re_pcre[z], rulestruct[b].pcre_extra[z], SaganProcSyslog_LOCAL->syslog_message, (int)strlen(SaganProcSyslog_LOCAL->syslog_message), 0, 0, ovector, PCRE_OVECCOUNT);

                   }  /* End of pcre if */

                if ( rc == 1 ) {
                   pcrematch++;
                   }
                }
		
		} /* End of content: & pcre */
	
		/* if you got match */

		if ( pcrematch == rulestruct[b].pcre_count + rulestruct[b].content_count ) 
		   {
		
		   if ( match == 0 ) { 
		   
		   pthread_mutex_lock(&CounterMutex);
		   counters->saganfound++;
		   pthread_mutex_unlock(&CounterMutex);

		   ip_src=NULL;
		   ip_dst=NULL;
		   dst_port=0;
		   src_port=0;
		   username=NULL;
		   uid=NULL;

#ifdef HAVE_LIBLOGNORM
		   if ( rulestruct[b].normalize == 1 && counters->liblognormtoload_count != 0 ) {
		        
			SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));
			memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));

			SaganNormalizeLiblognorm = sagan_normalize_liblognorm(SaganProcSyslog_LOCAL->syslog_message);
			ip_src = SaganNormalizeLiblognorm->ip_src; 
			ip_dst = SaganNormalizeLiblognorm->ip_dst;
			src_port = SaganNormalizeLiblognorm->src_port;
			dst_port = SaganNormalizeLiblognorm->dst_port;
			username = SaganNormalizeLiblognorm->username;
			uid = SaganNormalizeLiblognorm->uid;

			free(SaganNormalizeLiblognorm);
			}

#endif
/* Normalization always over rides parse_src_ip/parse_port */ 

if ( rulestruct[b].normalize == 0 ) {

 /* parse_src_ip: {position} */

 if ( rulestruct[b].s_find_src_ip == 1 ) {

   snprintf(f_src_ip, sizeof(f_src_ip), "%s", parse_ip(SaganProcSyslog_LOCAL->syslog_message, rulestruct[b].s_find_src_pos));

   if (strcmp(f_src_ip,"0")) {
    	  ip_src = f_src_ip; 
             } else {
      	  ip_src = NULL; 
        }
  }

 /* parse_dst_ip: {postion} */

 if ( rulestruct[b].s_find_dst_ip == 1 ) {

   snprintf(f_dst_ip, sizeof(f_dst_ip), "%s", parse_ip(SaganProcSyslog_LOCAL->syslog_message, rulestruct[b].s_find_dst_pos));

   if (strcmp(f_dst_ip,"0")) {
          ip_dst = f_dst_ip;
             } else {
          ip_dst = NULL; 
        }
  }

/* parse_port */

if ( rulestruct[b].s_find_port == 1 ) {
   src_port = parse_port(SaganProcSyslog_LOCAL->syslog_message);
    } else {
   src_port = config->sagan_port;
   }

if ( rulestruct[b].s_find_proto == 1 ) {
   proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);
    } else {
   proto = rulestruct[b].ip_proto;
   }
}


if ( ip_src == NULL ) ip_src=SaganProcSyslog_LOCAL->syslog_host;
if ( ip_dst == NULL ) ip_dst=SaganProcSyslog_LOCAL->syslog_host;

if ( src_port == 0 ) src_port=config->sagan_port;
if ( dst_port == 0 ) dst_port=rulestruct[b].dst_port;  

snprintf(s_msg, sizeof(s_msg), "%s", rulestruct[b].s_msg);

/* We don't want 127.0.0.1,  so remap it to something more useful */

if (!strcmp(ip_src, "127.0.0.1" )) ip_src=config->sagan_host;
if (!strcmp(ip_dst, "127.0.0.1" )) ip_dst=config->sagan_host;

after_log_flag=0; 

/*********************************************************/
/* After - Similar to thresholding,  but the opposite    */
/* direction - ie - alert _after_ X number of events     */
/*********************************************************/

if ( rulestruct[b].after_src_or_dst != 0 ) {
     
      after_log_flag=1;

      t = time(NULL);
      now=localtime(&t);
      strftime(timet, sizeof(timet), "%s",  now);

      /* After by source IP address */

      if ( rulestruct[b].after_src_or_dst == 1 ) {
         after_flag = 0;

         for (i = 0; i < after_count_by_src; i++ ) {
             if (!strcmp( afterbysrc[i].ipsrc, ip_src ) && !strcmp(afterbysrc[i].sid, rulestruct[b].s_sid )) {

                after_flag=1;
		
		pthread_mutex_lock(&AfterMutexSrc);

                afterbysrc[i].count++;
                after_oldtime_src = atol(timet) - afterbysrc[i].utime;
                afterbysrc[i].utime = atol(timet);

                if ( after_oldtime_src > rulestruct[b].after_seconds ) {
                   afterbysrc[i].count=1;
                   afterbysrc[i].utime = atol(timet);
                   after_log_flag=1;
                   }

		pthread_mutex_unlock(&AfterMutexSrc);

                if ( rulestruct[b].after_count < afterbysrc[i].count )
                        {
                        after_log_flag = 0;
                        Sagan_Log(0, "After SID %s by source IP address. [%s]", afterbysrc[i].sid, ip_src);

			pthread_mutex_lock(&CounterMutex);
                        counters->after_total++;
			pthread_mutex_unlock(&CounterMutex);
                        }

            }
          }
	}


         /* If not found,  add it to the array */

         if ( after_flag == 0 ) {

	    pthread_mutex_lock(&AfterMutexSrc);

            afterbysrc = (after_by_src *) realloc(afterbysrc, (after_count_by_src+1) * sizeof(after_by_src));
            snprintf(afterbysrc[after_count_by_src].ipsrc, sizeof(afterbysrc[after_count_by_src].ipsrc), "%s", ip_src);
            snprintf(afterbysrc[after_count_by_src].sid, sizeof(afterbysrc[after_count_by_src].sid), "%s", rulestruct[b].s_sid );
            afterbysrc[after_count_by_src].count = 1;
            afterbysrc[after_count_by_src].utime = atol(timet);
            after_count_by_src++;

	    pthread_mutex_unlock(&AfterMutexSrc);
            }

      /* After by destination IP address */

        if ( rulestruct[b].after_src_or_dst == 2 ) {
            
	    after_flag = 0;

        /* Check array for matching src / sid */

        for (i = 0; i < after_count_by_dst; i++ ) {
                if (!strcmp( afterbydst[i].ipdst, ip_dst ) && !strcmp(afterbydst[i].sid, rulestruct[b].s_sid )) {
                   after_flag=1;
		  
		   pthread_mutex_lock(&AfterMutexDst);

                   afterbydst[i].count++;
                   after_oldtime_src = atol(timet) - afterbydst[i].utime;
                   afterbydst[i].utime = atol(timet);
                      if ( after_oldtime_src > rulestruct[b].after_seconds ) {
                         afterbydst[i].count=1;
                         afterbydst[i].utime = atol(timet);
                         after_log_flag=1;
                         }

	           pthread_mutex_unlock(&AfterMutexDst);

        if ( rulestruct[b].after_count < afterbydst[i].count ) {
           after_log_flag = 0;
           Sagan_Log(0, "After SID %s by destination IP address. [%s]", afterbysrc[i].sid, ip_dst);

	   pthread_mutex_lock(&CounterMutex);
           counters->after_total++;
	   pthread_mutex_unlock(&CounterMutex);
           }
	 }
       }

        /* If not found,  add it to the array */

        if ( after_flag == 0 ) {

	   pthread_mutex_lock(&AfterMutexDst);

           afterbydst = (after_by_dst *) realloc(afterbydst, (after_count_by_dst+1) * sizeof(after_by_dst));
           snprintf(afterbydst[after_count_by_dst].ipdst, sizeof(afterbydst[after_count_by_dst].ipdst), "%s", ip_dst);
           snprintf(afterbydst[after_count_by_dst].sid, sizeof(afterbydst[after_count_by_dst].sid), "%s", rulestruct[b].s_sid );
           afterbydst[after_count_by_dst].count = 1;
           afterbydst[after_count_by_dst].utime = atol(timet);
           after_count_by_dst++;

	   pthread_mutex_unlock(&AfterMutexDst);
           }
        }

} /* End of After */


thresh_log_flag = 0;

/*********************************************************/
/* Thresh holding                                        */
/*********************************************************/

if ( rulestruct[b].threshold_type != 0 && after_log_flag == 0) { 

      t = time(NULL);
      now=localtime(&t);
      strftime(timet, sizeof(timet), "%s",  now);

      /* Thresholding by source IP address */
		      
      if ( rulestruct[b].threshold_src_or_dst == 1 ) { 
         thresh_flag = 0;
	
	 /* Check array for matching src / sid */

	 for (i = 0; i < thresh_count_by_src; i++ ) { 
	     if (!strcmp( threshbysrc[i].ipsrc, ip_src ) && !strcmp(threshbysrc[i].sid, rulestruct[b].s_sid )) { 

	        thresh_flag=1;

		pthread_mutex_lock(&ThreshMutexSrc);

		threshbysrc[i].count++;
		thresh_oldtime_src = atol(timet) - threshbysrc[i].utime;

		threshbysrc[i].utime = atol(timet);

		if ( thresh_oldtime_src > rulestruct[b].threshold_seconds ) {
		   threshbysrc[i].count=1;
		   threshbysrc[i].utime = atol(timet);
		   thresh_log_flag=0;
		   }

		pthread_mutex_unlock(&ThreshMutexSrc);

		if ( rulestruct[b].threshold_count < threshbysrc[i].count ) 
			{ 
			thresh_log_flag = 1;
			Sagan_Log(0, "Threshold SID %s by source IP address. [%s]", threshbysrc[i].sid, ip_src);

			pthread_mutex_lock(&CounterMutex);
			counters->threshold_total++;
			pthread_mutex_unlock(&CounterMutex);
			}
  	
	     }
	 }
	
	 /* If not found,  add it to the array */
	
	 if ( thresh_flag == 0 ) { 
	    
	    pthread_mutex_lock(&ThreshMutexSrc);

	    threshbysrc = (thresh_by_src *) realloc(threshbysrc, (thresh_count_by_src+1) * sizeof(thresh_by_src));
            snprintf(threshbysrc[thresh_count_by_src].ipsrc, sizeof(threshbysrc[thresh_count_by_src].ipsrc), "%s", ip_src);
	    snprintf(threshbysrc[thresh_count_by_src].sid, sizeof(threshbysrc[thresh_count_by_src].sid), "%s", rulestruct[b].s_sid );
	    threshbysrc[thresh_count_by_src].count = 1;
	    threshbysrc[thresh_count_by_src].utime = atol(timet);
	    thresh_count_by_src++;

	    pthread_mutex_unlock(&ThreshMutexSrc);

	    }
	 }

      /* Thresholding by destination IP address */

	if ( rulestruct[b].threshold_src_or_dst == 2 ) {
            thresh_flag = 0;
       
	/* Check array for matching src / sid */

	for (i = 0; i < thresh_count_by_dst; i++ ) {
		if (!strcmp( threshbydst[i].ipdst, ip_dst ) && !strcmp(threshbydst[i].sid, rulestruct[b].s_sid )) {

                   thresh_flag=1;

		   pthread_mutex_lock(&ThreshMutexDst);

                   threshbydst[i].count++;
                   thresh_oldtime_src = atol(timet) - threshbydst[i].utime;
                   threshbydst[i].utime = atol(timet);
                      if ( thresh_oldtime_src > rulestruct[b].threshold_seconds ) {
                         threshbydst[i].count=1;
                         threshbydst[i].utime = atol(timet);
                         thresh_log_flag=0;
                         }
		   
		   pthread_mutex_unlock(&ThreshMutexDst);

	if ( rulestruct[b].threshold_count < threshbydst[i].count ) {
	   thresh_log_flag = 1;
	   Sagan_Log(0, "Threshold SID %s by destination IP address. [%s]", threshbysrc[i].sid, ip_dst);

	   pthread_mutex_lock(&CounterMutex);
	   counters->threshold_total++;
	   pthread_mutex_unlock(&CounterMutex);
	   }
         }
       }

	/* If not found,  add it to the array */

	if ( thresh_flag == 0 ) {

	   pthread_mutex_lock(&ThreshMutexDst);

           threshbydst = (thresh_by_dst *) realloc(threshbydst, (thresh_count_by_dst+1) * sizeof(thresh_by_dst));
           snprintf(threshbydst[thresh_count_by_dst].ipdst, sizeof(threshbydst[thresh_count_by_dst].ipdst), "%s", ip_dst);
           snprintf(threshbydst[thresh_count_by_dst].sid, sizeof(threshbydst[thresh_count_by_dst].sid), "%s", rulestruct[b].s_sid );
           threshbydst[thresh_count_by_dst].count = 1;
           threshbydst[thresh_count_by_dst].utime = atol(timet);
           thresh_count_by_dst++;
  	   
	   pthread_mutex_unlock(&ThreshMutexDst);
           }
        }
}  /* End of thresholding */


/****************************************************************************/
/* Populate the SaganEvent array with the information needed.  This info    */
/* will be passed to the threads.  No need to populate it _if_ we're in a   */
/* threshold state.                                                         */
/****************************************************************************/

/* Check for thesholding & "after" */

if ( thresh_log_flag == 0 && after_log_flag == 0 ) { 

threadid++;
if ( threadid >= MAX_THREADS ) threadid=0;

//msgslot++;
//if ( msgslot >= MAX_MSGSLOT ) msgslot=0;

/* We can't use the pointers from our syslog data.  If two (or more) event's
 * fire at the same time,  the two alerts will have corrupted information 
 * (due to threading).   So we populate the SaganEvent[threadid] with the
 * var[msgslot] information. - Champ Clark 02/02/2011
 */

snprintf(ip_srctmp, sizeof(ip_srctmp), "%s", ip_src);
snprintf(ip_dsttmp, sizeof(ip_dsttmp), "%s", ip_dst);

SaganEvent = malloc(sizeof(struct _Sagan_Event));
memset(SaganEvent, 0, sizeof(_SaganEvent));


SaganEvent->ip_src    =       ip_src;
SaganEvent->ip_dst    =       ip_dst;
SaganEvent->dst_port  =       dst_port;
SaganEvent->src_port  =       src_port;
SaganEvent->found     =       b;

SaganEvent->sid       =       rulestruct[b].s_sid;
SaganEvent->rev       =       rulestruct[b].s_rev;
SaganEvent->class     =       rulestruct[b].s_classtype;
SaganEvent->pri       =       rulestruct[b].s_pri;
SaganEvent->ip_proto  =       proto;


SaganEvent->program   =       SaganProcSyslog_LOCAL->syslog_program;
SaganEvent->message   =       SaganProcSyslog_LOCAL->syslog_message;
SaganEvent->time      =       SaganProcSyslog_LOCAL->syslog_time;
SaganEvent->date      =       SaganProcSyslog_LOCAL->syslog_date;
SaganEvent->f_msg     =       s_msg;
SaganEvent->facility  =       SaganProcSyslog_LOCAL->syslog_facility;
SaganEvent->priority  =       SaganProcSyslog_LOCAL->syslog_level;
SaganEvent->tag       =       SaganProcSyslog_LOCAL->syslog_tag;
SaganEvent->host      =       SaganProcSyslog_LOCAL->syslog_host;
SaganEvent->event_time_sec =   time(NULL);

SaganEvent->generatorid =       1;              /* Rule based alerts are always 1 */


}

/***************************************************************************/
/* Output plugins that cannot be threaded and require little I/O (almost   */
/* no I/O blocking) - IE - unified2/ASCII alerts                           */
/***************************************************************************/

/* If thresholding isn't happening,  send to output plugins */

if ( thresh_log_flag == 0 && after_log_flag == 0 ) { 

Sagan_Output( SaganEvent );
free(SaganEvent);

  } /* End of threshold */
 } /* End of match */
} /* End of pcre match */

match=0;  /* Reset match! */
pcrematch=0;
rc=0;
} /* End for for loop */


return(0);
} 

