/*
** Copyright (C) 2009-2011 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2011 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-external.c 
 *
 * Threaded function for user defined external system (execl) calls.  This
 * allows sagan to pass information to a external program. 
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "sagan.h"
#include "version.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct rule_struct *rulestruct;

void sagan_ext_thread ( SaganEvent *Event ) {

pthread_mutex_t ext_mutex = PTHREAD_MUTEX_INITIALIZER;

int in[2];
int out[2];
int n, pid;
char buf[MAX_SYSLOGMSG];
char data[MAX_SYSLOGMSG];
char tmpref[2048];
int ret;
char tmp[6];

if ( config->sagan_exttype == 1 ) { 
   
   /* Parsable */

  snprintf(tmpref, sizeof(tmpref), "%s", reflookup( Event->found, 1 ));

if ( Event->drop == 1 ) { 
   snprintf(tmp, sizeof(tmp), "True");
   } else { 
   snprintf(tmp, sizeof(tmp), "False");
   }

   snprintf(data, sizeof(data), "\nID:%s\nMessage:%s\nClassification:%s\nDrop:%s\nPriority:%d\nDate:%s\nTime:%s\nSource:%s\nSource Port:%d\nDestination:%s\nDestination Port:%d\nFacility:%s\nSyslog Priority:%s\n%sSyslog message:%s\n", rulestruct[Event->found].s_sid, Event->f_msg, rulestruct[Event->found].s_classtype, tmp, rulestruct[Event->found].s_pri,  Event->date, Event->time, Event->ip_src, Event->src_port,  Event->ip_dst, Event->dst_port, Event->facility, Event->priority, tmpref, Event->message);
   
  } else { 

  /* Alert like */

  snprintf(tmpref, sizeof(tmpref), "%s", reflookup( Event->found, 0 ));

  snprintf(data, sizeof(data), "[**] [%s] %s [**]\n[Classification: %s] [Priority: %d]\n%s %s %s:%d -> %s:%d %s %s\nSyslog message: %s%s\n\n", rulestruct[Event->found].s_sid, Event->f_msg, rulestruct[Event->found].s_classtype, rulestruct[Event->found].s_pri, Event->date, Event->time, Event->ip_src, Event->src_port, Event->ip_dst, Event->dst_port, Event->facility, Event->priority, Event->message, tmpref);
  }


if ( pipe(in) < 0 ) {
   removelockfile();
   sagan_log(1, "[%s, line %d] Cannot create input pipe!", __FILE__, __LINE__);
   }


if ( pipe(out) < 0 ) {
   removelockfile();
   sagan_log(1, "[%s, line %d] Cannot create output pipe!", __FILE__, __LINE__);
   }


if (( pid = fork()) == 0 ) { 

   /* Causes problems wiht alert.log */
   pthread_mutex_lock( &ext_mutex );
   close(0);
   close(1);
   close(2);

   dup2(in[0],0);		// Stdin..
   dup2(out[1],1);
   dup2(out[1],2);

   close(in[1]);
   close(out[0]);
   pthread_mutex_unlock( &ext_mutex );

   ret=execl(config->sagan_extern, config->sagan_extern, NULL, (char *)NULL);
   removelockfile();
   sagan_log(1, "[%s, line %d] Cannot execute %s", __FILE__, __LINE__, config->sagan_extern);
   } 

   pthread_mutex_lock( &ext_mutex );
   close(in[0]);
   close(out[1]);
   pthread_mutex_unlock( &ext_mutex );

   /* Write to child input */


   n = write(in[1], data, strlen(data));
   pthread_mutex_lock( &ext_mutex );
   close(in[1]);
   pthread_mutex_unlock( &ext_mutex );

   n = read(out[0], buf, sizeof(buf));
   buf[n] = 0;

   waitpid(pid, NULL, 0);

pthread_mutex_lock( &ext_mutex );
counters->threadextc--;
pthread_mutex_unlock( &ext_mutex );

pthread_exit(NULL);
}

