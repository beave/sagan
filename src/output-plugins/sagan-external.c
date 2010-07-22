/*
** Copyright (C) 2009-2010 Softwink, Inc. 
** Copyright (C) 2009-2010 Champ Clark III <champ@softwink.com>
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

char sagan_extern[MAXPATH];
int  sagan_exttype;
int  threadextc;

void *sagan_ext_thread( void *ethreadargs ) {

pthread_mutex_t ext_mutex = PTHREAD_MUTEX_INITIALIZER;
struct ext_thread_args * eargs = (struct ext_thread_args *) ethreadargs;

int in[2];
int out[2];
int n, pid;
char buf[MAX_SYSLOGMSG];
char data[MAX_SYSLOGMSG];
int ret;

if ( sagan_exttype == 1 ) { 
   
   /* Parsable */

  snprintf(data, sizeof(data), "\nID:%s\nMessage:%s\nClassification:%s\nPriority:%d\nDate:%s\nTime:%s\nSource:%s\nSource Port:%d\nDestination:%s\nDestination Port:%d\nFacility:%s\nSyslog Priority:%s\nSyslog message: %s\n", eargs->sid, eargs->msg, eargs->classtype, eargs->pri,  eargs->date, eargs->time, eargs->ip_src, eargs->src_port,  eargs->ip_dst, eargs->dst_port, eargs->facility, eargs->fpri, eargs->sysmsg);
   
  } else { 

  /* Alert like */

   snprintf(data, sizeof(data), "\n[**] [%s] %s [**]\n[Classification: %s] [Priority: %d]\n%s %s %s:%d -> %s:%d %s %s\n\nSyslog message: %s", eargs->sid, eargs->msg, eargs->classtype, eargs->pri, eargs->date, eargs->time, eargs->ip_src, eargs->src_port, eargs->ip_dst, eargs->dst_port, eargs->facility, eargs->fpri, eargs->sysmsg);
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

   ret=execl(sagan_extern, sagan_extern, NULL, (char *)NULL);
   removelockfile();
   sagan_log(1, "[%s, line %d] Cannot execute %s", __FILE__, __LINE__, sagan_extern);
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
threadextc--;
pthread_mutex_unlock( &ext_mutex );

pthread_exit(NULL);
}

