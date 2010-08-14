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

/* sagan-signal.c
 *
 * This runs as a thread for signal processing.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

#include "version.h"
#include "sagan.h"


int classcount;
int refcount;
int rulecount;
int ruletotal;
int threadmaxdbc;
int threadmaxextc;
int threadmaxemailc;
int threadmaxlogzillac;
int dbtype;
int sensor_id;

struct rule_struct *rulestruct;
struct class_struct *classstruct;
struct ref_struct *refstruct;

char sagan_extern[255];
char sagan_esmtp_server[255];
int logzilla_log;

unsigned long long sigcid;		/* For CID on recv. of signal */

int daemonize;

unsigned long long int sagantotal;
unsigned long long int saganfound;
unsigned long long int sagandrop;
unsigned long long threshold_total;

FILE *alertfp;

pthread_mutex_t sig_mutex = PTHREAD_MUTEX_INITIALIZER;

void sig_handler(int sigargs ) {

        sigset_t signal_set;
        int sig;

        for(;;) {
                /* wait for any and all signals */
                sigfillset( &signal_set );
                sigwait( &signal_set, &sig );


                switch( sig )
                {
		  /* exit */
		  case SIGQUIT:
		  case SIGINT:
		  case SIGTERM:
		  case SIGSEGV:
		  case SIGABRT:

                  sagan_log(0, "\n\n[Received signal %d. Sagan version %s shutting down]-------\n", sig, VERSION);
		  sagan_statistics();

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
		  if ( dbtype != 0 ) record_last_cid();
#endif
                  removelockfile();
                  exit(0);
                  break;


                 case SIGHUP:
                   pthread_mutex_lock(&sig_mutex);
   		   sagan_log(0, "[Reloading Sagan version %s.]-------", VERSION);

		      /* Reset counters */
		   refcount=0; classcount=0; rulecount=0; ruletotal=0;
		   
		   /* Re-load everything */
		   load_config();

                  pthread_mutex_unlock(&sig_mutex);
		  
		  sagan_log(0, "Configuration reloaded.");
                  break;

		/* Signals to ignore */
	        case 17:		/* Child process has exited. */	
		case 28:		/* Terminal 'resize'/alarm. */
		break;

		case SIGUSR1:
		sagan_statistics(); 
		break;

		default:
		sagan_log(0, "[Received signal %d. Sagan doesn't know how to deal with]", sig);
                }
        }
}


/****************************************************************************/
/* sig_handler_daemon,  for handling signals when the --daemon flag is used */
/* We don't spawn a sig_handler() thread in the event --daemon is used.     */
/* Signals must be handled differently.  This is really redundant code and  */
/* I don't like it,  but oh well.                                           */
/****************************************************************************/

void sig_handler_daemon( int sig ) {

switch( sig )
	{
        case SIGQUIT:
        case SIGINT:
        case SIGTERM:
        case SIGSEGV:
        case SIGABRT:

        sagan_log(0, "\n\n[Received signal %d. Sagan version %s shutting down]-------\n", sig, VERSION);
        sagan_statistics();

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
        if ( dbtype != 0 ) record_last_cid();
#endif
        removelockfile();
        exit(0);
        break;


        case SIGHUP:
	        pthread_mutex_lock(&sig_mutex);
                sagan_log(0, "[Reloading Sagan version %s.]-------", VERSION);

                /* Reset counters */
                refcount=0; classcount=0; rulecount=0; ruletotal=0;

                /* Re-load everything */
                load_config();

                pthread_mutex_unlock(&sig_mutex);

		sagan_log(0, "Configuration reloaded.");
                break;

	case 17:                /* Child process has exited. */
	case 28:                /* Terminal 'resize'/alarm. */
	break;

	case SIGUSR1:
        sagan_statistics();
        break;

        default:
        sagan_log(0, "[Received signal %d. Sagan doesn't know how to deal with]", sig);
	}

}
