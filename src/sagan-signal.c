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
#include <stdint.h>

#include "version.h"
#include "sagan.h"

#ifdef HAVE_LIBLOGNORM
#include <liblognorm.h>
#include <ptree.h>
#include <lognorm.h>
static ln_ctx ctx;
int liblognorm_count;
#endif

#ifdef HAVE_LIBPRELUDE
#include <libprelude/prelude.h>
char sagan_prelude_profile[255];
sbool sagan_prelude_flag;
prelude_client_t *preludeclient;
#endif

FILE *alertfp;

int classcount;
int refcount;
int rulecount;
int ruletotal;
uint64_t threadmaxemailc;
int dbtype;
int sensor_id;

struct rule_struct *rulestruct;
struct class_struct *classstruct;
struct ref_struct *refstruct;

char sagan_extern[255];
char sagan_esmtp_server[255];
int logzilla_log;

uint64_t sigcid;		/* For CID on recv. of signal */

int daemonize;

uint64_t sagantotal;
uint64_t saganfound;
uint64_t sagandrop;
uint64_t threshold_total;

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

#ifdef HAVE_LIBPRELUDE

/* This comment is from the Snort source code. "Sensor reporting to Prelude
   shall never go offline,  which is why we use the 
   PRELUDE_CLIENT_EXIT_STATUS_FAILURE.  */

if ( sagan_prelude_flag != 0 ) { 
prelude_client_destroy(preludeclient, PRELUDE_CLIENT_EXIT_STATUS_FAILURE);
prelude_deinit();
}

#endif

                  removelockfile();
                  exit(0);
                  break;



                 case SIGHUP:
                   pthread_mutex_lock(&sig_mutex);
   		   sagan_log(0, "[Reloading Sagan version %s.]-------", VERSION);

		      /* Reset counters */
		   refcount=0; classcount=0; rulecount=0; ruletotal=0;

#ifdef HAVE_LIBLOGNORM
liblognorm_count=0;
#endif
		   
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

#ifdef HAVE_LIBLOGNORM
	ln_exitCtx(ctx);
#endif

	fflush(alertfp); 
	fclose(alertfp);		/* Close Sagan alert file */

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
