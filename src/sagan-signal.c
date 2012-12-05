/*
** Copyright (C) 2009-2012 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2012 Champ Clark III <cclark@quadrantsec.com>
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

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/sagan-unified2.h"
sbool sagan_unified2_flag;
#endif

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
#include "output-plugins/sagan-snort.h"
#endif


struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct rule_struct *rulestruct;
struct class_struct *classstruct;
struct ref_struct *refstruct;


pthread_mutex_t sig_mutex = PTHREAD_MUTEX_INITIALIZER;

void Sig_Handler( _SaganSigArgs *args ) {

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

                  Sagan_Log(0, "\n\n[Received signal %d. Sagan version %s shutting down]-------\n", sig, VERSION);
		  sagan_statistics();

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

		  /* last_cid != cid (has there been any alerts? */

		  if ( config->dbtype != 0 && counters->last_cid != counters-> cid ) record_last_cid();
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
if ( sagan_unified2_flag ) Unified2CleanExit(config); 
#endif

	        fflush(config->sagan_alert_stream);
	        fclose(config->sagan_alert_stream);             /* Close Sagan alert file */

       		fflush(config->sagan_log_stream);               /* Close the sagan.log */
        	fclose(config->sagan_log_stream);

                Remove_Lock_File();
                exit(0);
                break;

                 case SIGHUP:
                   pthread_mutex_lock(&sig_mutex);
   		   Sagan_Log(0, "[Reloading Sagan version %s.]-------", VERSION);

		      /* Reset counters */
		   counters->refcount=0; counters->classcount=0; counters->rulecount=0; counters->ruletotal=0;
		   
		   /* Re-load everything */

		  Load_Config();

                  pthread_mutex_unlock(&sig_mutex);
		  
		  Sagan_Log(0, "Configuration reloaded.");
                  break;

		/* Signals to ignore */
	        case 17:		/* Child process has exited. */	
		case 28:		/* Terminal 'resize'/alarm. */
		break;

		case SIGUSR1:
		sagan_statistics(); 
		break;

		default:
		Sagan_Log(0, "[Received signal %d. Sagan doesn't know how to deal with]", sig);
                }
        }
}

