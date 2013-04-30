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
#include <string.h>

#include "version.h"

#include "sagan.h"
#include "processors/sagan-blacklist.h"
#include "processors/sagan-search.h"
#include "processors/sagan-track-clients.h"

#ifdef WITH_WEBSENSE
#include "processors/sagan-websense.h"
#endif

#ifdef HAVE_LIBLOGNORM
#include <liblognorm.h>
#include <ptree.h>
#include <lognorm.h>
//static ln_ctx ctx;
int liblognorm_count;
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/sagan-unified2.h"
sbool sagan_unified2_flag;
#endif

struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _Class_Struct *classstruct;
struct _Sagan_Processor_Generator *generator;
struct _Sagan_Blacklist *SaganBlacklist;
struct _Sagan_Nocase_Searchlist *SaganNocaseSearchlist;
struct _Sagan_Case_Searchlist *SaganCaseSearchlist;
struct _Sagan_Track_Clients *SaganTrackClients;

#ifdef WITH_WEBSENSE
struct _Sagan_Websense_Ignore_List *SaganWebsenseIgnoreList;
struct _Sagan_Websense_Queue *SaganWebsenseQueue;
struct _Sagan_Websense_Cache *SaganWebsenseCache;
#endif 

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
		   counters->refcount=0; 
		   counters->classcount=0;
		   counters->rulecount=0; 
		   counters->ruletotal=0;
		   counters->genmapcount=0;

		   memset(rulestruct, 0, sizeof(_Rule_Struct));
		   memset(classstruct, 0, sizeof(_Class_Struct));
		   memset(generator, 0, sizeof(_Sagan_Processor_Generator)); 

		   /* Re-load primary configuration (rules/classifictions/etc) */

		  Load_Config();

		  if (config->blacklist_flag) {
		     counters->blacklist_count=0;
		     memset(SaganBlacklist, 0, sizeof(_Sagan_Blacklist));
		     Sagan_Blacklist_Load();
		     Sagan_Log(0, "Reloaded Blacklist. [File: %s | Count: %d | Parse Depth: %d]", config->blacklist_file, counters->blacklist_count, config->blacklist_parse_depth);
		     }

		  if (config->search_nocase_flag) {
                     counters->search_nocase_count=0;
		     memset(SaganNocaseSearchlist, 0, sizeof(_Sagan_Nocase_Searchlist));
		     Sagan_Search_Load(1);
		     Sagan_Log(0, "Reloaded Search [nocase]. [File: %s | Count: %d]", config->search_nocase_file, counters->search_nocase_count); 
		     }

		  if (config->search_case_flag) {
		     counters->search_case_count=0;
		     memset(SaganCaseSearchlist, 0, sizeof(_Sagan_Case_Searchlist));
		     Sagan_Search_Load(2);
		     Sagan_Log(0, "Reloaded Search. [File: %s | Count: %d]", config->search_nocase_file, counters->search_nocase_count);
		     }


		  if (config->sagan_track_clients_flag) { 
		     counters->track_clients_client_count = 0;
		     counters->track_clients_down = 0; 
		     memset(SaganTrackClients, 0, sizeof(_Sagan_Track_Clients));
		     Sagan_Log(0, "Reset Sagan Track Client.");
		     }

/*		  DNS Cache *not currently global* DEBUG 
		  if (config->syslog_src_lookup) { 
		     counters->dns_cache_count=0;
		     counters->dns_miss_count=0;
		     }
*/

#ifdef WITH_WEBSENSE
		  if ( config->websense_flag ) {
		     counters->websense_cache_count=0;
		     counters->websense_cache_hit=0;
		     counters->websense_ignore_hit=0;
		     counters->websense_postive_hit=0;
		     memset(SaganWebsenseIgnoreList, 0, sizeof(_Sagan_Websense_Ignore_List));
		     memset(SaganWebsenseQueue, 0, sizeof(_Sagan_Websense_Queue));

		     SaganWebsenseCache = malloc(config->websense_max_cache * sizeof(struct _Sagan_Websense_Cache));
		     memset(SaganWebsenseCache, 0, sizeof(_Sagan_Websense_Cache));

		     config->websense_last_time = atol(config->sagan_startutime);
 		     Sagan_Websense_Ignore_List();
		     Sagan_Log(0, "Reset Websense Processor.");
		     }
#endif

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

