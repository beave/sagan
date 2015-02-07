/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
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
#include "sagan-defs.h"
#include "sagan-flowbit.h"
#include "sagan-config.h"
#include "sagan-lockfile.h"
#include "sagan-signal.h"
#include "sagan-stats.h"
#include "sagan-gen-msg.h"
#include "sagan-classifications.h"
#include "processors/sagan-perfmon.h"
#include "sagan-rules.h"

#include "processors/sagan-blacklist.h"
#include "processors/sagan-search.h"
#include "processors/sagan-track-clients.h"
#include "processors/sagan-criticalstack.h"

#ifdef WITH_WEBSENSE
#include "processors/sagan-websense.h"
#endif

#ifdef HAVE_LIBLOGNORM
#include <liblognorm.h>
#include <ptree.h>
#include <lognorm.h>
int liblognorm_count;
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/sagan-unified2.h"
sbool sagan_unified2_flag;
#endif

#ifdef HAVE_LIBGEOIP
#include <GeoIP.h>
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
struct _Sagan_Flowbit *flowbit;

sbool sagan_reload; 	/* Used to indicate Sagan is in reload.  This keeps Sagan
			   pulling rules, etc. from memory in the middle of a
			   reload */

struct _Sagan_CriticalStack_Intel_Addr *Sagan_CriticalStack_Intel_Addr;
struct _Sagan_CriticalStack_Intel_Domain *Sagan_CriticalStack_Intel_Domain;
struct _Sagan_CriticalStack_Intel_File_Hash *Sagan_CriticalStack_Intel_File_Hash;
struct _Sagan_CriticalStack_Intel_URL *Sagan_CriticalStack_Intel_URL;
struct _Sagan_CriticalStack_Intel_Software *Sagan_CriticalStack_Intel_Software;
struct _Sagan_CriticalStack_Intel_Email *Sagan_CriticalStack_Intel_Email;
struct _Sagan_CriticalStack_Intel_User_Name *Sagan_CriticalStack_Intel_User_Name;
struct _Sagan_CriticalStack_Intel_File_Name *Sagan_CriticalStack_Intel_File_Name;
struct _Sagan_CriticalStack_Intel_Cert_Hash *Sagan_CriticalStack_Intel_Cert_Hash;

#ifdef WITH_WEBSENSE
struct _Sagan_Websense_Ignore_List *SaganWebsenseIgnoreList;
struct _Sagan_Websense_Queue *SaganWebsenseQueue;
struct _Sagan_Websense_Cache *SaganWebsenseCache;
#endif

pthread_mutex_t sig_mutex = PTHREAD_MUTEX_INITIALIZER;

void Sig_Handler( _SaganSigArgs *args )
{

    sigset_t signal_set;
    int sig;

    for(;;)
        {
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

                    Sagan_Log(S_NORMAL, "\n\n[Received signal %d. Sagan version %s shutting down]-------\n", sig, VERSION);
                    sagan_statistics();

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
                    if ( sagan_unified2_flag ) Unified2CleanExit();
#endif

                    fflush(config->sagan_alert_stream);
                    fclose(config->sagan_alert_stream);             /* Close Sagan alert file */

                    fflush(config->sagan_log_stream);               /* Close the sagan.log */
                    fclose(config->sagan_log_stream);

                    if ( config->perfmonitor_flag )
                        Sagan_Perfmonitor_Exit();

                    Remove_Lock_File();
                    exit(0);
                    break;

                case SIGHUP:
                    pthread_mutex_lock(&sig_mutex);

                    sagan_reload = 1; 			/* So we don't wipe memory while in the middle of analysis */

                    Sagan_Log(S_NORMAL, "[Reloading Sagan version %s.]-------", VERSION);

                    /* Reset counters */
                    counters->refcount=0;
                    counters->classcount=0;
                    counters->rulecount=0;
                    counters->ruletotal=0;
                    counters->genmapcount=0;
                    counters->flowbit_track_count=0;

                    memset(rulestruct, 0, sizeof(_Rule_Struct));
                    memset(classstruct, 0, sizeof(_Class_Struct));
                    memset(generator, 0, sizeof(_Sagan_Processor_Generator));
                    memset(flowbit, 0, sizeof(_Sagan_Flowbit));


                    /* Re-load primary configuration (rules/classifictions/etc) */

                    Load_Config();

                    if (config->blacklist_flag)
                        {
                            counters->blacklist_count=0;
                            memset(SaganBlacklist, 0, sizeof(_Sagan_Blacklist));
                            Sagan_Blacklist_Load();
                            Sagan_Log(S_NORMAL, "Reloaded Blacklist. [File: %s | Count: %d | Parse Depth: %d]", config->blacklist_file, counters->blacklist_count, config->blacklist_parse_depth);
                        }

                    if (config->search_nocase_flag)
                        {
                            counters->search_nocase_count=0;
                            memset(SaganNocaseSearchlist, 0, sizeof(_Sagan_Nocase_Searchlist));
                            Sagan_Search_Load(1);
                            Sagan_Log(S_NORMAL, "Reloaded Search [nocase]. [File: %s | Count: %d]", config->search_nocase_file, counters->search_nocase_count);
                        }

                    if (config->search_case_flag)
                        {
                            counters->search_case_count=0;
                            memset(SaganCaseSearchlist, 0, sizeof(_Sagan_Case_Searchlist));
                            Sagan_Search_Load(2);
                            Sagan_Log(S_NORMAL, "Reloaded Search. [File: %s | Count: %d]", config->search_nocase_file, counters->search_nocase_count);
                        }


                    if (config->criticalstack_flag)
                        {

                            Sagan_CriticalStack_Intel_Addr = (_Sagan_CriticalStack_Intel_Addr *) realloc(Sagan_CriticalStack_Intel_Addr, 1 * sizeof(_Sagan_CriticalStack_Intel_Addr));
                            counters->criticalstack_addr_count = 0;

                            Sagan_CriticalStack_Intel_Domain = (_Sagan_CriticalStack_Intel_Domain *) realloc(Sagan_CriticalStack_Intel_Domain, 1 * sizeof(_Sagan_CriticalStack_Intel_Domain));
                            counters->criticalstack_domain_count=0;

                            Sagan_CriticalStack_Intel_File_Hash = (_Sagan_CriticalStack_Intel_File_Hash *) realloc(Sagan_CriticalStack_Intel_File_Hash, 1 * sizeof(_Sagan_CriticalStack_Intel_File_Hash));
                            counters->criticalstack_file_hash_count=0;

                            Sagan_CriticalStack_Intel_URL = (_Sagan_CriticalStack_Intel_URL *) realloc(Sagan_CriticalStack_Intel_URL, 1 * sizeof(_Sagan_CriticalStack_Intel_URL));
                            counters->criticalstack_url_count=0;

                            Sagan_CriticalStack_Intel_Software = (_Sagan_CriticalStack_Intel_Software *) realloc(Sagan_CriticalStack_Intel_Software, 1 * sizeof(_Sagan_CriticalStack_Intel_Software));
                            counters->criticalstack_software_count=0;

                            Sagan_CriticalStack_Intel_Email = (_Sagan_CriticalStack_Intel_Email *) realloc(Sagan_CriticalStack_Intel_Email, 1 * sizeof(_Sagan_CriticalStack_Intel_Email));
                            counters->criticalstack_email_count=0;

                            Sagan_CriticalStack_Intel_User_Name = (_Sagan_CriticalStack_Intel_User_Name *) realloc(Sagan_CriticalStack_Intel_User_Name, 1 * sizeof(_Sagan_CriticalStack_Intel_User_Name));
                            counters->criticalstack_user_name_count=0;

                            Sagan_CriticalStack_Intel_File_Name = (_Sagan_CriticalStack_Intel_File_Name *) realloc(Sagan_CriticalStack_Intel_File_Name, 1 * sizeof(_Sagan_CriticalStack_Intel_File_Name));
                            counters->criticalstack_file_name_count=0;

                            Sagan_CriticalStack_Intel_Cert_Hash = (_Sagan_CriticalStack_Intel_Cert_Hash *) realloc(Sagan_CriticalStack_Intel_Cert_Hash, 1 * sizeof(_Sagan_CriticalStack_Intel_Cert_Hash));
                            counters->criticalstack_cert_hash_count=0;

                            Sagan_CriticalStack_Load_File();
                            Sagan_Log(S_NORMAL, "Reloaded CriticalStack data.");

                        }



                    if (config->sagan_track_clients_flag)
                        {
                            counters->track_clients_client_count = 0;
                            counters->track_clients_down = 0;
                            memset(SaganTrackClients, 0, sizeof(_Sagan_Track_Clients));
                            fclose(config->sagan_track_client_file);
                            Sagan_Load_Tracking_Cache();
                            Sagan_Log(S_NORMAL, "Reset Sagan Track Client.");
                        }


                    /*		  DNS Cache *not currently global* DEBUG
                    		  if (config->syslog_src_lookup) {
                    		     counters->dns_cache_count=0;
                    		     counters->dns_miss_count=0;
                    		     }
                    */

#ifdef WITH_WEBSENSE
                    if ( config->websense_flag )
                        {
                            counters->websense_cache_count=0;
                            counters->websense_cache_hit=0;
                            counters->websense_ignore_hit=0;
                            counters->websense_postive_hit=0;
                            memset(SaganWebsenseIgnoreList, 0, sizeof(_Sagan_Websense_Ignore_List));
                            memset(SaganWebsenseQueue, 0, sizeof(_Sagan_Websense_Queue));
                            memset(SaganWebsenseCache, 0, sizeof(_Sagan_Websense_Cache));

                            config->websense_last_time = atol(config->sagan_startutime);
                            Sagan_Websense_Ignore_List();
                            Sagan_Log(S_NORMAL, "Reset Websense Processor.");
                        }
#endif

#ifdef HAVE_LIBGEOIP
                    Sagan_Log(S_NORMAL, "Reloading GeoIP data.");
                    config->geoip = GeoIP_open(config->geoip_country_file, GEOIP_MEMORY_CACHE);
#endif

                    sagan_reload = 0;
                    pthread_mutex_unlock(&sig_mutex);

                    Sagan_Log(S_NORMAL, "Configuration reloaded.");
                    break;

                    /* Signals to ignore */
                case 17:		/* Child process has exited. */
                case 28:		/* Terminal 'resize'/alarm. */
                    break;

                case SIGUSR1:
                    sagan_statistics();
                    break;

                default:
                    Sagan_Log(S_NORMAL, "[Received signal %d. Sagan doesn't know how to deal with]", sig);
                }
        }
}

