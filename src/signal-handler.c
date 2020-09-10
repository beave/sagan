/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
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

/* signal.c
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
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <errno.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "version.h"

#include "sagan.h"
#include "sagan-defs.h"
#include "flexbit-mmap.h"
#include "sagan-config.h"
#include "config-yaml.h"
#include "lockfile.h"
#include "signal-handler.h"
#include "stats.h"
#include "gen-msg.h"
#include "classifications.h"

#include "processors/perfmon.h"
#include "rules.h"
#include "ignore-list.h"
#include "flow.h"

#include "processors/blacklist.h"
#include "processors/track-clients.h"
#include "processors/zeek-intel.h"
#include "processors/client-stats.h"
#include "processors/stats-json.h"

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
#include <liblognorm.h>
int liblognorm_count;
#endif

#ifdef HAVE_LIBMAXMINDDB
#include <maxminddb.h>
#include "geoip.h"
struct _Sagan_GeoIP_Skip *GeoIP_Skip;
#endif

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
struct _Sagan_Bluedot_Skip *Bluedot_Skip;
#endif

#define MAX_DEATH_TIME 15

struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _Rules_Loaded *rules_loaded;
struct _Class_Struct *classstruct;
struct _Sagan_Processor_Generator *generator;
struct _Sagan_Blacklist *SaganBlacklist;
struct _Sagan_Track_Clients *SaganTrackClients;
struct _SaganVar *var;

struct _Sagan_Ignorelist *SaganIgnorelist;

struct _Sagan_BroIntel_Intel_Addr *Sagan_BroIntel_Intel_Addr;
struct _Sagan_BroIntel_Intel_Domain *Sagan_BroIntel_Intel_Domain;
struct _Sagan_BroIntel_Intel_File_Hash *Sagan_BroIntel_Intel_File_Hash;
struct _Sagan_BroIntel_Intel_URL *Sagan_BroIntel_Intel_URL;
struct _Sagan_BroIntel_Intel_Software *Sagan_BroIntel_Intel_Software;
struct _Sagan_BroIntel_Intel_Email *Sagan_BroIntel_Intel_Email;
struct _Sagan_BroIntel_Intel_User_Name *Sagan_BroIntel_Intel_User_Name;
struct _Sagan_BroIntel_Intel_File_Name *Sagan_BroIntel_Intel_File_Name;
struct _Sagan_BroIntel_Intel_Cert_Hash *Sagan_BroIntel_Intel_Cert_Hash;

pthread_mutex_t SaganReloadMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t SaganReloadCond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t SaganRulesLoadedMutex;

bool death;
int proc_running;

void Sig_Handler( void )
{

    (void)SetThreadName("SaganSignal");

    sigset_t signal_set;
    int sig;

    bool orig_perfmon_value = false;
    bool orig_stats_json_value = false;
    bool orig_client_stats_value = false;

    unsigned char max_death_time = 0;

#ifdef HAVE_LIBPCAP
    bool orig_plog_value = 0;
#endif

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


                    Sagan_Log(NORMAL, "\n\n[Received signal %d. Sagan version %s shutting down]-------\n", sig, VERSION);

                    /* This tells "new" threads to stop processing new data */

                    death=true;

                    /* We wait until there are no more running/processing threads
                       or until the thread space is zero.  We don't want to start
                       closing files, etc until everything has settled. */

                    while( proc_running > 0 )
                        {
                            Sagan_Log(WARN, "Waiting on %d working thread(s)....[%d/%d]", proc_running, max_death_time, MAX_DEATH_TIME);
                            sleep(1);
                            max_death_time++;

                            if ( max_death_time >= MAX_DEATH_TIME )
                                {
                                    Sagan_Log(WARN, "Hard abort! :(");
                                    break;
                                }

                        }

                    /* Sagan will wait indefinitely for a hung thread to quit.  In the
                       event it has been more that MAX_DEATH_TIME seconds,  we force
                               an abort and let the user know */

                    if ( max_death_time > MAX_DEATH_TIME )
                        {
                            Sagan_Log(WARN, "Not all threads stopped.  Forcing abort!");
                        }

                    Statistics();

#ifdef HAVE_LIBMAXMINDDB

                    MMDB_close(&config->geoip2);

#endif

                    if ( config->eve_flag == true && config->eve_stream_status == true )
                        {

                            fflush(config->eve_stream);
                            fclose(config->eve_stream);

                        }

                    if ( config->alert_flag == true && config->sagan_alert_stream_status == true )
                        {

                            fflush(config->sagan_alert_stream);
                            fclose(config->sagan_alert_stream);             /* Close Sagan alert file */

                        }

                    if ( config->fast_flag == true && config->sagan_fast_stream_status == true )
                        {

                            fflush(config->sagan_fast_stream);
                            fclose(config->sagan_fast_stream);

                        }

                    if ( config->sagan_log_stream_status == true )
                        {
                            fflush(config->sagan_log_stream);               /* Close the sagan.log */
                            fclose(config->sagan_log_stream);
                        }

                    /* IPC Shared Memory */

                    if ( config->shm_counters_status == true )
                        {

                            File_Unlock(config->shm_counters);

                            if ( close(config->shm_counters) != 0 )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Cannot close IPC counters! [%s]", __FILE__, __LINE__, strerror(errno));
                                }
                        }

                    if ( config->shm_flexbit_status == true )
                        {
                            File_Unlock(config->shm_flexbit);

                            if ( close(config->shm_flexbit) != 0 )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Cannot close IPC flexbit! [%s]", __FILE__, __LINE__, strerror(errno));
                                }
                        }

                    if ( config->shm_thresh2_status == true )
                        {
                            File_Unlock(config->shm_thresh2);

                            if ( close(config->shm_thresh2) != 0 )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Cannot close IPC _Threshold2_IPC! [%s]", __FILE__, __LINE__, strerror(errno));
                                }
                        }

                    if ( config->shm_after2_status == true )
                        {
                            File_Unlock(config->shm_after2);

                            if ( close(config->shm_after2) != 0 )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Cannot close IPC _After2_IPC! [%s]", __FILE__, __LINE__, strerror(errno));
                                }
                        }

                    if ( config->sagan_track_clients_flag == true && config->shm_track_clients == true )
                        {

                            File_Unlock(config->shm_track_clients);

                            if ( close(config->shm_track_clients) != 0 )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Cannot close IPC _Sagan_Track_Clients! [%s]", __FILE__, __LINE__, strerror(errno));
                                }

                        }


                    if ( config->perfmonitor_flag == true && config->perfmonitor_file_stream_status == true )
                        {
                            Sagan_Perfmonitor_Close();
                        }

                    if ( config->stats_json_flag == true && config->stats_json_file_stream_status == true )
                        {
                            Stats_JSON_Close();
                        }

                    if ( config->client_stats_flag == true && config->client_stats_file_stream_status == true )
                        {
                            Client_Stats_Close();
                        }

                    Remove_Lock_File();
                    exit(0);
                    break;

                case SIGHUP:

                    config->sagan_reload = 1;				/* Only this thread can alter this */

                    pthread_mutex_lock(&SaganReloadMutex);

                    Sagan_Log(NORMAL, "[Reloading Sagan version %s.]-------", VERSION);

                    /*
                    * Close and re-open log files.  This is for logrotate and such
                    * 04/14/2015 - Champ Clark III (cclark@quadrantsec.com)
                    */

                    Open_Log_File(REOPEN, ALL_LOGS);

                    /******************/
                    /* Reset counters */
                    /******************/

                    __atomic_store_n (&counters->refcount, 0, __ATOMIC_SEQ_CST);
                    __atomic_store_n (&counters->classcount, 0, __ATOMIC_SEQ_CST);
                    __atomic_store_n (&counters->rulecount, 0, __ATOMIC_SEQ_CST);
                    __atomic_store_n (&counters->ruletotal, 0, __ATOMIC_SEQ_CST);
                    __atomic_store_n (&counters->genmapcount, 0, __ATOMIC_SEQ_CST);
                    __atomic_store_n (&counters->rules_loaded_count, 0, __ATOMIC_SEQ_CST);
                    __atomic_store_n (&counters->var_count, 0, __ATOMIC_SEQ_CST);


                    memset(rules_loaded, 0, sizeof(_Rules_Loaded));
                    memset(rulestruct, 0, sizeof(_Rule_Struct));
                    memset(classstruct, 0, sizeof(_Class_Struct));
                    memset(generator, 0, sizeof(_Sagan_Processor_Generator));
                    memset(var, 0, sizeof(_SaganVar));

                    /**********************************/
                    /* Disabled and reset processors. */
                    /**********************************/

                    /* Note: Processors that run as there own thread (perfmon, plog) cannot be
                     * loaded via SIGHUP.  They must be loaded at run time.  Once they are loaded,
                     * they cannot be disabled/re-enabled. */

                    /* Single Threaded processors */


                    /* Perfmon */

                    if ( config->perfmonitor_flag == true && orig_perfmon_value == false )
                        {
                            Sagan_Perfmonitor_Close();
                            orig_perfmon_value = true;
                        }

                    config->perfmonitor_flag = false;

                    /* Stats JSON */

                    if ( config->stats_json_flag == true && orig_perfmon_value == false )
                        {
                            Stats_JSON_Close();
                            orig_stats_json_value = true;
                        }

                    config->stats_json_flag = false;

                    /* Client stats */

                    if ( config->client_stats_flag == true && orig_client_stats_value == false )
                        {
                            Client_Stats_Close();
                            orig_client_stats_value = true;
                        }

                    config->client_stats_flag = false;



#ifdef HAVE_LIBPCAP

                    if ( config->plog_flag )
                        {
                            orig_plog_value = 1;
                        }

                    config->plog_flag = 0;
#endif

                    /* Multi Threaded processors */

                    config->blacklist_flag = 0;

                    if ( config->blacklist_flag )
                        {
                            free(SaganBlacklist);
                        }

                    config->blacklist_flag = 0;

                    if ( config->brointel_flag )
                        {
                            free(Sagan_BroIntel_Intel_Addr);
                            free(Sagan_BroIntel_Intel_Domain);
                            free(Sagan_BroIntel_Intel_File_Hash);
                            free(Sagan_BroIntel_Intel_URL);
                            free(Sagan_BroIntel_Intel_Software);
                            free(Sagan_BroIntel_Intel_Email);
                            free(Sagan_BroIntel_Intel_User_Name);
                            free(Sagan_BroIntel_Intel_File_Name);
                            free(Sagan_BroIntel_Intel_Cert_Hash);

                            __atomic_store_n (&counters->brointel_addr_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_domain_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_file_hash_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_url_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_software_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_email_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_user_name_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_file_name_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_cert_hash_count, 0, __ATOMIC_SEQ_CST);
                            __atomic_store_n (&counters->brointel_dups, 0, __ATOMIC_SEQ_CST);


                        }

                    config->brointel_flag = 0;

                    if ( config->sagan_track_clients_flag )
                        {

                            free(SaganTrackClients);

                        }

                    /* Output formats */

#ifdef WITH_SYSLOG
                    config->sagan_syslog_flag = 0;
#endif


#ifdef HAVE_LIBESMTP
                    config->sagan_esmtp_flag = 0;
#endif

#ifdef HAVE_LIBMAXMINDDB

                    /* GeoIP skip */
                    __atomic_store_n (&counters->geoip_skip_count, 0, __ATOMIC_SEQ_CST);
                    memset(GeoIP_Skip, 0, sizeof(_Sagan_GeoIP_Skip));
#endif


#ifdef WITH_BLUEDOT
                    __atomic_store_n (&counters->bluedot_skip_count, 0, __ATOMIC_SEQ_CST);
                    memset(Bluedot_Skip, 0, sizeof(_Sagan_Bluedot_Skip));
#endif

                    /* Non-output / Processors */

                    if ( config->sagan_droplist_flag )
                        {
                            config->sagan_droplist_flag = 0;
                            free(SaganIgnorelist);
                        }

                    /************************************************************/
                    /* Re-load primary configuration (rules/classifictions/etc) */
                    /************************************************************/

                    pthread_mutex_lock(&SaganRulesLoadedMutex);
                    Load_YAML_Config(config->sagan_config);	/* <- RELOAD */
                    pthread_mutex_unlock(&SaganRulesLoadedMutex);

                    /************************************************************/
                    /* Re-load primary configuration (rules/classifictions/etc) */
                    /************************************************************/

                    /* Perfmon */

                    if ( config->perfmonitor_flag == true )
                        {
                            if ( orig_perfmon_value == true )
                                {
                                    Sagan_Perfmonitor_Open();
                                }
                            else
                                {
                                    Sagan_Log(WARN, "** 'perfmonitor' must be loaded at runtime! NOT loading 'perfmonitor'!");
                                    config->perfmonitor_flag = false;
                                }
                        }

                    /* JSON Stats */

                    if ( config->stats_json_flag == true )
                        {
                            if ( orig_stats_json_value == true )
                                {
                                    Stats_JSON_Init();
                                }
                            else
                                {
                                    Sagan_Log(WARN, "** 'stats-json' must be loaded at runtime! NOT loading 'stats-json'!");
                                    config->stats_json_flag = false;
                                }
                        }

                    /* Client Stats */

                    if ( config->client_stats_flag == true )
                        {
                            if ( orig_client_stats_value == true )
                                {
                                    Client_Stats_Init();
                                }
                            else
                                {
                                    Sagan_Log(WARN, "** 'client-stats' must be loaded at runtime! NOT loading 'client-stats'!");
                                    config->client_stats_flag = false;
                                }
                        }


#ifdef HAVE_LIBPCAP

                    if ( config->plog_flag == 1 )
                        {
                            if ( orig_plog_value == 1 )
                                {
                                    config->plog_flag = 1;
                                }
                            else
                                {
                                    Sagan_Log(WARN, "** 'plog' must be loaded at runtime! NOT loading 'plog'!");
                                    config->plog_flag = 0;
                                }
                        }
#endif

                    /* Load Blacklist data */

                    if ( config->blacklist_flag )
                        {
                            __atomic_store_n (&counters->blacklist_count, 0, __ATOMIC_SEQ_CST);
                            Sagan_Blacklist_Init();
                            Sagan_Blacklist_Load();
                        }

                    if ( config->brointel_flag )
                        {
                            Sagan_BroIntel_Init();
                            Sagan_BroIntel_Load_File();
                        }

                    if ( config->sagan_track_clients_flag )
                        {
                            Sagan_Log(NORMAL, "Reset Sagan Track Client.");
                        }


                    /* Non output / processors */

                    if ( config->sagan_droplist_flag )
                        {
                            Load_Ignore_List();
                            Sagan_Log(NORMAL, "Loaded %d ignore/drop list item(s).", counters->droplist_count);
                        }

#ifdef HAVE_LIBMAXMINDDB
                    Sagan_Log(NORMAL, "Reloading GeoIP data.");
                    Open_GeoIP2_Database();
#endif


                    pthread_cond_signal(&SaganReloadCond);
                    pthread_mutex_unlock(&SaganReloadMutex);

                    config->sagan_reload = 0;

                    Sagan_Log(NORMAL, "Configuration reloaded.");
                    break;

                /* Signals to ignore */
                case 17:		/* Child process has exited. */
                case 28:		/* Terminal 'resize'/alarm. */
                case 33:		/* Interrupts GDB ("Real time" signal) */
                    break;

                case SIGUSR1:
                    Statistics();
                    break;

                default:
                    Sagan_Log(NORMAL, "[Received signal %d. Sagan doesn't know how to deal with]", sig);
                }
        }
}

