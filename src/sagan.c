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

/* sagan.c
 *
 * This is the main "thread" and engine that looks for events & patterns
 * based on 'snort like' rule sets.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <pcre.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "sagan.h"
#include "sagan-defs.h"
#include "version.h"

#include "sagan-credits.h"
#include "sagan-flowbit.h"
#include "sagan-processor.h"
#include "sagan-config.h"
#include "sagan-ignore-list.h"
#include "sagan-key.h"
#include "sagan-lockfile.h"
#include "sagan-signal.h"
#include "sagan-usage.h"
#include "parsers/parsers.h"

#ifdef HAVE_LIBPCAP
#include "sagan-plog.h"
#endif

#include "processors/sagan-engine.h"
#include "processors/sagan-search.h"
#include "processors/sagan-blacklist.h"
#include "processors/sagan-track-clients.h"
#include "processors/sagan-perfmon.h"
#include "processors/sagan-criticalstack.h"

#ifdef HAVE_LIBLOGNORM
#include "sagan-liblognorm.h"
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/sagan-unified2.h"
#endif

#define OVECCOUNT 30

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct class_struct *classstruct;
struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _Sagan_Flowbit *flowbit;


#ifdef WITH_WEBSENSE
#include <curl/curl.h>
#include "processors/sagan-websense.h"
#endif

sbool daemonize=0;
sbool sagan_reload=0;

struct _Sagan_Proc_Syslog *SaganProcSyslog = NULL;

int proc_msgslot=0;

pthread_cond_t SaganProcDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t SaganProcWorkMutex=PTHREAD_MUTEX_INITIALIZER;

/* ########################################################################
 * Start of main() thread
 * ######################################################################## */

int main(int argc, char **argv)
{

    const struct option long_options[] =
    {
        { "help",         no_argument,          NULL,   'h' },
        { "debug",        required_argument,    NULL,   'd' },
        { "daemon",       no_argument,          NULL,   'D' },
        { "user",         required_argument,    NULL,   'u' },
        { "chroot",       required_argument,    NULL,   'c' },
        { "credits",	  no_argument,		NULL,	'C' },
        { "config",       required_argument,    NULL,   'f' },
        { "log",          required_argument,    NULL,   'l' },
        { "file",	  required_argument,    NULL,   'F' },
        {0, 0, 0, 0}
    };

    static const char *short_options =
        "l:f:u:d:c:pDhC";

    int option_index = 0;

    /****************************************************************************/
    /* libpcap/PLOG (syslog sniffer) local variables                            */
    /****************************************************************************/

#ifdef HAVE_LIBPCAP
    pthread_t pcap_thread;
    pthread_attr_t thread_pcap_attr;
    pthread_attr_init(&thread_pcap_attr);
    pthread_attr_setdetachstate(&thread_pcap_attr,  PTHREAD_CREATE_DETACHED);
#endif

    /****************************************************************************/
    /* Perfmonitor local variables                                              */
    /****************************************************************************/

    pthread_t perfmonitor_thread;
    pthread_attr_t thread_perfmonitor_attr;
    pthread_attr_init(&thread_perfmonitor_attr);
    pthread_attr_setdetachstate(&thread_perfmonitor_attr,  PTHREAD_CREATE_DETACHED);

    /****************************************************************************/
    /* Various local variables						        */
    /****************************************************************************/

    /* Block all signals,  we create a signal handling thread */

    sigset_t signal_set;
    pthread_t sig_thread;
    sigfillset( &signal_set );
    pthread_sigmask( SIG_BLOCK, &signal_set, NULL );

    /* Key board handler (displays stats, etc */

    pthread_t key_thread;
    pthread_attr_t key_thread_attr;
    pthread_attr_init(&key_thread_attr);
    pthread_attr_setdetachstate(&key_thread_attr,  PTHREAD_CREATE_DETACHED);

    struct sockaddr_in sa;
    char src_dns_lookup[20];
    int  dns_flag=0;

    sbool fifoerr=0;

    char *syslog_host=NULL;
    char *syslog_facility=NULL;
    char *syslog_priority=NULL;
    char *syslog_level=NULL;
    char *syslog_tag=NULL;
    char *syslog_date=NULL;
    char *syslog_time=NULL;
    char *syslog_program=NULL;
    char *syslog_msg=NULL;

    char syslogstring[MAX_SYSLOGMSG];

    char c;
    char *tok;
    int rc=0;

    char *runas=RUNAS;

    int i;

    time_t t;
    struct tm *run;

    sbool debugflag=0;

    /* Allocate and clear memory for global structs */

    /* Allocate memory for global struct _SaganDebug */
    debug = malloc(sizeof(_SaganDebug));
    memset(debug, 0, sizeof(_SaganDebug));

    /* Allocate memroy for global struct _SaganConfig */
    config = malloc(sizeof(_SaganConfig));
    memset(config, 0, sizeof(_SaganConfig));

    struct _SaganSigArgs *sigargs;
    sigargs = malloc(sizeof(_SaganSigArgs));
    memset(sigargs, 0, sizeof(_SaganSigArgs));

    struct _SaganDNSCache *dnscache;
    dnscache = malloc(sizeof(_SaganDNSCache));
    memset(dnscache, 0, sizeof(_SaganDNSCache));

    counters = malloc(sizeof(_SaganCounters));
    memset(counters, 0, sizeof(_SaganCounters));

    flowbit = malloc(sizeof(_Sagan_Flowbit));
    memset(flowbit, 0, sizeof(_Sagan_Flowbit));

    t = time(NULL);
    run=localtime(&t);
    strftime(config->sagan_startutime, sizeof(config->sagan_startutime), "%s",  run);

    strlcpy(config->sagan_config, CONFIG_FILE_PATH, sizeof(config->sagan_config));

    /* We set the config->sagan_log_filepath to the system default.  It'll be fopen'ed
       shortly - 06/03/2011 - Champ Clark III */

    strlcpy(config->sagan_log_filepath, SAGANLOG, sizeof(config->sagan_log_filepath));

    /* Get command line arg's */
    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {

            switch(c)
                {

                    if (c == -1) break;

                case 'h':
                    Sagan_Usage();
                    exit(0);
                    break;

                case 'C':
                    Sagan_Credits();
                    exit(0);
                    break;

                case 'd':

		    if (Sagan_strstr(optarg, "criticalstack")) 
			{
		            debug->debugcriticalstack=1; 
			    debugflag=1; 
			}

                    if (Sagan_strstr(optarg, "syslog"))
                        {
                            debug->debugsyslog=1;
                            debugflag=1;
                        }

                    if (Sagan_strstr(optarg, "load"))
                        {
                            debug->debugload=1;
                            debugflag=1;
                        }

                    if (Sagan_strstr(optarg, "fwsam"))
                        {
                            debug->debugfwsam=1;
                            debugflag=1;
                        }

                    if (Sagan_strstr(optarg, "external"))
                        {
                            debug->debugexternal=1;
                            debugflag=1;
                        }

                    if (Sagan_strstr(optarg, "threads"))
                        {
                            debug->debugthreads=1;
                            debugflag=1;
                        }

                    if (Sagan_strstr(optarg, "flowbit"))
                        {
                            debug->debugflowbit=1;
                            debugflag=1;
                        }

                    if (Sagan_strstr(optarg, "engine"))
                        {
                            debug->debugengine=1;
                            debugflag=1;
                        }

#ifdef HAVE_LIBGEOIP
                    if (Sagan_strstr(optarg, "geoip"))
                        {
                            debug->debuggeoip=1;
                            debugflag=1;
                        }
#endif

#ifdef HAVE_LIBLOGNORM
                    if (Sagan_strstr(optarg, "normalize" ))
                        {
                            debug->debugnormalize=1;
                            debugflag=1;
                        }
#endif

#ifdef HAVE_LIBESMTP
                    if (Sagan_strstr(optarg, "smtp"))
                        {
                            debug->debugesmtp=1;
                            debugflag=1;
                        }
#endif

#ifdef HAVE_LIBPCAP
                    if (Sagan_strstr(optarg, "plog"))
                        {
                            debug->debugplog=1;
                            debugflag=1;
                        }
#endif

#ifdef WITH_WEBSENSE
                    if (Sagan_strstr(optarg, "websense"))
                        {
                            debug->debugwebsense=1;
                            debugflag=1;
                        }
#endif

                    /* If option is unknown */

                    if ( debugflag == 0 )
                        {
                            fprintf(stderr, "Unknown debug option %s!\n", optarg);
                            exit(1);
                        }


                    break;

                case 'D':
                    daemonize=1;
                    break;

                case 'u':
                    runas=optarg;
                    break;

                case 'c':
                    Chroot(runas,optarg);
                    break;

                case 'F':
                    config->sagan_fifo_flag=1;
                    strlcpy(config->sagan_fifo,optarg,sizeof(config->sagan_fifo) - 1);
                    break;

                case 'f':
                    strlcpy(config->sagan_config,optarg,sizeof(config->sagan_config) - 1);
                    break;

                case 'l':
                    strlcpy(config->sagan_log_filepath,optarg,sizeof(config->sagan_log_filepath) - 1);
                    break;

                default:
                    fprintf(stderr, "Invalid argument! See below for command line switches.\n");
                    Sagan_Usage();
                    exit(0);
                    break;
                }
        }

    /* Open the sagan.log file.  Moved from sagan-config.c as it became to complex
       06/03/2011 - Champ Clark */

    if ((config->sagan_log_stream = fopen(config->sagan_log_filepath, "a")) == NULL)
        {
            fprintf(stderr, "[E] [%s, line %d] Cannot open %s!\n", __FILE__, __LINE__, config->sagan_log_filepath);
            exit(1);
        }


    Load_Config();
    Sagan_Engine_Init();

#ifdef HAVE_LIBLOGNORM
    Sagan_Liblognorm_Load();
#endif


    /* Load/init liblognorm definitions.  I tried to move this into a subroutine,
     * but that ended up causing segfaults on ln_normalize() or causing
     * liblognorm not to function correctly (not parsing fields).  Make reloading
     * a SIGHUP a issue as well.
     * 12/17/2010 - Champ
     */

    SaganProcSyslog = malloc(config->max_processor_threads * sizeof(struct _Sagan_Proc_Syslog));
    pthread_t processor_id[config->max_processor_threads];
    pthread_attr_t thread_processor_attr;
    pthread_attr_init(&thread_processor_attr);
    pthread_attr_setdetachstate(&thread_processor_attr,  PTHREAD_CREATE_DETACHED);

    Sagan_Log(S_NORMAL, "Configuration file %s loaded and %d rules loaded.", config->sagan_config, counters->rulecount);
    Sagan_Log(S_NORMAL, "Out of %d rules, %d Flowbit(s) are in use.", counters->rulecount, counters->flowbit_total_counter);
    Sagan_Log(S_NORMAL, "Sagan version %s is firing up!", VERSION);

    /* We go ahead and assign values to SaganSigArgs (struct sig_thread_args).  This
     * struct is always used by the sig_handler thread,  and sometimes used by the
     * plog_handler (below).  So we assign values now */

    sigargs->daemonize = daemonize;

#ifdef HAVE_LIBPCAP

    /* Spawn a thread to 'sniff' syslog traffic (sagan-plog.c).  This redirects syslog
       traffic to the /dev/log socket.  This needs "root" access,  so we drop priv's
       after this thread is started */

    if ( config->plog_flag )
        {

            rc = pthread_create( &pcap_thread, NULL, (void *)plog_handler, sigargs );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(S_ERROR, "[%s, line %d] Error creating libpcap handler thread [error: %d].", __FILE__, __LINE__, rc);
                }

            sleep(1); 	/* Sleep to avoid race between main() and plog thread
		   	plog thread needs "root" rights before sagan_droppriv().
		   	In some cases main() run sagan_droppriv() before thread
		   	can complete - Champ Clark - 07/20/2011 */

        }
#endif


    sagan_droppriv(runas);              /* Become the Sagan user */
    Sagan_Log(S_NORMAL, "---------------------------------------------------------------------------");


    if ( config->perfmonitor_flag )
        {

            if (( config->perfmonitor_file_stream = fopen(config->perfmonitor_file_name, "a" )) == NULL )
                {
                    Remove_Lock_File();
                    Sagan_Log(S_ERROR, "[%s, line %d] Can't open %s!", __FILE__, __LINE__, config->perfmonitor_file_name);
                }


            rc = pthread_create( &perfmonitor_thread, NULL, (void *)Sagan_Perfmonitor_Handler, sigargs );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(S_ERROR, "[%s, line %d] Error creating Perfmonitor thread [error: %d].", __FILE__, __LINE__, rc);
                }
        }


    /* Open sagan alert file */

    if (( config->sagan_alert_stream = fopen(config->sagan_alert_filepath, "a" )) == NULL )
        {
            Remove_Lock_File();
            Sagan_Log(S_ERROR, "[%s, line %d] Can't open %s!", __FILE__, __LINE__, config->sagan_alert_filepath);
        }

    /****************************************************************************
     * Display processor information as we load
     ****************************************************************************/

    /* Sagan_Track_Clients processor ********************************************/

    if ( config->sagan_track_clients_flag)
        {
            if ( config->pp_sagan_track_clients ) Sagan_Log(S_NORMAL, "Client Tracking Processor: %d minute(s)", config->pp_sagan_track_clients);
            Sagan_Load_Tracking_Cache();
        }

    /* Sagan Blacklist IP processor *********************************************/

    if ( config->blacklist_flag)
        {
            Sagan_Blacklist_Load();
            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "Blacklist Processor loaded [%s]", config->blacklist_file);
            Sagan_Log(S_NORMAL, "Blacklist loaded %d entries", counters->blacklist_count);
            Sagan_Log(S_NORMAL, "Blacklist Parse Depth: %d", config->blacklist_parse_depth);

#ifdef HAVE_LIBLOGNORM
            if (config->blacklist_lognorm)
                {
                    Sagan_Log(S_NORMAL, "Blacklist Liblognorm: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Blacklist Liblognorm: Disabled");
                }
#endif

#ifndef HAVE_LIBLOGNORM
            if (config->blacklist_lognorm)
                {
                    Sagan_Log(S_WARN, "Blacklist Liblognorm: Disabled (lacks compiled in support!)");
                    config->blacklist_lognorm=0;
                }
#endif

            if (config->blacklist_parse_proto)
                {
                    Sagan_Log(S_NORMAL, "Blacklist Parse_Protocol: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Blacklist Parse Protocol: Disabled");
                }

            if (config->blacklist_parse_proto_program)
                {
                    Sagan_Log(S_NORMAL, "Blacklist Parse Protocol via Program: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Blacklist Parse Protocol via Program: Disabled");
                }

            if (config->blacklist_parse_src) Sagan_Log(S_NORMAL, "Blacklist Default Source Position: %d", config->blacklist_parse_src);
            if (config->blacklist_parse_dst) Sagan_Log(S_NORMAL, "Blacklist Default Destination Position: %d", config->blacklist_parse_dst);

        }

    /* Sagan Search [nocase ****************************************************/

    if ( config->search_nocase_flag)
        {
            Sagan_Search_Load( 1 );
            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "Search [nocase] Processor loaded [%s]", config->search_nocase_file);
            Sagan_Log(S_NORMAL, "Search [nocase] loaded %d entries", counters->search_nocase_count);
            Sagan_Log(S_NORMAL, "Search [nocase] Parse Depth: %d", config->search_nocase_parse_depth);

#ifdef HAVE_LIBLOGNORM
            if (config->search_nocase_lognorm)
                {
                    Sagan_Log(S_NORMAL, "Search [nocase] Liblognorm: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Search [nocase] Liblognorm: Disabled");
                }
#endif

#ifndef HAVE_LIBLOGNORM
            if (config->search_nocase_lognorm)
                {
                    Sagan_Log(S_WARN, "Search [nocase] Liblognorm: Disabled (lacks compiled in support!)");
                    config->search_nocase_lognorm = 0;
                }
#endif

            if (config->search_nocase_parse_proto)
                {
                    Sagan_Log(S_NORMAL, "Search [nocase] Parse Protocol: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Search [nocase] Parse Protocol: Disabled");
                }

            if (config->search_nocase_parse_proto_program)
                {
                    Sagan_Log(S_NORMAL, "Search [nocase] Parse Protocol via Program: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Search [nocase] Parse Protocol via Program: Disabled");
                }

            if (config->search_nocase_parse_src) Sagan_Log(S_NORMAL, "Search [nocase] Default Source Position: %d", config->search_nocase_parse_src);
            if (config->search_nocase_parse_dst) Sagan_Log(S_NORMAL, "Search [nocase] Default Destination Position: %d", config->search_nocase_parse_dst);
        }

    /* Sagan Search ************************************************************/

    if ( config->search_case_flag)
        {
            Sagan_Search_Load( 2 );
            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "Search Processor loaded [%s]", config->search_case_file);
            Sagan_Log(S_NORMAL, "Search loaded %d entries", counters->search_case_count);
            Sagan_Log(S_NORMAL, "Search [nocase] Parse Depth: %d", config->search_case_parse_depth);

#ifdef HAVE_LIBLOGNORM
            if (config->search_case_lognorm)
                {
                    Sagan_Log(S_NORMAL, "Search Liblognorm: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Search Liblognorm: Disabled");
                }
#endif

#ifndef HAVE_LIBLOGNORM
            if (config->search_case_lognorm)
                {
                    Sagan_Log(S_WARN, "Search Liblognorm: Disabled (lacks compiled in support!)");
                    config->search_case_lognorm = 0;
                }
#endif

            if (config->search_case_parse_proto)
                {
                    Sagan_Log(S_NORMAL, "Search Parse Protocol: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Search Parse Protocol: Disabled");
                }

            if (config->search_case_parse_proto_program)
                {
                    Sagan_Log(S_NORMAL, "Search Parse Protocol via Program: Enabled");
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Search Parse Protocol via Program: Disabled");
                }

            if (config->search_case_parse_src) Sagan_Log(S_NORMAL, "Search Default Source Position: %d", config->search_case_parse_src);
            if (config->search_case_parse_dst) Sagan_Log(S_NORMAL, "Search Default Destination Position: %d", config->search_case_parse_dst);

        }

    /* Sagan Websense processor ************************************************/

#ifdef WITH_WEBSENSE
    if ( config->websense_flag )
        {

            curl_global_init(CURL_GLOBAL_ALL);
            config->websense_last_time = atol(config->sagan_startutime);
            Sagan_Websense_Init();
            Sagan_Websense_Ignore_List();

            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "Websense URL: %s", config->websense_url);
            Sagan_Log(S_NORMAL, "Websense Auth: %s", config->websense_auth);
            Sagan_Log(S_NORMAL, "Websense Device ID: %s", config->websense_device_id);
            Sagan_Log(S_NORMAL, "Websense Parse Depth: %d", config->websense_parse_depth);
            Sagan_Log(S_NORMAL, "Websense Max Cache: %d", config->websense_max_cache);
            Sagan_Log(S_NORMAL, "Websense Cache Timeout: %d minutes", config->websense_timeout  / 60);
            Sagan_Log(S_NORMAL, "Websense Ignore List File: %s", config->websense_ignore_list);
            Sagan_Log(S_NORMAL, "Websense Ignore List entries: %d", counters->websense_ignore_list_count);
        }

    if ( config->websense_lognorm ) Sagan_Log(S_NORMAL, "Websense Liblognorm: Enabled");
    if ( config->websense_parse_src ) Sagan_Log(S_NORMAL, "Websense Default Parse Source Depth: %d", config->websense_parse_src);
    if ( config->websense_parse_dst ) Sagan_Log(S_NORMAL, "Websense Default Parse Destination Depth: %d", config->websense_parse_dst);

#endif

    /* Sagan Critical Stack processor *******************************************/

    if ( config->criticalstack_flag ) 
	{

		Sagan_CriticalStack_Init(); 
		Sagan_CriticalStack_Load_File(); 

		Sagan_Log(S_NORMAL, ""); 
		Sagan_Log(S_NORMAL, "Critical Stack File: %s", config->criticalstack_file); 

/*
	if (strcmp(config->criticalstack_ignorefile, "")) 
			{
			Sagan_Log(S_NORMAL, "Critical Stack Ignore File: %s", config->criticalstack_ignorefile); 
			} else { 
			Sagan_Log(S_NORMAL, "Critical Stack Ignore File: [None]"); 
			}

		Sagan_Log(S_NORMAL, "Critical Stack Parse Depth: %d", config->criticalstack_parse_depth); 
		Sagan_Log(S_NORMAL, "Critical Stack Priority: %d", config->criticalstack_priority); 

		if ( config->criticalstack_lognorm ) Sagan_Log(S_NORMAL, "Critical Stack Liblognorm: Enabled"); 
		if ( config->criticalstack_rules_only ) Sagan_Log(S_NORMAL, "Critical Stack Rules Only: Enabled");
		if ( config->criticalstack_parse_proto ) Sagan_Log(S_NORMAL, "Critical Stack Parse Proto: Enabled");
		if ( config->criticalstack_parse_proto_program) Sagan_Log(S_NORMAL, "Critical Stack Parse Proto Program: Enabled");
		if ( config->criticalstack_parse_src ) Sagan_Log(S_NORMAL, "Critical Stack Default Parse Source Depth: %d", config->criticalstack_parse_src); 
                if ( config->criticalstack_parse_dst ) Sagan_Log(S_NORMAL, "Critical Stack Default Parse Destination Depth: %d", config->criticalstack_parse_dst);
*/

		Sagan_Log(S_NORMAL, "Critical Stack Intel::ADDR Loaded: %d", counters->criticalstack_addr_count);
		Sagan_Log(S_NORMAL, "Critical Stack Intel::DOMAIN Loaded: %d", counters->criticalstack_domain_count);
		Sagan_Log(S_NORMAL, "Critical Stack Intel::FILE_HASH Loaded: %d", counters->criticalstack_file_hash_count); 
		Sagan_Log(S_NORMAL, "Critical Stack Intel::URL Loaded: %d", counters->criticalstack_url_count);
		Sagan_Log(S_NORMAL, "Critical Stack Intel::SOFTWARE Loaded: %d", counters->criticalstack_software_count); 
		Sagan_Log(S_NORMAL, "Critical Stack Intel::EMAIL Loaded: %d", counters->criticalstack_email_count);
		Sagan_Log(S_NORMAL, "Critical Stack Intel::USER_NAME Loaded: %d", counters->criticalstack_user_name_count);
		Sagan_Log(S_NORMAL, "Critical Stack Intel::FILE_NAME Loaded: %d", counters->criticalstack_file_name_count);
		Sagan_Log(S_NORMAL, "Critical Stack Intel::CERT_HASH Loaded: %d", counters->criticalstack_cert_hash_count);

		
	}

    /***************************************************************************
     * Output plugins
     ***************************************************************************/

#ifdef HAVE_LIBESMTP
    if ( config->sagan_esmtp_flag )
        {
            Sagan_Log(S_NORMAL, "");
            if ( config->min_email_priority ) Sagan_Log(S_NORMAL, "E-mail on priority %d or higher.", config->min_email_priority);
            Sagan_Log(S_NORMAL, "E-Mail will be sent from: %s", config->sagan_esmtp_from);
            Sagan_Log(S_NORMAL, "SMTP server is set to: %s", config->sagan_esmtp_server);
        }
#endif

#ifdef WITH_SNORTSAM

    if ( config->sagan_fwsam_flag )
        {
            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "Snortsam output plug in enabled.");
        }

#endif

    if ( config->sagan_external_output_flag )
        {
            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "External program to be called: %s", config->sagan_extern);
        }

    /* Unified2 ****************************************************************/

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

    if ( config->sagan_unified2_flag )
        {
            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "Unified2 file: %s", config->unified2_filepath);
            Sagan_Log(S_NORMAL, "Unified2 limit: %dM", config->unified2_limit  / 1024 / 1024 );
            Unified2InitFile();
        }

#endif

    /***************************************************************************
     * Non-Processor/Output option
     ***************************************************************************/

    /* What to "ignore" ********************************************************/

    if ( config->sagan_droplist_flag )
        {
            Load_Ignore_List();
            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "Loaded %d ignore/drop list item(s).", counters->droplist_count);
        }

    /***************************************************************************
     * Continue with normal startup!
     ***************************************************************************/

    Sagan_Log(S_NORMAL, "");
    Sagan_Log(S_NORMAL, " ,-._,-. 	-*> Sagan! <*-");
    Sagan_Log(S_NORMAL, " \\/)\"(\\/	Version %s", VERSION);
    Sagan_Log(S_NORMAL, "  (_o_)	Champ Clark III & The Quadrant InfoSec Team [quadrantsec.com]");
    Sagan_Log(S_NORMAL, "  /   \\/)	Copyright (C) 2009-2015 Quadrant Information Security, et al.");
    Sagan_Log(S_NORMAL, " (|| ||) 	Using PCRE version: %s", pcre_version());
    Sagan_Log(S_NORMAL, "  oo-oo     Sagan is processing events.....");
    Sagan_Log(S_NORMAL, "");

    /* Become a daemon if requested */

    if ( daemonize )
        {
            Sagan_Log(S_NORMAL, "Becoming a daemon!");

            pid_t pid = 0;
            setsid();
            pid = fork();
            if (pid == 0) {}
            else
                {
                    exit(0);
                }
        }

    /* Create the signal handlers thread _after_ the fork() so it can properly
     * handly signals - Champ Clark III - 06/13/2011 */

    rc = pthread_create( &sig_thread, NULL, (void *)Sig_Handler, sigargs );

    if ( rc != 0  )
        {
            Remove_Lock_File();
            Sagan_Log(S_ERROR, "[%s, line %d] Error creating signal handler thread. [error: %d]", __FILE__, __LINE__, rc);
        }


    /* We don't want the key_handler() if we're in daemon mode! */

    if (!daemonize)
        {

            rc = pthread_create( &key_thread, NULL, (void *)key_handler, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(S_ERROR, "[%s, line %d] Error creating key_handler thread. [error: %d]", __FILE__, __LINE__, rc);
                }

        }

    /* We do this after forking so init scripts can complete */

    /* Check lock file _after_ thread.  If you don't it'll retreive the wrong pid
     * and incorrectly believe there is a stale lock file if --daemon */

    checklockfile();

    Sagan_Log(S_NORMAL, "Spawning %d Processor Threads.", config->max_processor_threads);

    for (i = 0; i < config->max_processor_threads; i++)
        {

            rc = pthread_create ( &processor_id[i], &thread_processor_attr, (void *)Sagan_Processor, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(S_ERROR, "Could not pthread_create() for I/O processors [error: %d]", rc);
                }
        }

    Sagan_Log(S_NORMAL, "");

    if ( config->sagan_fifo_flag == 0 )
        {
            Sagan_Log(S_NORMAL, "Attempting to open syslog FIFO (%s).", config->sagan_fifo);
        }
    else
        {
            Sagan_Log(S_NORMAL, "Attempting to open syslog FILE (%s).", config->sagan_fifo);
        }



    while(1)
        {

            FILE *fd;
            fd = fopen(config->sagan_fifo, "r");

            if ( config->sagan_fifo_flag == 0 )
                {
                    Sagan_Log(S_NORMAL, "Successfully opened FIFO (%s).", config->sagan_fifo);
                }
            else
                {
                    Sagan_Log(S_NORMAL, "Successfully opened FILE (%s) and processing events.....", config->sagan_fifo);
                }

            while(fd != NULL)
                {


                    while(fgets(syslogstring, sizeof(syslogstring), fd) != NULL)
                        {

                            /* If the FIFO was in a error state,  let user know the FIFO writer has resumed */

                            if ( fifoerr == 1 )
                                {
                                    Sagan_Log(S_NORMAL, "FIFO writer has restarted. Processing events.");
                                    fifoerr=0;
                                }

                            counters->sagantotal++;

                            syslog_host = strtok_r(syslogstring, "|", &tok);

                            /* If we're using DNS (and we shouldn't be!),  we start DNS checks and lookups
                             * here.  We cache both good and bad lookups to not over load our DNS server(s).
                             * The only way DNS cache can be cleared is to restart Sagan */

                            if (config->syslog_src_lookup )
                                {
                                    if ( inet_pton(AF_INET, syslog_host, &(sa.sin_addr)) == 0 )   	/* Is inbound a valid IP? */
                                        {
                                            dns_flag=0;

                                            for(i=0; i <= counters->dns_cache_count ; i++)  			/* Check cache first */
                                                {
                                                    if (!strcmp( dnscache[i].hostname, syslog_host))
                                                        {
                                                            syslog_host = dnscache[i].src_ip;
                                                            dns_flag=1;
                                                        }
                                                }

                                            /* If entry was not found in cache,  look it up */

                                            if ( dns_flag == 0 )
                                                {

                                                    /* Do a DNS lookup */
                                                    strlcpy(src_dns_lookup, DNS_Lookup(syslog_host), sizeof(src_dns_lookup));

                                                    /* Invalid lookups get the config->sagan_host value */

                                                    if (src_dns_lookup[0] == '0' )
                                                        {
                                                            strlcpy(src_dns_lookup, config->sagan_host, sizeof(src_dns_lookup));
                                                            counters->dns_miss_count++;
                                                        }


                                                    /* Add entry to DNS Cache */

                                                    dnscache = (_SaganDNSCache *) realloc(dnscache, (counters->dns_cache_count+1) * sizeof(_SaganDNSCache));
                                                    strlcpy(dnscache[counters->dns_cache_count].hostname, syslog_host, sizeof(dnscache[counters->dns_cache_count].hostname));
                                                    strlcpy(dnscache[counters->dns_cache_count].src_ip, src_dns_lookup, sizeof(dnscache[counters->dns_cache_count].src_ip));
                                                    counters->dns_cache_count++;
                                                    syslog_host = src_dns_lookup;

                                                }
                                        }

                                }
                            else
                                {

                                    /* We check to see if values from our FIFO are valid.  If we aren't doing DNS related
                                    * stuff (above),  we start basic check with the syslog_host */

                                    if (syslog_host == NULL || inet_pton(AF_INET, syslog_host, &(sa.sin_addr)) == 0  )
                                        {
                                            syslog_host = config->sagan_host;
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'host' (replaced with %s)", config->sagan_host);
                                        }
                                }

//	        if ( config->home_any == 1) {

                            /* We know check the rest of the values */

                            syslog_facility=strtok_r(NULL, "|", &tok);
                            if ( syslog_facility == NULL )
                                {
                                    syslog_facility = "SAGAN: FACILITY ERROR";
                                    Sagan_Log(S_WARN, "Sagan received a malformed 'facility'");
                                }

                            syslog_priority=strtok_r(NULL, "|", &tok);
                            if ( syslog_priority == NULL )
                                {
                                    syslog_priority = "SAGAN: PRIORITY ERROR";
                                    Sagan_Log(S_WARN, "Sagan received a malformed 'priority'");
                                }

                            syslog_level=strtok_r(NULL, "|", &tok);
                            if ( syslog_level == NULL )
                                {
                                    syslog_level = "SAGAN: LEVEL ERROR";
                                    Sagan_Log(S_WARN, "Sagan received a malformed 'level'");
                                }

                            syslog_tag=strtok_r(NULL, "|", &tok);
                            if ( syslog_tag == NULL )
                                {
                                    syslog_tag = "SAGAN: TAG ERROR";
                                    Sagan_Log(S_WARN, "Sagan received a malformed 'tag'");
                                }

                            syslog_date=strtok_r(NULL, "|", &tok);
                            if ( syslog_date == NULL )
                                {
                                    syslog_date = "SAGAN: DATE ERROR";
                                    Sagan_Log(S_WARN, "Sagan received a malformed 'date'");
                                }

                            syslog_time=strtok_r(NULL, "|", &tok);
                            if ( syslog_time == NULL )
                                {
                                    syslog_time = "SAGAN: TIME ERROR";
                                    Sagan_Log(S_WARN, "Sagan received a malformed 'time'");
                                }


                            syslog_program=strtok_r(NULL, "|", &tok);
                            if ( syslog_program == NULL )
                                {
                                    syslog_program = "SAGAN: PROGRAM ERROR";
                                    Sagan_Log(S_WARN, "Sagan received a malformed 'program'");
                                }

                            syslog_msg=strtok_r(NULL, "", &tok);		/* In case the message has | in it,  we delimit on "" */
                            if ( syslog_msg == NULL )
                                {
                                    syslog_msg = "SAGAN: MESSAGE ERROR";
                                    Sagan_Log(S_WARN, "Sagan received a malformed 'message' [Syslog Host: %s]", syslog_host);


                                    /* If the message is lost,  all is lost.  Typically,  you don't lose part of the message,
                                     * it's more likely to lose all  - Champ Clark III 11/17/2011 */

                                    counters->sagan_log_drop++;

                                }


                            /* Strip any \n or \r from the syslog_msg */

                            if ( strcspn ( syslog_msg, "\n" ) < strlen(syslog_msg) )
                                syslog_msg[strcspn ( syslog_msg, "\n" )] = '\0';

                            if ( proc_msgslot < config->max_processor_threads )
                                {

                                    pthread_mutex_lock(&SaganProcWorkMutex);

                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_host, syslog_host, sizeof(SaganProcSyslog[proc_msgslot].syslog_host));
                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_facility, syslog_facility, sizeof(SaganProcSyslog[proc_msgslot].syslog_facility));
                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_priority, syslog_priority, sizeof(SaganProcSyslog[proc_msgslot].syslog_priority));
                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_level, syslog_level, sizeof(SaganProcSyslog[proc_msgslot].syslog_level));
                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_tag, syslog_tag, sizeof(SaganProcSyslog[proc_msgslot].syslog_tag));
                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_date, syslog_date, sizeof(SaganProcSyslog[proc_msgslot].syslog_date));
                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_time, syslog_time, sizeof(SaganProcSyslog[proc_msgslot].syslog_time));
                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_program, syslog_program, sizeof(SaganProcSyslog[proc_msgslot].syslog_program));
                                    strlcpy(SaganProcSyslog[proc_msgslot].syslog_message, syslog_msg, sizeof(SaganProcSyslog[proc_msgslot].syslog_message));

                                    proc_msgslot++;

                                    pthread_cond_signal(&SaganProcDoWork);
                                    pthread_mutex_unlock(&SaganProcWorkMutex);
                                }
                            else
                                {
                                    Sagan_Log(S_WARN, "[%s, line %d] Out of worker threads!", __FILE__, __LINE__);
                                    counters->sagan_log_drop++;
                                }

                            if (debug->debugthreads) Sagan_Log(S_DEBUG, "Current \"proc_msgslot\": %d", proc_msgslot);

                            if (debug->debugsyslog)
                                {

                                    Sagan_Log(S_DEBUG, "[%s, line %d] **[RAW Syslog]*********************************", __FILE__, __LINE__);
                                    Sagan_Log(S_DEBUG, "[%s, line %d] Host: %s | Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s", __FILE__, __LINE__, syslog_host, syslog_program, syslog_facility, syslog_priority, syslog_level, syslog_tag);
                                    Sagan_Log(S_DEBUG, "[%s, line %d] Raw message: %s", __FILE__, __LINE__, syslog_msg);

                                }


                        } /* while(fgets) */

                    /* fgets() has returned a error,  likely due to the FIFO writer leaving */

                    /* DEBUG : set a kill flag and join */
                    /* RMEOVE LOCK */

                    if ( fifoerr == 0 )
                        {
                            if ( config->sagan_fifo_flag != 0 )
                                {
                                    Sagan_Log(S_NORMAL, "EOF reached. Waiting for threads to catch up");
                                    sleep(5);
                                    fclose(fd);
                                    Sagan_Log(S_NORMAL, "Exiting.");		/* DEBUG: Rejoin threads */
                                    exit(0);
                                }
                            else
                                {
                                    Sagan_Log(S_WARN, "FIFO writer closed.  Waiting for FIFO write to restart....");
                                    fifoerr=1; 			/* Set flag so our wile(fgets) knows */
                                }
                        }
                    sleep(1);		/* So we don't eat 100% CPU */

                } /* while(fd != NULL)  */

            fclose(fd); 			/* ???? */

        } /* End of while(1) */

} /* End of main */


