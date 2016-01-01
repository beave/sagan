/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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
#include <stdbool.h>

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
#include "sagan-stats.h"
#include "sagan-ipc.h"
#include "parsers/parsers.h"

#ifdef HAVE_LIBPCAP
#include "sagan-plog.h"
#endif

#include "processors/sagan-engine.h"
#include "processors/sagan-blacklist.h"
#include "processors/sagan-track-clients.h"
#include "processors/sagan-perfmon.h"
#include "processors/sagan-bro-intel.h"

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

#ifdef WITH_BLUEDOT
#include <curl/curl.h>
#include "processors/sagan-bluedot.h"
#endif

sbool daemonize=0;
sbool quiet=0;

struct _Sagan_Proc_Syslog *SaganProcSyslog = NULL;

int proc_msgslot=0;

pthread_cond_t SaganProcDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t SaganProcWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganMalformedCounter=PTHREAD_MUTEX_INITIALIZER;

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
        "l:f:u:F:d:c:pDhC";

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

    signed char c;
    char *tok;
    int rc=0;

    int i;

    time_t t;
    struct tm *run;

    sbool debugflag=0;

    /* Allocate and clear memory for global structs */

    /* Allocate memory for global struct _SaganDebug */

    debug = malloc(sizeof(_SaganDebug));

    if ( debug == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for debug. Abort!", __FILE__, __LINE__);
        }

    memset(debug, 0, sizeof(_SaganDebug));

    /* Allocate memroy for global struct _SaganConfig */

    config = malloc(sizeof(_SaganConfig));

    if ( config == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for config. Abort!", __FILE__, __LINE__);
        }

    memset(config, 0, sizeof(_SaganConfig));

    struct _SaganSigArgs *sigargs;
    sigargs = malloc(sizeof(_SaganSigArgs));

    if ( sigargs == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for sigargs. Abort!", __FILE__, __LINE__);
        }

    memset(sigargs, 0, sizeof(_SaganSigArgs));

    struct _SaganDNSCache *dnscache;
    dnscache = malloc(sizeof(_SaganDNSCache));

    if ( dnscache == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for dnscache. Abort!", __FILE__, __LINE__);
        }

    memset(dnscache, 0, sizeof(_SaganDNSCache));

    counters = malloc(sizeof(_SaganCounters));

    if ( counters == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for counters. Abort!", __FILE__, __LINE__);
        }

    memset(counters, 0, sizeof(_SaganCounters));

    t = time(NULL);
    run=localtime(&t);
    strftime(config->sagan_startutime, sizeof(config->sagan_startutime), "%s",  run);

    strlcpy(config->sagan_config, CONFIG_FILE_PATH, sizeof(config->sagan_config));

    config->sagan_fifo[0] = '\0';	/* Set this here.  This could be a file via
    					   comamnd line or FIFO via configuration
					   file */

    /* We set the config->sagan_log_filepath to the system default.  It'll be fopen'ed
       shortly - 06/03/2011 - Champ Clark III */

    strlcpy(config->sagan_log_filepath, SAGANLOG, sizeof(config->sagan_log_filepath));
    config->sagan_runas = RUNAS;

    /* "systemd" wants to start Sagan in the foreground,  but doesn't know what to
     * do with stdin/stdout.  Hence,  CPU goes to 100%.  This detects our terminal
     * type ( >/dev/null </dev/null ) and tell's Sagan to ignore input and output.
     *
     * For more details, see:
     *
     * https://groups.google.com/forum/#!topic/sagan-users/kgJvf1eyQcg
     *
     */

    if ( !isatty(0) || !isatty(1) || !isatty(2) )
        {
            quiet = 1;
        }


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

                    if (Sagan_strstr(optarg, "malformed"))
                        {
                            debug->debugmalformed=1;
                            debugflag=1;
                        }

                    if (Sagan_strstr(optarg, "limits"))
                        {
                            debug->debuglimits=1;
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

                    if (Sagan_strstr(optarg, "brointel"))
                        {
                            debug->debugbrointel=1;
                            debugflag=1;
                        }

                    if (Sagan_strstr(optarg, "ipc"))
                        {
                            debug->debugipc=1;
                            debugflag=1;
                        }

#ifdef HAVE_LIBMAXMINDDB

                    if (Sagan_strstr(optarg, "geoip2"))
                        {
                            debug->debuggeoip2=1;
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

#ifdef WITH_BLUEDOT
                    if (Sagan_strstr(optarg, "bluedot"))
                        {
                            debug->debugbluedot=1;
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
                    config->sagan_runas=optarg;
                    break;

                case 'c':
                    Sagan_Chroot(optarg);
                    break;

                case 'F':
                    config->sagan_is_file=1;
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

    Sagan_Open_Log_File(OPEN, SAGAN_LOG);

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

    if ( SaganProcSyslog == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog. Abort!", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog, 0, sizeof(struct _Sagan_Proc_Syslog));

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


    Sagan_Droppriv();              /* Become the Sagan user */
    Sagan_Log(S_NORMAL, "---------------------------------------------------------------------------");

    Sagan_IPC_Init();

    if ( config->perfmonitor_flag )
        {

            Sagan_Perfmonitor_Open();

            rc = pthread_create( &perfmonitor_thread, NULL, (void *)Sagan_Perfmonitor_Handler, sigargs );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(S_ERROR, "[%s, line %d] Error creating Perfmonitor thread [error: %d].", __FILE__, __LINE__, rc);
                }
        }


    /* Open sagan alert file */

    Sagan_Open_Log_File(OPEN, ALERT_LOG);

    /****************************************************************************
     * Display processor information as we load
     ****************************************************************************/

    /* Sagan_Track_Clients processor ********************************************/

    if ( config->sagan_track_clients_flag )
        {

            Sagan_Track_Clients_Init();

            if ( config->pp_sagan_track_clients )
                {
                    Sagan_Log(S_NORMAL, "");
                    Sagan_Log(S_NORMAL, "Client Tracking Processor: %d minute(s)", config->pp_sagan_track_clients);
                }

        }

    /* Sagan Blacklist IP processor *********************************************/

    if ( config->blacklist_flag)
        {
            Sagan_Blacklist_Init();
            Sagan_Blacklist_Load();
        }

#ifdef WITH_BLUEDOT
    if ( config->bluedot_flag )
        {

            curl_global_init(CURL_GLOBAL_ALL);
            Sagan_Bluedot_Init();

            Sagan_Log(S_NORMAL, "");
            Sagan_Log(S_NORMAL, "Bluedot URL: %s", config->bluedot_url);
//            Sagan_Log(S_NORMAL, "Bluedot Auth: %s", config->bluedot_auth);
            Sagan_Log(S_NORMAL, "Bluedot Device ID: %s", config->bluedot_device_id);
            Sagan_Log(S_NORMAL, "Bluedot Categories File: %s", config->bluedot_cat);
            Sagan_Log(S_NORMAL, "Bluedot Max Cache: %d", config->bluedot_max_cache);
            Sagan_Log(S_NORMAL, "Bluedot Cache Timeout: %d minutes.", config->bluedot_timeout  / 60);
            Sagan_Log(S_NORMAL, "Bluedot loaded %d categories.", counters->bluedot_cat_count);

        }

#endif


    /* Sagan Bro Intel processor *******************************************/

    if ( config->brointel_flag )
        {

            Sagan_Log(S_NORMAL, "");

            Sagan_BroIntel_Init();
            Sagan_BroIntel_Load_File();

            Sagan_Log(S_NORMAL, "Bro Intel::ADDR Loaded: %d", counters->brointel_addr_count);
            Sagan_Log(S_NORMAL, "Bro Intel::DOMAIN Loaded: %d", counters->brointel_domain_count);
            Sagan_Log(S_NORMAL, "Bro Intel::FILE_HASH Loaded: %d", counters->brointel_file_hash_count);
            Sagan_Log(S_NORMAL, "Bro Intel::URL Loaded: %d", counters->brointel_url_count);
            Sagan_Log(S_NORMAL, "Bro Intel::SOFTWARE Loaded: %d", counters->brointel_software_count);
            Sagan_Log(S_NORMAL, "Bro Intel::EMAIL Loaded: %d", counters->brointel_email_count);
            Sagan_Log(S_NORMAL, "Bro Intel::USER_NAME Loaded: %d", counters->brointel_user_name_count);
            Sagan_Log(S_NORMAL, "Bro Intel::FILE_NAME Loaded: %d", counters->brointel_file_name_count);
            Sagan_Log(S_NORMAL, "Bro Intel::CERT_HASH Loaded: %d", counters->brointel_cert_hash_count);
            Sagan_Log(S_NORMAL, "Bro Intel Duplicates Detected: %d", counters->brointel_dups);

        }


    /***************************************************************************
     * Output plugins
     ***************************************************************************/

#ifdef HAVE_LIBESMTP
    if ( config->sagan_esmtp_flag )
        {
            Sagan_Log(S_NORMAL, "");

            if ( config->min_email_priority )
                {
                    Sagan_Log(S_NORMAL, "E-mail on priority %d or higher.", config->min_email_priority);
                }

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
    Sagan_Log(S_NORMAL, "  /   \\/)	Copyright (C) 2009-2016 Quadrant Information Security, et al.");
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

    if (!daemonize )
        {
            if (!quiet)
                {

                    rc = pthread_create( &key_thread, NULL, (void *)key_handler, NULL );

                    if ( rc != 0 )
                        {
                            Remove_Lock_File();
                            Sagan_Log(S_ERROR, "[%s, line %d] Error creating key_handler thread. [error: %d]", __FILE__, __LINE__, rc);
                        }
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

    if ( config->sagan_is_file == 0 )
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

            if (( fd = fopen(config->sagan_fifo, "r" )) == NULL )
                {
                    /* try to create it */
                    if (mkfifo(config->sagan_fifo, 0700) == -1)
                        {
                          Sagan_Log(S_ERROR, "Could not create fifo %s. Abort!", config->sagan_fifo);
                        }
                    else
                        {
                          Sagan_Log(S_NORMAL, "Fifo not found, creating it (%s).", config->sagan_fifo);
                        }
                    fd = fopen(config->sagan_fifo, "r");
                    if ( fd == NULL )
                        {
                          Sagan_Log(S_ERROR, "Error opening %s. Abort!", config->sagan_fifo);
                        }
                }

            if ( config->sagan_is_file == 0 )
                {
                    Sagan_Log(S_NORMAL, "Successfully opened FIFO (%s).", config->sagan_fifo);

#if defined(F_GETPIPE_SZ) && defined(F_SETPIPE_SZ)

                    Sagan_Set_Pipe_Size(fd);

#endif

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

#if defined(F_GETPIPE_SZ) && defined(F_SETPIPE_SZ)

                                    Sagan_Set_Pipe_Size(fd);

#endif

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

                                                    if ( dnscache == NULL )
                                                        {
                                                            Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for dnscache. Abort!", __FILE__, __LINE__);
                                                        }

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

                                            pthread_mutex_lock(&SaganMalformedCounter);
                                            counters->malformed_host++;
                                            pthread_mutex_unlock(&SaganMalformedCounter);

                                            if ( debug->debugmalformed )
                                                {
                                                    Sagan_Log(S_WARN, "Sagan received a malformed 'host' (replaced with %s)", config->sagan_host);
                                                }

                                        }
                                }

                            /* We know check the rest of the values */

                            syslog_facility=strtok_r(NULL, "|", &tok);
                            if ( syslog_facility == NULL )
                                {
                                    syslog_facility = "SAGAN: FACILITY ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_facility++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'facility'");
                                        }
                                }

                            syslog_priority=strtok_r(NULL, "|", &tok);
                            if ( syslog_priority == NULL )
                                {
                                    syslog_priority = "SAGAN: PRIORITY ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_priority++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'priority'");
                                        }
                                }

                            syslog_level=strtok_r(NULL, "|", &tok);
                            if ( syslog_level == NULL )
                                {
                                    syslog_level = "SAGAN: LEVEL ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_level++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'level'");
                                        }
                                }

                            syslog_tag=strtok_r(NULL, "|", &tok);
                            if ( syslog_tag == NULL )
                                {
                                    syslog_tag = "SAGAN: TAG ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_tag++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'tag'");
                                        }
                                }

                            syslog_date=strtok_r(NULL, "|", &tok);
                            if ( syslog_date == NULL )
                                {
                                    syslog_date = "SAGAN: DATE ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_date++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'date'");
                                        }
                                }

                            syslog_time=strtok_r(NULL, "|", &tok);
                            if ( syslog_time == NULL )
                                {
                                    syslog_time = "SAGAN: TIME ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_time++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'time'");
                                        }
                                }


                            syslog_program=strtok_r(NULL, "|", &tok);
                            if ( syslog_program == NULL )
                                {
                                    syslog_program = "SAGAN: PROGRAM ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_program++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'program'");
                                        }
                                }

                            syslog_msg=strtok_r(NULL, "", &tok);		/* In case the message has | in it,  we delimit on "" */
                            if ( syslog_msg == NULL )
                                {
                                    syslog_msg = "SAGAN: MESSAGE ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_message++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(S_WARN, "Sagan received a malformed 'message' [Syslog Host: %s]", syslog_host);
                                        }

                                    /* If the message is lost,  all is lost.  Typically,  you don't lose part of the message,
                                     * it's more likely to lose all  - Champ Clark III 11/17/2011 */

                                    counters->sagan_log_drop++;

                                }


                            /* Strip any \n or \r from the syslog_msg */

                            if ( strcspn ( syslog_msg, "\n" ) < strlen(syslog_msg) )
                                {
                                    syslog_msg[strcspn ( syslog_msg, "\n" )] = '\0';
                                }

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
                                    counters->worker_thread_exhaustion++;
                                    counters->sagan_log_drop++;
                                }

                            if (debug->debugthreads)
                                {
                                    Sagan_Log(S_DEBUG, "Current \"proc_msgslot\": %d", proc_msgslot);
                                }

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
                            if ( config->sagan_is_file != 0 )
                                {
                                    Sagan_Log(S_NORMAL, "EOF reached. Waiting for threads to catch up....");
                                    Sagan_Log(S_NORMAL, "");

                                    while(proc_msgslot != 0)
                                        {
                                            Sagan_Log(S_NORMAL, "Waiting on %d threads....", proc_msgslot);
                                            sleep(1);
                                        }

                                    fclose(fd);
                                    Sagan_Statistics();
                                    Remove_Lock_File();

                                    Sagan_Log(S_NORMAL, "Exiting.");		/* DEBUG: Rejoin threads */
                                    exit(0);
                                }
                            else
                                {
                                    Sagan_Log(S_WARN, "FIFO writer closed.  Waiting for FIFO writer to restart....");
                                    fifoerr=1; 			/* Set flag so our wile(fgets) knows */
                                }
                        }
                    sleep(1);		/* So we don't eat 100% CPU */

                } /* while(fd != NULL)  */

            fclose(fd); 			/* ???? */

        } /* End of while(1) */

} /* End of main */


