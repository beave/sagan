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
//#include <pcre.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <sys/wait.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "version.h"

#include "credits.h"
#include "flexbit-mmap.h"
#include "processor.h"
#include "sagan-config.h"
#include "config-yaml.h"
#include "ignore-list.h"
#include "key.h"
#include "lockfile.h"
#include "signal-handler.h"
#include "usage.h"
#include "stats.h"
#include "ipc.h"
#include "tracking-syslog.h"
#include "parsers/parsers.h"

#include "input-pipe.h"

#ifdef HAVE_LIBFASTJSON
#include "input-json.h"
#include "message-json-map.h"
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef HAVE_LIBPCAP
#include "plog.h"
#endif

#include "processors/engine.h"
#include "rules.h"
#include "processors/blacklist.h"
#include "processors/track-clients.h"
#include "processors/perfmon.h"
#include "processors/client-stats.h"
#include "processors/zeek-intel.h"
#include "processors/stats-json.h"


#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
#endif

#define OVECCOUNT 30

/* Init */

struct _SaganCounters *counters = NULL;
struct _SaganConfig *config = NULL;
struct _SaganDebug *debug = NULL;
struct _SaganDNSCache *dnscache = NULL;


#ifdef HAVE_LIBFASTJSON
struct _Syslog_JSON_Map *Syslog_JSON_Map = NULL;
struct _JSON_Message_Map *JSON_Message_Map = NULL;
#endif

/* Already Init'ed */

struct _Rule_Struct *rulestruct;
struct _Sagan_Ignorelist *SaganIgnorelist;

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
#endif

#ifdef HAVE_LIBHIREDIS
#include <hiredis/hiredis.h>
#include "redis.h"
#endif

struct _Sagan_Pass_Syslog *SaganPassSyslog = NULL;


int proc_msgslot = 0;
int proc_running = 0;


pthread_cond_t SaganProcDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t SaganProcWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganRulesLoadedMutex=PTHREAD_MUTEX_INITIALIZER;

/* ########################################################################
 * Start of main() thread
 * ######################################################################## */

int main(int argc, char **argv)
{

    (void)SetThreadName("SaganMain");

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
        { "quiet", 	  no_argument, 		NULL, 	'Q' },
        {0, 0, 0, 0}
    };

    static const char *short_options =
        "l:f:u:F:d:c:pDhCQ";

    int option_index = 0;

    struct _Sagan_Pass_Syslog *SaganPassSyslog_LOCAL = NULL;

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
    /* Redis local variables                                                    */
    /****************************************************************************/

#ifdef HAVE_LIBHIREDIS
    char redis_reply[5];
    char redis_command[300];
#endif

    /****************************************************************************/
    /* Perfmonitor local variables                                              */
    /****************************************************************************/

    pthread_t perfmonitor_thread;
    pthread_attr_t thread_perfmonitor_attr;
    pthread_attr_init(&thread_perfmonitor_attr);
    pthread_attr_setdetachstate(&thread_perfmonitor_attr,  PTHREAD_CREATE_DETACHED);

    /****************************************************************************/
    /* JSON Stats local variables                                               */
    /****************************************************************************/

    pthread_t stats_json_thread;
    pthread_attr_t thread_stats_json_attr;
    pthread_attr_init(&thread_stats_json_attr);
    pthread_attr_setdetachstate(&thread_stats_json_attr,  PTHREAD_CREATE_DETACHED);

    /****************************************************************************/
    /* Client local variables                                              */
    /****************************************************************************/

    pthread_t client_stats_thread;
    pthread_attr_t thread_client_stats_attr;
    pthread_attr_init(&thread_client_stats_attr);
    pthread_attr_setdetachstate(&thread_client_stats_attr,  PTHREAD_CREATE_DETACHED);

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

    /* client_tracker_report_handler thread */

    pthread_t ct_report_thread;
    pthread_attr_t ct_report_thread_attr;
    pthread_attr_init(&ct_report_thread_attr);
    pthread_attr_setdetachstate(&ct_report_thread_attr,  PTHREAD_CREATE_DETACHED);

    /* Rule tracking for syslog output */;

    pthread_t tracking_thread;
    pthread_attr_t tracking_thread_attr;
    pthread_attr_init(&tracking_thread_attr);
    pthread_attr_setdetachstate(&tracking_thread_attr,  PTHREAD_CREATE_DETACHED);


    bool fifoerr = false;
    bool ignore_flag = false;

    char syslogstring[MAX_SYSLOGMSG] = { 0 };

    signed char c;
    int rc=0;

    int i;

    time_t t;
    struct tm *run;

    bool debugflag = false;

    int batch_count = 0;

    /* Allocate memory for global struct _SaganDebug */

    debug = malloc(sizeof(_SaganDebug));

    if ( debug == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for debug. Abort!", __FILE__, __LINE__);
        }

    memset(debug, 0, sizeof(_SaganDebug));

    /* Allocate memory for global struct _SaganConfig */

    config = malloc(sizeof(_SaganConfig));

    if ( config == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for config. Abort!", __FILE__, __LINE__);
        }

    memset(config, 0, sizeof(_SaganConfig));

    /* Allocate memory for global struct _SaganCounters */

    counters = malloc(sizeof(_SaganCounters));

    if ( counters == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for counters. Abort!", __FILE__, __LINE__);
        }

    memset(counters, 0, sizeof(_SaganCounters));

    /* Allocate memory for global struct _SaganDNSCache */

    dnscache = malloc(sizeof(_SaganDNSCache));

    if ( dnscache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for dnscache. Abort!", __FILE__, __LINE__);
        }

    memset(dnscache, 0, sizeof(_SaganDNSCache));


#ifdef HAVE_LIBFASTJSON

    /* Allocate memory for global Syslog_JSON_Map */

    Syslog_JSON_Map = malloc(sizeof(_Syslog_JSON_Map));

    if ( Syslog_JSON_Map == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for Syslog_JSON_Map. Abort!", __FILE__, __LINE__);
        }

    /* Allocate memory for global Syslog_Message_JSON_Map */

    JSON_Message_Map = malloc(sizeof(_JSON_Message_Map));

    if ( JSON_Message_Map == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for JSON_Message_Map. Abort!", __FILE__, __LINE__);
        }

#endif

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
            config->quiet = true;
        }

    /* Get command line arg's */

    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {

            switch(c)
                {

                case 'h':
                    Usage();
                    exit(0);
                    break;

                case 'Q':
                    config->quiet = true;
                    break;

                case 'C':
                    Credits();
                    exit(0);
                    break;

                case 'd':

                    if (Sagan_strstr(optarg, "malformed"))
                        {
                            debug->debugmalformed = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "parse_ip"))
                        {
                            debug->debugparse_ip = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "limits"))
                        {
                            debug->debuglimits = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "syslog"))
                        {
                            debug->debugsyslog = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "load"))
                        {
                            debug->debugload = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "fwsam"))
                        {
                            debug->debugfwsam = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "external"))
                        {
                            debug->debugexternal = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "threads"))
                        {
                            debug->debugthreads = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "flexbit"))
                        {
                            debug->debugflexbit = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "xbit"))
                        {
                            debug->debugxbit = true;
                            debugflag = true;
                        }


                    if (Sagan_strstr(optarg, "engine"))
                        {
                            debug->debugengine = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "brointel"))
                        {
                            debug->debugbrointel = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "ipc"))
                        {
                            debug->debugipc = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "json"))
                        {
                            debug->debugjson = true;
                            debugflag = true;
                        }

                    if (Sagan_strstr(optarg, "client-stats"))
                        {
                            debug->debugclient_stats = true;
                            debugflag = true;
                        }

#ifdef HAVE_LIBMAXMINDDB

                    if (Sagan_strstr(optarg, "geoip"))
                        {
                            debug->debuggeoip2 = true;
                            debugflag = true;
                        }
#endif

#ifdef HAVE_LIBLOGNORM
                    if (Sagan_strstr(optarg, "normalize" ))
                        {
                            debug->debugnormalize = true;
                            debugflag = true;
                        }
#endif

#ifdef HAVE_LIBESMTP
                    if (Sagan_strstr(optarg, "smtp"))
                        {
                            debug->debugesmtp = true;
                            debugflag = true;
                        }
#endif

#ifdef HAVE_LIBPCAP
                    if (Sagan_strstr(optarg, "plog"))
                        {
                            debug->debugplog = true;
                            debugflag = true;
                        }
#endif

#ifdef WITH_BLUEDOT
                    if (Sagan_strstr(optarg, "bluedot"))
                        {
                            debug->debugbluedot = true;
                            debugflag = true;
                        }
#endif

#ifdef HAVE_LIBHIREDIS
                    if (Sagan_strstr(optarg, "redis"))
                        {
                            debug->debugredis = true;
                            debugflag = true;
                        }
#endif

                    /* If option is unknown */

                    if ( debugflag == false )
                        {
                            fprintf(stderr, "Unknown debug option %s!\n", optarg);
                            exit(1);
                        }


                    break;

                case 'D':
                    config->daemonize = true;
                    break;

                case 'u':
                    config->sagan_runas=optarg;
                    break;

                case 'c':
                    Chroot(optarg);
                    break;

                case 'F':
                    config->sagan_is_file = true;
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
                    Usage();
                    exit(0);
                    break;
                }
        }

    Open_Log_File(OPEN, SAGAN_LOG);

    /* Become a daemon if requested */

    if ( config->daemonize )
        {

            Sagan_Log(NORMAL, "Becoming a daemon!");

            pid_t pid = 0;
            pid = fork();

            if ( pid == 0 )
                {

                    /* Child */

                    if ( setsid() == -1 )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed creating new session while daemonizing", __FILE__, __LINE__);
                            exit(1);
                        }

                    pid = fork();

                    if ( pid == 0 )
                        {

                            /* Grandchild, the actual daemon */

                            if ( chdir("/") == -1 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed changing directory to / after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                    exit(1);
                                }

                            /* Close and re-open stdin, stdout, and stderr, so as to
                               to release anyone waiting on them. */

                            close(0);
                            close(1);
                            close(2);

                            if ( open("/dev/null", O_RDONLY) == -1 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed reopening stdin after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_WRONLY) == -1 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed reopening stdout after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                            if ( open("/dev/null", O_RDWR) == -1 )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed reopening stderr after daemonizing [errno %d]", __FILE__, __LINE__, errno);
                                }

                        }
                    else if ( pid < 0 )
                        {

                            Sagan_Log(ERROR, "[%s, line %d] Failed second fork while daemonizing", __FILE__, __LINE__);
                            exit(1);

                        }
                    else
                        {

                            exit(0);
                        }

                }
            else if ( pid < 0 )
                {

                    Sagan_Log(ERROR, "[%s, line %d] Failed first fork while daemonizing", __FILE__, __LINE__);
                    exit(1);

                }
            else
                {

                    /* Wait for child to exit */
                    waitpid(pid, NULL, 0);
                    exit(0);
                }
        }


    /* Create the signal handlers thread _after_ the fork() so it can properly
     * handly signals - Champ Clark III - 06/13/2011 */

    rc = pthread_create( &sig_thread, NULL, (void *)Sig_Handler, NULL );

    if ( rc != 0  )
        {
            Remove_Lock_File();
            Sagan_Log(ERROR, "[%s, line %d] Error creating signal handler thread. [error: %d]", __FILE__, __LINE__, rc);
        }


#ifdef PCRE_HAVE_JIT

    /* We test if pages will support RWX before loading rules.  If it doesn't due to the OS,
       we want to disable PCRE JIT now.  This prevents confusing warnings of PCRE JIT during
       rule load */

    config->pcre_jit = true;

    if (PageSupportsRWX() == false)
        {
            Sagan_Log(WARN, "The operating system doens't allow RWX pages.  Disabling PCRE JIT.");
            config->pcre_jit = false;
        }

#endif

    pthread_mutex_lock(&SaganRulesLoadedMutex);
    (void)Load_YAML_Config(config->sagan_config);
    pthread_mutex_unlock(&SaganRulesLoadedMutex);

    (void)Sagan_Engine_Init();

    SaganPassSyslog = malloc(config->max_processor_threads * sizeof(_Sagan_Pass_Syslog));

    if ( SaganPassSyslog == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganPassSyslog. Abort!", __FILE__, __LINE__);
        }

    memset(SaganPassSyslog, 0, sizeof(struct _Sagan_Pass_Syslog));

    SaganPassSyslog_LOCAL = malloc(config->max_processor_threads * sizeof(_Sagan_Pass_Syslog));

    if ( SaganPassSyslog_LOCAL == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganPassSyslog_LOCAL. Abort!", __FILE__, __LINE__);
        }

    memset(SaganPassSyslog_LOCAL, 0, sizeof(struct _Sagan_Pass_Syslog));


    pthread_t processor_id[config->max_processor_threads];
    pthread_attr_t thread_processor_attr;
    pthread_attr_init(&thread_processor_attr);
    pthread_attr_setdetachstate(&thread_processor_attr,  PTHREAD_CREATE_DETACHED);

#ifdef HAVE_LIBHIREDIS

    /* Redis "writer" threads */

    pthread_t redis_writer_processor_id[config->redis_max_writer_threads];
    pthread_attr_t redis_writer_thread_processor_attr;
    pthread_attr_init(&redis_writer_thread_processor_attr);
    pthread_attr_setdetachstate(&redis_writer_thread_processor_attr,  PTHREAD_CREATE_DETACHED);

#endif

    Sagan_Log(NORMAL, "Configuration file %s loaded and %d rules loaded.", config->sagan_config, counters->rulecount);
    Sagan_Log(NORMAL, "There are %d rules loaded.", counters->rulecount);
    Sagan_Log(NORMAL, "%d flexbit(s) are in use.", counters->flexbit_total_counter);
    Sagan_Log(NORMAL, "%d xbit(s) are in use.", counters->xbit_total_counter);
    Sagan_Log(NORMAL, "%d dynamic rule(s) are loaded.", counters->dynamic_rule_count);

#ifdef HAVE_LIBFASTJSON

    Sagan_Log(NORMAL, "Named pipe/FIFO input type: %s", config->input_type == INPUT_PIPE ? "Pipe":"JSON");
    Sagan_Log(NORMAL, "Parse JSON in message: %s", config->parse_json_message == true ? "Enabled":"Disabled");
    Sagan_Log(NORMAL, "Parse JSON in program: %s", config->parse_json_program == true ? "Enabled":"Disabled");
    Sagan_Log(NORMAL, "Client Stats         : %s", config->client_stats_flag == true ? "Enabled":"Disabled");


#endif

    Sagan_Log(NORMAL, "Syslog batch: %d", config->max_batch);


#ifdef PCRE_HAVE_JIT

    if ( config->pcre_jit )
        {
            Sagan_Log(NORMAL, "PCRE JIT is enabled.");
        }

#endif

    Sagan_Log(NORMAL, "");
    Sagan_Log(NORMAL, "Sagan version %s is firing up on %s (cluster: %s)", VERSION, config->sagan_sensor_name, config->sagan_cluster_name);
    Sagan_Log(NORMAL, "");

#ifdef HAVE_LIBPCAP

    /* Spawn a thread to 'sniff' syslog traffic (sagan-plog.c).  This redirects syslog
       traffic to the /dev/log socket.  This needs "root" access,  so we drop priv's
       after this thread is started */

    if ( config->plog_flag )
        {

            rc = pthread_create( &pcap_thread, NULL, (void *)Plog_Handler, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating libpcap handler thread [error: %d].", __FILE__, __LINE__, rc);
                }

            sleep(1); 	/* Sleep to avoid race between main() and plog thread
		   	plog thread needs "root" rights before sagan_droppriv().
		   	In some cases main() run sagan_droppriv() before thread
		   	can complete - Champ Clark - 07/20/2011 */

        }
#endif



    CheckLockFile();

    Droppriv();              /* Become the Sagan user */

    Sagan_Log(NORMAL, "---------------------------------------------------------------------------");

    IPC_Init();

    if ( config->perfmonitor_flag )
        {

            Sagan_Perfmonitor_Open();

            rc = pthread_create( &perfmonitor_thread, NULL, (void *)Sagan_Perfmonitor_Handler, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating Perfmonitor thread [error: %d].", __FILE__, __LINE__, rc);
                }
        }

    if ( config->stats_json_flag )
        {

            Stats_JSON_Init();

            rc = pthread_create( &stats_json_thread, NULL, (void *)Stats_JSON_Handler, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating stats-json thread [error: %d].", __FILE__, __LINE__, rc);
                }
        }


    if ( config->client_stats_flag )
        {

            Client_Stats_Init();

            rc = pthread_create( &client_stats_thread, NULL, (void *)Client_Stats_Handler, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating Clients Stats  thread [error: %d].", __FILE__, __LINE__, rc);
                }
        }


    /* Open sagan alert file */

    Open_Log_File(OPEN, ALERT_LOG);

    /****************************************************************************
     * Display processor information as we load
     ****************************************************************************/

    /* Sagan_Track_Clients processor ********************************************/

    if ( config->sagan_track_clients_flag )
        {

            Track_Clients_Thread_Init();

            /* We run a thread for client_tracker_report */

            rc = pthread_create( &ct_report_thread, NULL, (void *)Track_Clients_Thread, NULL );

            if ( rc != 0 )
                {
                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating client_tracker_report_client thread. [error: %d]", __FILE__, __LINE__, rc);
                }

            if ( config->pp_sagan_track_clients )
                {
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "Client Tracking Processor: %d minute(s)", config->pp_sagan_track_clients);
                }

        }

    /* Sagan Blacklist IP processor *********************************************/

    if ( config->blacklist_flag )
        {

            Sagan_Blacklist_Init();
            Sagan_Blacklist_Load();

        }

#ifdef WITH_BLUEDOT
    if ( config->bluedot_flag )
        {

            /* Lookup Bluedot IP so we don't explode DNS :) */

            rc = DNS_Lookup( config->bluedot_host, config->bluedot_ip, sizeof(config->bluedot_ip) );

            /* Record epoch so we can determine TTL */

            config->bluedot_dns_last_lookup = atol(config->sagan_startutime);

            if ( rc != 0 )
                {
                    Sagan_Log(ERROR, "Cannot look up IP address for '%s'.  Abort!", config->bluedot_host );
                }

            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "Bluedot IP: %s", config->bluedot_ip);
            Sagan_Log(NORMAL, "Bluedot URL: http://%s/%s", config->bluedot_ip, config->bluedot_uri);
            Sagan_Log(NORMAL, "Bluedot Device ID: %s", config->bluedot_device_id);
            Sagan_Log(NORMAL, "Bluedot Categories File: %s", config->bluedot_cat);
            Sagan_Log(NORMAL, "Bluedot loaded %d categories.", counters->bluedot_cat_count);
            Sagan_Log(NORMAL, "Bluedot Cache Timeout: %d minutes.", config->bluedot_timeout  / 60);
            Sagan_Log(NORMAL, "Bluedot IP Cache Size: %" PRIu64 "", config->bluedot_ip_max_cache);
            Sagan_Log(NORMAL, "Bluedot IP Queue Size: %" PRIu64 "", config->bluedot_ip_queue);
            Sagan_Log(NORMAL, "Bluedot Hash Cache Size: %" PRIu64 "", config->bluedot_hash_max_cache);
            Sagan_Log(NORMAL, "Bluedot URL Cache Size: %" PRIu64 "", config->bluedot_url_max_cache);
            Sagan_Log(NORMAL, "Bluedot Filename Cache Size: %" PRIu64 "", config->bluedot_filename_max_cache);
            Sagan_Log(NORMAL, "Bluedot JA3 Cache Size: %" PRIu64 "", config->bluedot_ja3_max_cache);

        }

#endif


    /* Sagan Bro Intel processor *******************************************/

    if ( config->brointel_flag )
        {

            Sagan_Log(NORMAL, "");

            Sagan_BroIntel_Init();
            Sagan_BroIntel_Load_File();

            Sagan_Log(NORMAL, "Bro Intel::ADDR Loaded: %d", counters->brointel_addr_count);
            Sagan_Log(NORMAL, "Bro Intel::DOMAIN Loaded: %d", counters->brointel_domain_count);
            Sagan_Log(NORMAL, "Bro Intel::FILE_HASH Loaded: %d", counters->brointel_file_hash_count);
            Sagan_Log(NORMAL, "Bro Intel::URL Loaded: %d", counters->brointel_url_count);
            Sagan_Log(NORMAL, "Bro Intel::SOFTWARE Loaded: %d", counters->brointel_software_count);
            Sagan_Log(NORMAL, "Bro Intel::EMAIL Loaded: %d", counters->brointel_email_count);
            Sagan_Log(NORMAL, "Bro Intel::USER_NAME Loaded: %d", counters->brointel_user_name_count);
            Sagan_Log(NORMAL, "Bro Intel::FILE_NAME Loaded: %d", counters->brointel_file_name_count);
            Sagan_Log(NORMAL, "Bro Intel::CERT_HASH Loaded: %d", counters->brointel_cert_hash_count);
            Sagan_Log(NORMAL, "Bro Intel Duplicates Detected: %d", counters->brointel_dups);

        }


    /***************************************************************************
     * Output plugins
     ***************************************************************************/

#ifdef HAVE_LIBESMTP

    if ( config->sagan_esmtp_flag )
        {
            Sagan_Log(NORMAL, "");

            Sagan_Log(NORMAL, "E-Mail will be sent from: %s", config->sagan_esmtp_from);
            Sagan_Log(NORMAL, "SMTP server is set to: %s", config->sagan_esmtp_server);
        }

#endif

    /***************************************************************************
     * Non-Processor/Output option
     ***************************************************************************/

    /* What to "ignore" ********************************************************/

    if ( config->sagan_droplist_flag )
        {

            Load_Ignore_List();
            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "Loaded %d ignore/drop list item(s).", counters->droplist_count);

        }

    /***************************************************************************
     * Continue with normal startup!
     ***************************************************************************/

    Sagan_Log(NORMAL, "");
    Sagan_Log(NORMAL, " ,-._,-. 	-*> Sagan! <*-");
    Sagan_Log(NORMAL, " \\/)\"(\\/	Version %s", VERSION);
    Sagan_Log(NORMAL, "  (_o_)	Champ Clark III & The Quadrant InfoSec Team [quadrantsec.com]");
    Sagan_Log(NORMAL, "  /   \\/)	Copyright (C) 2009-2020 Quadrant Information Security, et al.");
    Sagan_Log(NORMAL, " (|| ||) 	Using PCRE version: %s", pcre_version());
    Sagan_Log(NORMAL, "  oo-oo");
    Sagan_Log(NORMAL, "");


    /* We don't want the Key_Handler() if we're in daemon mode! */

    if (!config->daemonize )
        {

            if (!config->quiet)
                {

                    rc = pthread_create( &key_thread, NULL, (void *)Key_Handler, NULL );

                    if ( rc != 0 )
                        {

                            Remove_Lock_File();
                            Sagan_Log(ERROR, "[%s, line %d] Error creating Key_Handler() thread. [error: %d]", __FILE__, __LINE__, rc);

                        }
                }
        }

#ifdef HAVE_LIBHIREDIS

    /* Right now,  Redis is only used for xbit/flexbit storage */

    if ( config->redis_flag )
        {

            Redis_Writer_Init();
            Redis_Reader_Connect();

            strlcpy(redis_command, "PING", sizeof(redis_command));

            Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

            if (!strcmp(redis_reply, "PONG"))
                {
                    Sagan_Log(NORMAL, "Got 'reader' PONG from Redis at %s:%d.", config->redis_server, config->redis_port);
                }

            Sagan_Log(NORMAL, "");

        }

#endif

#ifdef WITH_SYSLOG

    if ( config->rule_tracking_flag == true )
        {

            rc = pthread_create( &tracking_thread, NULL, (void *)RuleTracking_Syslog, NULL );

            if ( rc != 0 )
                {

                    Remove_Lock_File();
                    Sagan_Log(ERROR, "[%s, line %d] Error creating RuleTracking_Syslog() thread. [error: %d]", __FILE__, __LINE__, rc);

                }

        }
#endif

    Sagan_Log(NORMAL, "Spawning %d Processor Threads.", config->max_processor_threads);

    for (i = 0; i < config->max_processor_threads; i++)
        {

            rc = pthread_create ( &processor_id[i], &thread_processor_attr, (void *)Processor, NULL );

            if ( rc != 0 )
                {

                    Remove_Lock_File();
                    Sagan_Log(ERROR, "Could not pthread_create() for I/O processors [error: %d]", rc);

                }
        }

#ifdef HAVE_LIBHIREDIS

    if ( config->redis_flag )
        {

            Sagan_Log(NORMAL, "Spawning %d Redis Writer Threads.", config->redis_max_writer_threads);

            for (i = 0; i < config->redis_max_writer_threads; i++)
                {

                    rc = pthread_create ( &redis_writer_processor_id[i], &redis_writer_thread_processor_attr, (void *)Redis_Writer, NULL );

                    if ( rc != 0 )
                        {

                            Remove_Lock_File();
                            Sagan_Log(ERROR, "Could not pthread_create() for I/O redis writers [error: %d]", rc);

                        }
                }
        }

#endif

    Sagan_Log(NORMAL, "");

    if ( !config->sagan_is_file )
        {

            Sagan_Log(NORMAL, "Attempting to open syslog FIFO (%s).", config->sagan_fifo);

        }
    else
        {

            Sagan_Log(NORMAL, "Attempting to open syslog FILE (%s).", config->sagan_fifo);

        }



    while(true)
        {

            FILE *fd;

            if (( fd = fopen(config->sagan_fifo, "r" )) == NULL )
                {

                    if ( config->sagan_is_file == false )
                        {

                            /* try to create it */

                            Sagan_Log(NORMAL, "Fifo not found, creating it (%s).", config->sagan_fifo);

                            if (mkfifo(config->sagan_fifo, 0700) == -1)
                                {
                                    Remove_Lock_File();
                                    Sagan_Log(ERROR, "Could not create FIFO '%s'. Abort!", config->sagan_fifo);
                                }

                            fd = fopen(config->sagan_fifo, "r");

                            if ( fd == NULL )
                                {
                                    Remove_Lock_File();
                                    Sagan_Log(ERROR, "Error opening %s. Abort!", config->sagan_fifo);
                                }

                        }
                    else
                        {
                            Remove_Lock_File();
                            Sagan_Log(ERROR, "Could not open file '%s'. Abort!", config->sagan_fifo);
                        }

                }

            if ( config->sagan_is_file == false )
                {
                    Sagan_Log(NORMAL, "Successfully opened FIFO (%s).", config->sagan_fifo);

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)

                    Set_Pipe_Size(fd);

#endif

                }
            else
                {
                    Sagan_Log(NORMAL, "Successfully opened FILE (%s) and processing events.....", config->sagan_fifo);
                }

            while(fd != NULL)
                {


                    clearerr( fd );

                    while(fgets(syslogstring, MAX_SYSLOGMSG, fd) != NULL)
                        {

                            /* If the FIFO was in a error state,  let user know the FIFO writer has resumed */

                            if ( fifoerr == true )
                                {

                                    Sagan_Log(NORMAL, "FIFO writer has restarted. Processing events.");

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)

                                    Set_Pipe_Size(fd);

#endif
                                    fifoerr = false;
                                }

                            __atomic_add_fetch(&counters->events_received, 1, __ATOMIC_SEQ_CST);

                            /* Copy log line to batch/queue if we haven't reached our batch limit */

                            if ( batch_count <= config->max_batch )
                                {

                                    if (debug->debugsyslog)
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] [batch position %d] Raw log: %s",  __FILE__, __LINE__, batch_count, syslogstring);
                                        }

                                    /* Check for "drop" to save CPU from "ignore list" */

                                    if ( config->sagan_droplist_flag )
                                        {

                                            ignore_flag = false;

                                            for (i = 0; i < counters->droplist_count; i++)
                                                {

                                                    if (Sagan_strstr(syslogstring, SaganIgnorelist[i].ignore_string))
                                                        {
                                                            __atomic_add_fetch(&counters->ignore_count, 1, __ATOMIC_SEQ_CST);
                                                            ignore_flag = true;
                                                            break;

                                                        }
                                                }


                                        }

                                    /* Add to batch */

                                    if ( ignore_flag == false )
                                        {

                                            /* Copy data to _LOCAL array */

                                            strlcpy(SaganPassSyslog_LOCAL[proc_msgslot].syslog[batch_count], syslogstring, sizeof(SaganPassSyslog_LOCAL[proc_msgslot].syslog[batch_count]));

                                            batch_count++;
                                        }

                                }

                            /* Do we have enough threads? */


                            if ( proc_msgslot < config->max_processor_threads )
                                {

                                    /* Has our batch count been reached */

                                    if ( batch_count >= config->max_batch )
                                        {

                                            batch_count=0;              /* Reset batch/queue */

                                            pthread_mutex_lock(&SaganProcWorkMutex);

                                            /* Copy local thread data to global thread */

                                            for ( i = 0; i < config->max_batch; i++)
                                                {
                                                    strlcpy(SaganPassSyslog[proc_msgslot].syslog[i], SaganPassSyslog_LOCAL[proc_msgslot].syslog[i], sizeof(SaganPassSyslog[proc_msgslot].syslog[i]));
                                                }

                                            counters->events_processed = counters->events_processed + config->max_batch;

                                            proc_msgslot++;

                                            /* Send work to thread */

                                            pthread_cond_signal(&SaganProcDoWork);
                                            pthread_mutex_unlock(&SaganProcWorkMutex);
                                        }

                                }
                            else
                                {

                                    /* If there's no thread, we lose the entire batch */

                                    counters->worker_thread_exhaustion = counters->worker_thread_exhaustion + config->max_batch; ;
                                    batch_count = 0;
                                }

                        } /* while(fgets) */

                    /* fgets() has returned a error,  likely due to the FIFO writer leaving */

                    if ( fifoerr == false )
                        {

                            if ( config->sagan_is_file != 0 )
                                {
                                    Sagan_Log(NORMAL, "EOF reached. Waiting for threads to catch up....");
                                    Sagan_Log(NORMAL, "");

                                    while(proc_msgslot != 0 || proc_running != 0)
                                        {
                                            Sagan_Log(NORMAL, "Waiting on %d/%d threads....", proc_msgslot, proc_running);
                                            sleep(1);
                                        }

                                    fclose(fd);
                                    Statistics();
                                    Remove_Lock_File();

                                    Sagan_Log(NORMAL, "Exiting.");
                                    exit(0);

                                }
                            else
                                {

                                    Sagan_Log(WARN, "FIFO writer closed.  Waiting for FIFO writer to restart....");
                                    clearerr(fd);
                                    fifoerr = true; 			/* Set flag so our wile(fgets) knows */
                                }
                        }
                    sleep(1);		/* So we don't eat 100% CPU */

                } /* while(fd != NULL)  */

            fclose(fd); 			/* ???? */

        } /* End of while(1) */

} /* End of main */


