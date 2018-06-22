/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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
#include <sys/wait.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "version.h"

#include "credits.h"
#include "xbit-mmap.h"
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
#include "parsers/parsers.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef HAVE_LIBPCAP
#include "plog.h"
#endif

#include "processors/engine.h"
#include "processors/blacklist.h"
#include "processors/track-clients.h"
#include "processors/perfmon.h"
#include "processors/bro-intel.h"

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/unified2.h"
#endif

#define OVECCOUNT 30

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganConfig *config;
struct _SaganDebug *debug;

#ifdef WITH_BLUEDOT
#include <curl/curl.h>
#include "processors/bluedot.h"
#endif

#ifdef HAVE_LIBHIREDIS
#include <hiredis/hiredis.h>
#include "redis.h"
#endif

struct _Sagan_Proc_Syslog *SaganProcSyslog = NULL;

int proc_msgslot = 0;
int proc_running = 0;

unsigned char dynamic_rule_flag = 0;
sbool reload_rules = false;

pthread_cond_t SaganProcDoWork=PTHREAD_COND_INITIALIZER;

pthread_mutex_t SaganProcWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganMalformedCounter=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganRulesLoadedMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganDynamicFlag=PTHREAD_MUTEX_INITIALIZER;

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

    char src_dns_lookup[20] = { 0 };

    sbool dns_flag = false;
    sbool fifoerr = false;

    char *syslog_host=NULL;
    char *syslog_facility=NULL;
    char *syslog_priority=NULL;
    char *syslog_level=NULL;
    char *syslog_tag=NULL;
    char *syslog_date=NULL;
    char *syslog_time=NULL;
    char *syslog_program=NULL;
    char *syslog_msg=NULL;

    char *psyslogstring = NULL;
    char syslogstring[MAX_SYSLOGMSG];

    signed char c;
    int rc=0;

    int i;

    int dynamic_line_count = 0;

    time_t t;
    struct tm *run;

    sbool debugflag = false;

    /* Allocate memory for global struct _SaganDebug */

    debug = malloc(sizeof(_SaganDebug));

    if ( debug == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for debug. Abort!", __FILE__, __LINE__);
        }

    memset(debug, 0, sizeof(_SaganDebug));

    /* Allocate memroy for global struct _SaganConfig */

    config = malloc(sizeof(_SaganConfig));

    if ( config == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for config. Abort!", __FILE__, __LINE__);
        }

    memset(config, 0, sizeof(_SaganConfig));

    struct _SaganDNSCache *dnscache;
    dnscache = malloc(sizeof(_SaganDNSCache));

    if ( dnscache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for dnscache. Abort!", __FILE__, __LINE__);
        }

    memset(dnscache, 0, sizeof(_SaganDNSCache));

    counters = malloc(sizeof(_SaganCounters));

    if ( counters == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for counters. Abort!", __FILE__, __LINE__);
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
            config->quiet = true;
        }


    /* Get command line arg's */
    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {

            switch(c)
                {

                    if (c == -1) break;

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

#ifdef HAVE_LIBMAXMINDDB

                    if (Sagan_strstr(optarg, "geoip2"))
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
    Load_YAML_Config(config->sagan_config);
    pthread_mutex_unlock(&SaganRulesLoadedMutex);

    Sagan_Engine_Init();

    SaganProcSyslog = malloc(config->max_processor_threads * sizeof(struct _Sagan_Proc_Syslog));

    if ( SaganProcSyslog == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganProcSyslog. Abort!", __FILE__, __LINE__);
        }

    memset(SaganProcSyslog, 0, sizeof(struct _Sagan_Proc_Syslog));

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
    Sagan_Log(NORMAL, "Out of %d rules, %d xbit(s) are in use.", counters->rulecount, counters->xbit_total_counter);
    Sagan_Log(NORMAL, "Out of %d rules, %d dynamic rule(s) are loaded.", counters->rulecount, counters->dynamic_rule_count);

#ifdef PCRE_HAVE_JIT

    if ( config->pcre_jit )
        {
            Sagan_Log(NORMAL, "PCRE JIT is enabled.");
        }

#endif

    Sagan_Log(NORMAL, "");
    Sagan_Log(NORMAL, "Sagan version %s is firing up on '%s'!", VERSION, config->sagan_sensor_name);
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

            curl_global_init(CURL_GLOBAL_ALL);

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
            Sagan_Log(NORMAL, "Bluedot Hash Cache Size: %" PRIu64 "", config->bluedot_hash_max_cache);
            Sagan_Log(NORMAL, "Bluedot URL Cache Size: %" PRIu64 "", config->bluedot_url_max_cache);
            Sagan_Log(NORMAL, "Bluedot Filename Cache Size: %" PRIu64 "", config->bluedot_filename_max_cache);

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

#ifdef WITH_SNORTSAM

    if ( config->sagan_fwsam_flag )
        {

            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "Snortsam output plug in enabled.");

        }

#endif

    if ( config->sagan_external_output_flag )
        {

            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "External program to be called: %s", config->sagan_external_command);

        }

    /* Unified2 ****************************************************************/

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

    if ( config->sagan_unified2_flag )
        {

            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "Unified2 file: %s", config->unified2_filepath);
            Sagan_Log(NORMAL, "Unified2 limit: %dM", config->unified2_limit  / 1024 / 1024 );
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
    Sagan_Log(NORMAL, "  /   \\/)	Copyright (C) 2009-2018 Quadrant Information Security, et al.");
    Sagan_Log(NORMAL, " (|| ||) 	Using PCRE version: %s", pcre_version());
    Sagan_Log(NORMAL, "  oo-oo     Sagan is processing events.....");
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

    /* We do this after forking so init scripts can complete */

    /* Check lock file _after_ thread.  If you don't it'll retreive the wrong pid
     * and incorrectly believe there is a stale lock file if --daemon */

    CheckLockFile();

#ifdef HAVE_LIBHIREDIS

    /* Right now,  Redis is only used for xbit storage */

    if ( config->redis_flag && config->xbit_storage == XBIT_STORAGE_REDIS )
        {

            Redis_Writer_Init();
            Redis_Reader_Connect();

            if ( config->redis_password[0] != '\0' )
                {

                    snprintf(redis_command, sizeof(redis_command), "AUTH %s", config->redis_password);
                    Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

                    if (!strcmp(redis_reply, "OK"))
                        {
                            Sagan_Log(NORMAL, "Authentication success for 'reader' to Redis server at %s:%d.", config->redis_server, config->redis_port);
                        }
                    else
                        {

                            Remove_Lock_File();
                            Sagan_Log(ERROR, "Authentication failure for 'reader' to Redis server at %s:%d. Abort!", config->redis_server, config->redis_port);
                        }
                }

            strlcpy(redis_command, "PING", sizeof(redis_command));

            Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

            if (!strcmp(redis_reply, "PONG"))
                {
                    Sagan_Log(NORMAL, "Got 'reader' PONG from Redis at %s:%d.", config->redis_server, config->redis_port);
                }

            Sagan_Log(NORMAL, "");

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

    if ( config->redis_flag && config->xbit_storage == XBIT_STORAGE_REDIS )
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
                                    Sagan_Log(ERROR, "Could not create FIFO '%s'. Abort!", config->sagan_fifo);
                                }

                            fd = fopen(config->sagan_fifo, "r");

                            if ( fd == NULL )
                                {
                                    Sagan_Log(ERROR, "Error opening %s. Abort!", config->sagan_fifo);
                                }

                        }
                    else
                        {

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


                    while(fgets(syslogstring, sizeof(syslogstring), fd) != NULL)
                        {
                            psyslogstring = syslogstring;

                            /* If the FIFO was in a error state,  let user know the FIFO writer has resumed */

                            if ( fifoerr == true )
                                {

                                    Sagan_Log(NORMAL, "FIFO writer has restarted. Processing events.");

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)

                                    Set_Pipe_Size(fd);

#endif
                                    fifoerr = false;
                                }

                            counters->sagantotal++;

                            /* If Dynamic rules are loaded,  keep track of line count */

                            if ( config->dynamic_load_flag == true )
                                {

                                    dynamic_line_count++;
                                }

                            syslog_host = psyslogstring != NULL ? strsep(&psyslogstring, "|") : NULL;

                            /* If we're using DNS (and we shouldn't be!),  we start DNS checks and lookups
                             * here.  We cache both good and bad lookups to not over load our DNS server(s).
                             * The only way DNS cache can be cleared is to restart Sagan */

                            if (config->syslog_src_lookup )
                                {

                                    if ( !Is_IP(syslog_host) )   	/* Is inbound a valid IP? */
                                        {
                                            dns_flag = false;

                                            for(i=0; i <= counters->dns_cache_count ; i++)  			/* Check cache first */
                                                {
                                                    if (!strcmp( dnscache[i].hostname, syslog_host))
                                                        {
                                                            syslog_host = dnscache[i].src_ip;
                                                            dns_flag = true;
                                                        }
                                                }

                                            /* If entry was not found in cache,  look it up */

                                            if ( dns_flag == false )
                                                {

                                                    /* Do a DNS lookup */

                                                    rc = DNS_Lookup(syslog_host, src_dns_lookup, sizeof(src_dns_lookup));

                                                    /* Invalid lookups get the config->sagan_host value */

                                                    if ( rc == -1 )
                                                        {

                                                            strlcpy(src_dns_lookup, config->sagan_host, sizeof(src_dns_lookup));
                                                            counters->dns_miss_count++;

                                                        }


                                                    /* Add entry to DNS Cache */

                                                    dnscache = (_SaganDNSCache *) realloc(dnscache, (counters->dns_cache_count+1) * sizeof(_SaganDNSCache));

                                                    if ( dnscache == NULL )
                                                        {

                                                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for dnscache. Abort!", __FILE__, __LINE__);

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

                                    if (syslog_host == NULL || !Is_IP(syslog_host) )
                                        {
                                            syslog_host = config->sagan_host;

                                            pthread_mutex_lock(&SaganMalformedCounter);
                                            counters->malformed_host++;
                                            pthread_mutex_unlock(&SaganMalformedCounter);

                                            if ( debug->debugmalformed )
                                                {
                                                    Sagan_Log(DEBUG, "Sagan received a malformed 'host': '%s' (replaced with %s)", syslog_host, config->sagan_host);
                                                }
                                        }
                                }

                            /* We now check the rest of the values */

                            syslog_facility = psyslogstring != NULL ? strsep(&psyslogstring, "|") : NULL;
                            if ( syslog_facility == NULL )
                                {

                                    syslog_facility = "SAGAN: FACILITY ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_facility++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(DEBUG, "Sagan received a malformed 'facility'");
                                        }
                                }

                            syslog_priority = psyslogstring != NULL ? strsep(&psyslogstring, "|") : NULL;
                            if ( syslog_priority == NULL )
                                {

                                    syslog_priority = "SAGAN: PRIORITY ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_priority++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(DEBUG, "Sagan received a malformed 'priority'");
                                        }
                                }

                            syslog_level = psyslogstring != NULL ? strsep(&psyslogstring, "|") : NULL;
                            if ( syslog_level == NULL )
                                {

                                    syslog_level = "SAGAN: LEVEL ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_level++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(DEBUG, "Sagan received a malformed 'level'");
                                        }
                                }

                            syslog_tag = psyslogstring != NULL ? strsep(&psyslogstring, "|") : NULL;
                            if ( syslog_tag == NULL )
                                {

                                    syslog_tag = "SAGAN: TAG ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_tag++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(DEBUG, "Sagan received a malformed 'tag'");
                                        }
                                }

                            syslog_date = psyslogstring != NULL ? strsep(&psyslogstring, "|") : NULL;
                            if ( syslog_date == NULL )
                                {

                                    syslog_date = "SAGAN: DATE ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_date++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(DEBUG, "Sagan received a malformed 'date'");
                                        }
                                }

                            syslog_time = psyslogstring != NULL ? strsep(&psyslogstring, "|") : NULL;
                            if ( syslog_time == NULL )
                                {

                                    syslog_time = "SAGAN: TIME ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_time++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(DEBUG, "Sagan received a malformed 'time'");
                                        }
                                }


                            syslog_program = psyslogstring != NULL ? strsep(&psyslogstring, "|") : NULL;
                            if ( syslog_program == NULL )
                                {

                                    syslog_program = "SAGAN: PROGRAM ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_program++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(DEBUG, "Sagan received a malformed 'program'");
                                        }
                                }
                            syslog_msg = psyslogstring != NULL ? strsep(&psyslogstring, "") : NULL; /* In case the message has | in it,  we delimit on "" */

                            if ( syslog_msg == NULL )
                                {

                                    syslog_msg = "SAGAN: MESSAGE ERROR";

                                    pthread_mutex_lock(&SaganMalformedCounter);
                                    counters->malformed_message++;
                                    pthread_mutex_unlock(&SaganMalformedCounter);

                                    if ( debug->debugmalformed )
                                        {
                                            Sagan_Log(DEBUG, "Sagan received a malformed 'message' [Syslog Host: %s]", syslog_host);
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

                                    if ( config->dynamic_load_flag == true && ( dynamic_line_count >= config->dynamic_load_sample_rate ) )
                                        {

                                            pthread_mutex_lock(&SaganDynamicFlag);
                                            dynamic_rule_flag = DYNAMIC_RULE;
                                            pthread_mutex_unlock(&SaganDynamicFlag);

                                            dynamic_line_count = 0;
                                        }


                                    /* Thread holds here if rule load is in progress */

                                    if ( config->dynamic_load_flag == true )
                                        {

                                            pthread_mutex_lock(&SaganRulesLoadedMutex);
                                            reload_rules = true;
                                            pthread_mutex_unlock(&SaganRulesLoadedMutex);

                                        }

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
                                    Sagan_Log(DEBUG, "[%s, line %d] Current \"proc_msgslot\": %d", __FILE__, __LINE__, proc_msgslot);
                                }

                            if (debug->debugsyslog)
                                {

                                    Sagan_Log(DEBUG, "[%s, line %d] **[RAW Syslog]*********************************", __FILE__, __LINE__);
                                    Sagan_Log(DEBUG, "[%s, line %d] Host: %s | Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s", __FILE__, __LINE__, syslog_host, syslog_program, syslog_facility, syslog_priority, syslog_level, syslog_tag);
                                    Sagan_Log(DEBUG, "[%s, line %d] Raw message: %s", __FILE__, __LINE__, syslog_msg);

                                }


                        } /* while(fgets) */

                    /* fgets() has returned a error,  likely due to the FIFO writer leaving */

                    /* RMEOVE LOCK */

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
                                    fifoerr = true; 			/* Set flag so our wile(fgets) knows */
                                }
                        }
                    sleep(1);		/* So we don't eat 100% CPU */

                } /* while(fd != NULL)  */

            fclose(fd); 			/* ???? */

        } /* End of while(1) */

} /* End of main */


