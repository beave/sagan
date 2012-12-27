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
#include "version.h"

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

#ifdef WITH_WEBSENSE
#include "processors/sagan-websense.h"
struct _Sagan_Websense_Cache *SaganWebsenseCache;
#endif

sbool daemonize=0;

struct _Sagan_Proc_Syslog *SaganProcSyslog = NULL;

int proc_msgslot=0;

pthread_cond_t SaganProcDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t SaganProcWorkMutex=PTHREAD_MUTEX_INITIALIZER;

/* ######################################################################## 
 * Start of main() thread
 * ######################################################################## */

int main(int argc, char **argv) {

const struct option long_options[] = {
        { "help",         no_argument,          NULL,   'h' },
        { "debug",        required_argument,    NULL,   'd' },
        { "daemon",       no_argument,          NULL,   'D' },
        { "user",         required_argument,    NULL,   'U' },
        { "chroot",       required_argument,    NULL,   'c' },
        { "config",       required_argument,    NULL,   'f' },
        { "log",          required_argument,    NULL,   'l' },
	{ "file",	  required_argument,    NULL,   'F' }, 
        {0, 0, 0, 0}

};

static const char *short_options =
"l:f:u:d:c:pDh";

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
/* Various local variables						    */
/****************************************************************************/

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
char *sqlout=NULL;
char *sql=NULL;
char sqltmp[MAXSQL];
#endif

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
char sysmsg[MAX_MSGSLOT][MAX_SYSLOGMSG]; 

char c;
char *tok;
int rc=0;

char *runas=RUNAS;

int i;

time_t t;
struct tm *now, *run;

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

t = time(NULL);
run=localtime(&t);
strftime(config->sagan_startutime, sizeof(config->sagan_startutime), "%s",  run);

snprintf(config->sagan_config, sizeof(config->sagan_config), "%s", CONFIG_FILE_PATH);

/* We set the config->sagan_log_filepath to the system default.  It'll be fopen'ed 
   shortly - 06/03/2011 - Champ Clark III */

snprintf(config->sagan_log_filepath, sizeof(config->sagan_log_filepath), "%s", SAGANLOG);

/* Get command line arg's */
while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) { 
   
   switch(c) {
           
	   if (c == -1) break;

           case 'h':
	   sagan_usage();
	   exit(0);
	   break;
	   
	   case 'd':

              if (strstr(optarg, "syslog")) { 
	      	 debug->debugsyslog=1;
		 debugflag=1; 
		 } 

              if (strstr(optarg, "load")) { 
	         debug->debugload=1;
		 debugflag=1; 
		 }

	      if (strstr(optarg, "fwsam")) { 
	         debug->debugfwsam=1;
		 debugflag=1;
		 } 

	      if (strstr(optarg, "external")) { 
	         debug->debugexternal=1;
		 debugflag=1; 
		 }

	      if (strstr(optarg, "threads")) {
	         debug->debugthreads=1;
		 debugflag=1; 
		 }

#ifdef HAVE_LIBLOGNORM
	      if (strstr(optarg, "normalize" )) {
	         debug->debugnormalize=1;
		 debugflag=1;
		 }
#endif
              
#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
	      if (strstr(optarg, "sql")) { 
	         debug->debugsql=1;
		 debugflag=1; 
		 }
#endif

#ifdef HAVE_LIBESMTP
	      if (strstr(optarg, "smtp")) {
	          debug->debugesmtp=1;
		  debugflag=1;
		  }
#endif

#ifdef HAVE_LIBPCAP
	      if (strstr(optarg, "plog")) { 
	         debug->debugplog=1;
		 debugflag=1;
		 }
#endif

#ifdef WITH_WEBSENSE
	      if (strstr(optarg, "websense")) {
	         debug->debugwebsense=1;
		 debugflag=1;
		 }
#endif

	      /* If option is unknown */

	      if ( debugflag == 0 )  {
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
	   sagan_chroot(runas,optarg);
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
          sagan_usage();
	  exit(0);
	  break;
  	  }
}

/* Open the sagan.log file.  Moved from sagan-config.c as it became to complex 
   06/03/2011 - Champ Clark */

if ((config->sagan_log_stream = fopen(config->sagan_log_filepath, "a")) == NULL) {
    fprintf(stderr, "[E] [%s, line %d] Cannot open %s!\n", __FILE__, __LINE__, config->sagan_log_filepath);
    exit(1);
    }


Load_Config();

#ifdef HAVE_LIBLOGNORM
sagan_liblognorm_load();
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

Sagan_Log(0, "Configuration file %s loaded and %d rules loaded.", config->sagan_config, counters->rulecount);
Sagan_Log(0, "Sagan version %s is firing up!", VERSION);

/* We go ahead and assign values to SaganSigArgs (struct sig_thread_args).  This
 * struct is always used by the sig_handler thread,  and sometimes used by the
 * plog_handler (below).  So we assign values now */

sigargs->daemonize = daemonize;

#ifdef HAVE_LIBPCAP

/* Spawn a thread to 'sniff' syslog traffic (sagan-plog.c).  This redirects syslog
   traffic to the /dev/log socket.  This needs "root" access,  so we drop priv's
   after this thread is started */

if ( config->plog_flag ) { 

if ( pthread_create( &pcap_thread, NULL, (void *)plog_handler, sigargs )) {

        Remove_Lock_File();
        Sagan_Log(1, "[%s, line %d] Error creating libpcap handler thread.", __FILE__, __LINE__);
        }

sleep(1); 	/* Sleep to avoid race between main() and plog thread 
		   plog thread needs "root" rights before sagan_droppriv().
		   In some cases main() run sagan_droppriv() before thread
		   can complete - Champ Clark - 07/20/2011 */
			
}
#endif

sagan_droppriv(runas);		/* Become the Sagan user */
Sagan_Log(0, "---------------------------------------------------------------------------");

/* Open sagan alert file */

if (( config->sagan_alert_stream = fopen(config->sagan_alert_filepath, "a" )) == NULL ) {
Remove_Lock_File();
Sagan_Log(1, "[%s, line %d] Can't open %s!", __FILE__, __LINE__, config->sagan_alert_filepath);
}

Sagan_Log(0, "Max Output Thread        : %" PRIu64 "", config->max_output_threads);
Sagan_Log(0, "Max Processor Threads    : %" PRIu64 "", config->max_processor_threads);

Sagan_Log(0, "");

/* Processor information */ 

if ( config->sagan_track_clients_flag) {
if ( config->pp_sagan_track_clients ) Sagan_Log(0, "Client Tracking Processor: %d minute(s)", config->pp_sagan_track_clients);
}

if ( config->blacklist_flag) { 

Sagan_Blacklist_Load(); 

Sagan_Log(0, "");
Sagan_Log(0, "Blacklist Processor loaded [%s]", config->blacklist_file); 
Sagan_Log(0, "Blacklist loaded %d entries", counters->blacklist_count);
Sagan_Log(0, "Blacklist Parse Depth: %d", config->blacklist_parse_depth);
}

#ifdef WITH_WEBSENSE
if ( config->websense_flag ) { 

SaganWebsenseCache = malloc(config->websense_max_cache * sizeof(struct _Sagan_Websense_Cache)); 
memset(SaganWebsenseCache, 0, sizeof(_Sagan_Websense_Cache));

config->websense_last_time = atol(config->sagan_startutime); 

Sagan_Websense_Ignore_List(); 

Sagan_Log(0, "");
Sagan_Log(0, "Websense URL: %s", config->websense_url);
Sagan_Log(0, "Websense Auth: %s", config->websense_auth);
Sagan_Log(0, "Websense Parse Depth: %d", config->websense_parse_depth);
Sagan_Log(0, "Websense Max Cache: %d", config->websense_max_cache);
Sagan_Log(0, "Websense Cache Timeout: %d minutes", config->websense_timeout  / 60); 
Sagan_Log(0, "Websense ignore list entires: %d", counters->websense_ignore_list_count); 
}
#endif

Sagan_Log(0, "");


#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
if ( config->dbtype ) { 

config->endian = checkendian();

db_connect();

get_sensor_id(); 
Sagan_Log(0, "Sensor ID            : %d", config->sensor_id);
counters->cid = get_cid() + 1; 

snprintf(sqltmp, sizeof(sqltmp), "SELECT MAX(cid) FROM event WHERE sid=%d", config->sensor_id);
sql=sqltmp;
sqlout = db_query(sql);

Sagan_Log(0, "Next CID             : %" PRIu64 "", counters->cid);

/* Check the event table and compare sensor.last_cid with event_cid.  If there's a 
 * mismatch,  we correct it  - Champ Clark 03/30/2012 */ 

if ( atol(sqlout) != counters->cid ) {
   Sagan_Log(2, "Inconsistent cid information for sid=%d.  Recovering by rolling forward to cid=%d", config->sensor_id, atol(sqlout) );
   counters->cid = atol(sqlout);
   record_last_cid(debug, config, counters);
   }

counters->last_cid = counters->cid;	/* Use to determine if a change has happened in sagan_siganl.c */
} 

#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

if ( config->sagan_unified2_flag ) { 
Sagan_Log(0, "");
Sagan_Log(0, "Unified2 file: %s", config->unified2_filepath);
Sagan_Log(0, "Unified2 limit: %dM", config->unified2_limit  / 1024 / 1024 );
Unified2InitFile( config );
}

#endif


Sagan_Log(0, "");

Sagan_Log(0, "");
Sagan_Log(0, " ,-._,-. 	-*> Sagan! <*-");
Sagan_Log(0, " \\/)\"(\\/	Version %s", VERSION);
Sagan_Log(0, "  (_o_)	Champ Clark III & The Quadrant InfoSec Team [quadrantsec.com]");
Sagan_Log(0, "  /   \\/)	Copyright (C) 2009-2012 Quadrant Information Security, et al.");
Sagan_Log(0, " (|| ||) 	Using PCRE version: %s", pcre_version());
Sagan_Log(0, "  oo-oo     Sagan is processing events.....");
Sagan_Log(0, "");

/* Become a daemon if requested */

if ( daemonize )
{
Sagan_Log(0, "Becoming a daemon!");

pid_t pid = 0;
setsid();
pid = fork();
if (pid == 0) {} else { exit(0); }
} 

/* Create the signal handlers thread _after_ the fork() so it can properly 
 * handly signals - Champ Clark III - 06/13/2011 */

if ( pthread_create( &sig_thread, NULL, (void *)Sig_Handler, sigargs )) {
        Remove_Lock_File();
        Sagan_Log(1, "[%s, line %d] Error creating signal handler thread.", __FILE__, __LINE__);
        }


/* We don't want the key_handler() if we're in daemon mode! */

if (!daemonize) { 

if (pthread_create( &key_thread, NULL, (void *)key_handler, config )) { ;
	Remove_Lock_File();
	Sagan_Log(1, "[%s, line %d] Error creating key_handler thread.", __FILE__, __LINE__);
	}

}

/* We do this after forking so init scripts can complete */

/* Check lock file _after_ thread.  If you don't it'll retreive the wrong pid
 * and incorrectly believe there is a stale lock file if --daemon */

checklockfile();

Sagan_Log(0, "Spawning %d Processors Threads.", config->max_processor_threads);

for (i = 0; i < config->max_processor_threads; i++) {

     if (  pthread_create ( &processor_id[i], &thread_processor_attr, (void *)Sagan_Processor, NULL )) { 
         Remove_Lock_File();
         Sagan_Log(1, "Could not pthread_create() for I/O processors [Error code: %d]", rc);                            
        }
     }

Sagan_Log(0, "");

if ( config->sagan_fifo_flag == 0 ) { 
Sagan_Log(0, "Attempting to open syslog FIFO (%s).", config->sagan_fifo);
} else { 
Sagan_Log(0, "Attempting to open syslog FILE (%s).", config->sagan_fifo);
}



while(1) { 

FILE *fd; 
fd = fopen(config->sagan_fifo, "r");

      if ( config->sagan_fifo_flag == 0 ) { 
      Sagan_Log(0, "Successfully opened FIFO (%s).", config->sagan_fifo);
      } else { 
      Sagan_Log(0, "Successfully opened FILE (%s) and processing events.....", config->sagan_fifo);
      }

while(fd != NULL) { 


	while(fgets(syslogstring, sizeof(syslogstring), fd) != NULL) {

	/* If the FIFO was in a error state,  let user know the FIFO writer has resumed */

	if ( fifoerr == 1 ) { 
	   Sagan_Log(0, "FIFO writer has restarted. Processing events."); 
	   fifoerr=0; 
	   }
	        

		counters->sagantotal++;
		syslog_host = strtok_r(syslogstring, "|", &tok);

		/* If we're using DNS (and we shouldn't be!),  we start DNS checks and lookups
		 * here.  We cache both good and bad lookups to not over load our DNS server(s).
		 * The only way DNS cache can be cleared is to restart Sagan */

		if (config->syslog_src_lookup ) { 
		   if ( inet_pton(AF_INET, syslog_host, &(sa.sin_addr)) == 0 ) { 	/* Is inbound a valid IP? */
		      dns_flag=0;							

		   for(i=0; i <= counters->dns_cache_count ; i++) {			/* Check cache first */
		      if (!strcmp( dnscache[i].hostname, syslog_host)) { 
		          syslog_host = dnscache[i].src_ip;
		          dns_flag=1;
		          } 
		   }

		   /* If entry was not found in cache,  look it up */

		   if ( dns_flag == 0 ) { 

		      /* Do a DNS lookup */
		      snprintf(src_dns_lookup, sizeof(src_dns_lookup), "%s", DNS_Lookup(syslog_host));
		    
		      /* Invalid lookups get the config->sagan_host value */

		      if (!strcmp(src_dns_lookup, "0" )) { 
		         snprintf(src_dns_lookup, sizeof(src_dns_lookup), "%s", config->sagan_host);
		  	 counters->dns_miss_count++; 
			 }


                    /* Add entry to DNS Cache */

                    dnscache = (_SaganDNSCache *) realloc(dnscache, (counters->dns_cache_count+1) * sizeof(_SaganDNSCache));
                    snprintf(dnscache[counters->dns_cache_count].hostname, sizeof(dnscache[counters->dns_cache_count].hostname), "%s", syslog_host);
                    snprintf(dnscache[counters->dns_cache_count].src_ip, sizeof(dnscache[counters->dns_cache_count].src_ip), "%s",  src_dns_lookup);
                    counters->dns_cache_count++; 
                    syslog_host = src_dns_lookup; 

		    }
	       }
		
	} else { 

	        /* We check to see if values from our FIFO are valid.  If we aren't doing DNS related 
		 * stuff (above),  we start basic check with the syslog_host */

                if (syslog_host == NULL || inet_pton(AF_INET, syslog_host, &(sa.sin_addr)) == 0  ) { 
                   syslog_host = config->sagan_host;
                   Sagan_Log(2, "Sagan received a malformed 'host' (replaced with %s)", config->sagan_host);
                   }
	       }
	
		/* We know check the rest of the values */

		syslog_facility=strtok_r(NULL, "|", &tok);
		if ( syslog_facility == NULL ) { 
		   syslog_facility = "SAGAN: FACILITY ERROR";
		   Sagan_Log(2, "Sagan received a malformed 'facility'");
		   }

                syslog_priority=strtok_r(NULL, "|", &tok);
		if ( syslog_priority == NULL ) { 
		   syslog_priority = "SAGAN: PRIORITY ERROR";
		   Sagan_Log(2, "Sagan received a malformed 'priority'");
		   }

                syslog_level=strtok_r(NULL, "|", &tok);
		if ( syslog_level == NULL ) { 
		   syslog_level = "SAGAN: LEVEL ERROR";
		   Sagan_Log(2, "Sagan received a malformed 'level'");
		   }

                syslog_tag=strtok_r(NULL, "|", &tok);
                if ( syslog_tag == NULL ) {
                   syslog_tag = "SAGAN: TAG ERROR";
                   Sagan_Log(2, "Sagan received a malformed 'tag'");
                   }

                syslog_date=strtok_r(NULL, "|", &tok);
                if ( syslog_date == NULL ) {
                   syslog_date = "SAGAN: DATE ERROR";
                   Sagan_Log(2, "Sagan received a malformed 'date'");
                   }

                syslog_time=strtok_r(NULL, "|", &tok);
                if ( syslog_time == NULL ) {
                   syslog_time = "SAGAN: TIME ERROR";
                   Sagan_Log(2, "Sagan received a malformed 'time'");
                   }


                syslog_program=strtok_r(NULL, "|", &tok);
                if ( syslog_program == NULL ) {
                   syslog_program = "SAGAN: PROGRAM ERROR";
                   Sagan_Log(2, "Sagan received a malformed 'program'");
		   }

		syslog_msg=strtok_r(NULL, "|", &tok);
                if ( syslog_msg == NULL ) {
                   syslog_msg = "SAGAN: MESSAGE ERROR";
                   Sagan_Log(2, "Sagan received a malformed 'message' [Syslog Host: %s]", syslog_host);


		   /* If the message is lost,  all is lost.  Typically,  you don't lose part of the message,  
		    * it's more likely to lose all  - Champ Clark III 11/17/2011 */

		   counters->sagan_log_drop++; 

                   }


               /* Strip any \n or \r from the syslog_msg */

               if ( strcspn ( syslog_msg, "\n" ) < strlen(syslog_msg) ) 
                  syslog_msg[strcspn ( syslog_msg, "\n" )] = '\0';

	       if ( proc_msgslot < config->max_processor_threads ) {

	       pthread_mutex_lock(&SaganProcWorkMutex);

	       snprintf(SaganProcSyslog[proc_msgslot].syslog_host, sizeof(SaganProcSyslog[proc_msgslot].syslog_host), "%s", syslog_host);
               snprintf(SaganProcSyslog[proc_msgslot].syslog_facility, sizeof(SaganProcSyslog[proc_msgslot].syslog_facility), "%s", syslog_facility);
               snprintf(SaganProcSyslog[proc_msgslot].syslog_priority, sizeof(SaganProcSyslog[proc_msgslot].syslog_priority), "%s", syslog_priority);
               snprintf(SaganProcSyslog[proc_msgslot].syslog_level, sizeof(SaganProcSyslog[proc_msgslot].syslog_level), "%s", syslog_level);
               snprintf(SaganProcSyslog[proc_msgslot].syslog_tag, sizeof(SaganProcSyslog[proc_msgslot].syslog_tag), "%s", syslog_tag);
               snprintf(SaganProcSyslog[proc_msgslot].syslog_date, sizeof(SaganProcSyslog[proc_msgslot].syslog_date), "%s", syslog_date);
               snprintf(SaganProcSyslog[proc_msgslot].syslog_time, sizeof(SaganProcSyslog[proc_msgslot].syslog_time), "%s", syslog_time);
               snprintf(SaganProcSyslog[proc_msgslot].syslog_program, sizeof(SaganProcSyslog[proc_msgslot].syslog_program), "%s", syslog_program);
               snprintf(SaganProcSyslog[proc_msgslot].syslog_message, sizeof(SaganProcSyslog[proc_msgslot].syslog_message), "%s", syslog_msg);

	       proc_msgslot++;

               pthread_cond_signal(&SaganProcDoWork);
               pthread_mutex_unlock(&SaganProcWorkMutex);
	       } else { 
	       Sagan_Log(2, "[%s, line %d] Out of worker threads!", __FILE__, __LINE__);
	       counters->sagan_log_drop++;
	       }

if (debug->debugthreads) Sagan_Log(0, "Current \"proc_msgslot\": %d", proc_msgslot); 
if (debug->debugsyslog) Sagan_Log(0, "%s|%s|%s|%s|%s|%s|%s|%s|%s", syslog_host, syslog_facility, syslog_priority, syslog_level, syslog_tag, syslog_date, syslog_time, syslog_program, syslog_msg);

} /* while(fgets) 

/* fgets() has returned a error,  likely due to the FIFO writer leaving */ 

if ( fifoerr == 0 ) 
   {
   Sagan_Log(0, "FIFO writer closed.  Waiting for FIFO write to restart...."); 
   fifoerr=1; 			/* Set flag so our wile(fgets) knows */ 
   sleep(1); 			/* So we don't eat 100% CPU */
   }

} /* while(fd != NULL)  */

fclose(fd); 			/* ???? */

} /* End of while(1) */

} /* End of main */


