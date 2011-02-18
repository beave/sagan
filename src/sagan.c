/*
** Copyright (C) 2009-2011 Softwink, Inc. 
** Copyright (C) 2009-2011 Champ Clark III <champ@softwink.com>
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
 * based on 'snort like' rule sets.   Some ideas and code where ripped
 * from Barnyard. 
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

#include "sagan.h"
#include "version.h"


#ifdef HAVE_LIBLOGNORM
#include <liblognorm.h>
#include <ptree.h>
#include <lognorm.h>
#endif

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
#include "output-plugins/sagan-snort.h"
#include "output-plugins/sagan-logzilla.h"
#endif

#ifdef HAVE_LIBPRELUDE
#include <libprelude/prelude.h>
#include "output-plugins/sagan-prelude.h"
#endif


#ifdef HAVE_LIBDNET
#include "output-plugins/sagan-unified2.h"
uint64_t unified_event_id=0;
sbool sagan_unified2_flag;
char unified2_filepath[MAXPATH];
int  unified2_limit;
int  unified2_nostamp;
#endif


#define OVECCOUNT 30

FILE *alertfp;
char alertlog[MAXPATH];

struct rule_struct *rulestruct;
struct class_struct *classstruct;

int daemonize=0;
int programmode=0;
int dochroot=0;

uint64_t sigcid;		/* Used for CID passing when signal's are caught */

char sagan_hostname[50]="sagan_hostname";
char sagan_interface[50]="syslog";
char sagan_filter[50]="none";
int  sagan_detail=1;
int  sensor_id;

char saganconf[MAXPATH]=CONFIG_FILE_PATH;
char *runas=RUNAS;

int  threadextc=0;
uint64_t threadmaxextc=0;
int  dropped=0;
int  classcount=0;
int  threadid =0;

char sagan_host[17];
char sagan_port[6];
char sagan_extern[MAXPATH];
char sagan_path[MAXPATH];
sbool sagan_ext_flag;

int  sagan_exttype=0;

uint64_t threshold_total=0;
uint64_t sagantotal=0;
uint64_t saganfound=0;
uint64_t sagandrop=0;

uint64_t saganesmtpdrop=0;
uint64_t saganexternaldrop=0;
uint64_t saganlogzilladrop=0;
uint64_t sagansnortdrop=0;
uint64_t saganpreludedrop=0;

sbool debugnormalize=0;
sbool debugsyslog=0;
sbool debugload=0;
sbool debugsql=0;
sbool debugesmtp=0;

sbool plog_flag;

int rulecount=0;
int ruletotal=0;

char fifo[MAX_SYSLOGMSG]="";
int  fifoi=0;

uint64_t max_ext_threads;

/****************************************************************************/
/* Liblognorm Globals                                                       */
/****************************************************************************/

#ifdef HAVE_LIBLOGNORM
struct stat fileinfo;
struct liblognorm_struct *liblognormstruct;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;
int liblognormtoload_count;

static ln_ctx ctx;
static ee_ctx eectx;

es_str_t *str;
es_str_t *propName = NULL;

struct ee_event *lnevent = NULL;;
struct ee_field *field = NULL;
char *cstr;
#endif

/****************************************************************************/
/* Prelude framework globals                                                */
/****************************************************************************/

#ifdef HAVE_LIBPRELUDE

sbool sagan_prelude_flag;
char sagan_prelude_profile[255];
uint64_t max_prelude_threads;
uint64_t threadpreludec=0;
uint64_t threadmaxpreludec=0;
#endif

/****************************************************************************/
/*  MySQL/PostgreSQL specific global variables.  Used for Logzilla & Snort  */
/*  Database support							    */
/****************************************************************************/

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

char dbusername[MAXUSER];
char dbpassword[MAXUSER];
char dbname[MAXDBNAME];
char dbhost[MAXHOST];

int  dbtype;
int  threaddbc=0;
uint64_t  threadmaxdbc=0;
uint64_t  maxdb_threads;

char logzilla_user[MAXUSER];
char logzilla_password[MAXPASS];
char logzilla_dbname[MAXDBNAME];
char logzilla_dbhost[MAXHOST];

int  logzilla_dbtype;
int  threadlogzillac=0;
uint64_t threadmaxlogzillac=0;
uint64_t max_logzilla_threads;

#endif

/****************************************************************************/
/* libesmtp global variables.  For e-mail/SMTP support.			    */
/****************************************************************************/

#ifdef HAVE_LIBESMTP
char sagan_esmtp_from[ESMTPFROM];
char sagan_esmtp_to[ESMTPTO];
char sagan_esmtp_server[ESMTPSERVER];
sbool sagan_esmtp_flag;

uint64_t  max_email_threads;
int  min_email_priority=0;
uint64_t  threadmaxemailc=0;
int  threademailc=0;

#endif 

/* Command line options */

const struct option long_options[] = {
	{ "help",         no_argument,          NULL,   'h' },
	{ "debug", 	  required_argument,	NULL, 	'd' },
	{ "daemon", 	  no_argument,		NULL,	'D' },
	{ "program", 	  no_argument,		NULL, 	'p' },
	{ "user",	  required_argument,	NULL,	'U' },
	{ "chroot", 	  no_argument, 		NULL, 	'c' },
	{ "config",	  required_argument, 	NULL, 	'f' },
	{0, 0, 0, 0}

};

static const char *short_options =
"fUd:pDhc";

int option_index = 0;

/* ######################################################################## */
/* Start of main() thread!
 * ######################################################################## */

int main(int argc, char **argv) {

sbool endianchk;

/****************************************************************************/
/* MySQL / PostgreSQL (snort/logzilla) local variables			    */
/****************************************************************************/

struct Sagan_Event *SaganEvent = NULL;
SaganEvent = malloc(MAX_THREADS * sizeof(struct Sagan_Event));

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

uint64_t cid = 0;

pthread_t threaddb_id[MAX_THREADS];
pthread_attr_t thread_db_attr;

pthread_attr_init(&thread_db_attr);
pthread_attr_setdetachstate(&thread_db_attr,  PTHREAD_CREATE_DETACHED);

pthread_t threadlogzilla_id[MAX_THREADS];
pthread_attr_t thread_logzilla_attr;

pthread_attr_init(&thread_logzilla_attr);
pthread_attr_setdetachstate(&thread_logzilla_attr,  PTHREAD_CREATE_DETACHED);

endianchk = checkendian();	// Needed for Snort output
#endif

/****************************************************************************/
/* Prelude support                                                          */
/****************************************************************************/

#ifdef HAVE_LIBPRELUDE
pthread_t threadprelude_id[MAX_THREADS];
pthread_attr_t thread_prelude_attr;
pthread_attr_init(&thread_prelude_attr);
pthread_attr_setdetachstate(&thread_prelude_attr,  PTHREAD_CREATE_DETACHED);
#endif

/****************************************************************************/
/* libesmtp (SMTP/e-mail) local variables				    */
/****************************************************************************/

#ifdef HAVE_LIBESMTP
pthread_t threademail_id[MAX_THREADS];
pthread_attr_t thread_email_attr;
pthread_attr_init(&thread_email_attr);
pthread_attr_setdetachstate(&thread_email_attr,  PTHREAD_CREATE_DETACHED);
#endif

/****************************************************************************/
/* libpcap/PLOG (syslog sniffer) local variables                                 */
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

/* External thread support */

pthread_t threadext_id[MAX_THREADS];
pthread_attr_t thread_ext_attr;
pthread_attr_init(&thread_ext_attr);
pthread_attr_setdetachstate(&thread_ext_attr,  PTHREAD_CREATE_DETACHED);

sbool fifoerr=0;

char *ip_src = NULL;
char *ip_dst = NULL;

char ip_srctmp[MAX_MSGSLOT][MAXIP];
char ip_dsttmp[MAX_MSGSLOT][MAXIP];

char *username = NULL;
char *uid = NULL;
char s_msg[1024];
char s_msgtmp[MAX_MSGSLOT][1024];

int  src_port;
int  dst_port;

int src_porttmp[MAX_MSGSLOT];
int dst_porttmp[MAX_MSGSLOT];

int  thresh_count_by_src=0;
int  thresh_count_by_dst=0;
sbool thresh_flag=0;
sbool thresh_log_flag=0;
char  timet[20];

struct thresh_by_src *threshbysrc = NULL;
struct thresh_by_dst *threshbydst = NULL;

uint64_t thresh_oldtime_src;

char fip[MAXIP];

char *syslog_host=NULL;
char  syslog_hosttmp[MAX_MSGSLOT][MAXHOST];

char *syslog_facility=NULL;
char syslog_facilitytmp[MAX_MSGSLOT][MAXFACILITY];

char *syslog_priority=NULL;
//char syslog_prioritytmp[MAXPRIORITY];

char *syslog_level=NULL;
char syslog_leveltmp[MAX_MSGSLOT][MAXLEVEL];

char *syslog_tag=NULL;
char syslog_tagtmp[MAX_MSGSLOT][MAXTAG];

char *syslog_date=NULL;
char syslog_datetmp[MAX_MSGSLOT][MAXDATE];

char *syslog_time=NULL;
char syslog_timetmp[MAX_MSGSLOT][MAXTIME];

char *syslog_program=NULL;
char syslog_programtmp[MAX_MSGSLOT][MAXPROGRAM];

char *syslog_msg=NULL;
char syslog_msg_origtmp[MAX_SYSLOGMSG];

int rc=0;

int ovector[OVECCOUNT];

char syslogstring[MAX_SYSLOGMSG];
char sysmsg[MAX_MSGSLOT][MAX_SYSLOGMSG]; 
int  msgslot=0;
char syslogtmp[2];
char c;

char *ptmp;
char *tok;
char *tok2;

/* For the ruleset */

char *content;
char *program;
char *facility;
char *syspri;
char *level;
char *tag;
char tmpbuf[128];
char ipbuf_src[128];
char ipbuf_dst[128];

char *syslog_msg_case;
char *s_content_case;

int i;
int fd=0;
int b;
int z;
int match=0;
int pcrematch=0;

time_t t;
struct tm *now;

/* Get command line arg's */
while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) { 
   
   switch(c) {
           
	   if (c == -1) break;

           case 'h':
	   sagan_usage();
	   exit(0);
	   break;
	   
	   case 'd':
	      
	      if (strstr(optarg, "normalize" )) { 
	         sagan_log(0, "Sagan liblognorn 'normalizing' debugging enabled.");
	         debugnormalize=1;
		 }
              
	      if (strstr(optarg, "syslog")) { 
	         sagan_log(0, "Sagan sylog debugging enabled.");
		 debugsyslog=1;
		 }

	      if (strstr(optarg, "load")) { 
	         sagan_log(0, "Sagan rules/config load time debugging enabled.");
		 debugload=1;
		 }
	      
	      if (strstr(optarg, "sql")) { 
	         sagan_log(0, "Sagan SQL debugging is enabled.");
		 debugsql=1;
		 }

	      if (strstr(optarg, "smtp")) { 
	         sagan_log(0, "Sagan SMTP (libesmtp) debugging is enabled.");
		 debugesmtp=1;
		 }

	   break;
          
	   case 'D':
	   daemonize=1;
	   break;

	   case 'U':
	   runas=optarg;
	   break;

	   case 'p':
	   programmode=1;
	   break;

	   case 'c':
	   dochroot=1;
	   break;

	   case 'f':
	   strncpy(saganconf,optarg,sizeof(saganconf) - 1);
	   saganconf[sizeof(saganconf)-1] = '\0';
	   break;

	  default:
          fprintf(stderr, "Invalid argument! See below for command line switches.\n");
          sagan_usage();
	  exit(0);
	  break;
  	  }
}

/* create the signal handling thread */

sig_thread_args[0].daemonize = daemonize;

load_config();

/* Load/init liblognorm definitions.  I tried to move this into a subroutine,
 * but that ended up causing segfaults on ln_normalize() or causing 
 * liblognorm not to function correctly (not parsing fields).  Make reloading
 * a SIGHUP a issue as well.
 * 12/17/2010 - Champ
 */

#ifdef HAVE_LIBLOGNORM
if((ctx = ln_initCtx()) == NULL) sagan_log(1, "[%s, line %d] Cannot initialize liblognorm context.", __FILE__, __LINE__);
if((eectx = ee_initCtx()) == NULL) sagan_log(1, "[%s, line %d] Cannot initialize libee context.", __FILE__, __LINE__);

ln_setEECtx(ctx, eectx);

for (i=0; i < liblognormtoload_count; i++) { 
sagan_log(0, "Loading %s for normalization.", liblognormtoloadstruct[i].filepath);
if (stat(liblognormtoloadstruct[i].filepath, &fileinfo)) sagan_log(1, "%s was not fonnd.", liblognormtoloadstruct[i].filepath);
ln_loadSamples(ctx, liblognormtoloadstruct[i].filepath);
}
#endif

sagan_log(0, "Configuration file %s loaded and %d rules loaded.", saganconf, rulecount);
sagan_log(0, "Sagan version %s is firing up!", VERSION);

#ifdef HAVE_LIBPCAP

/* Spawn a thread to 'sniff' syslog traffic (sagan-plog.c).  This redirects syslog
 * traffic to the /dev/log socket */

if ( plog_flag ) { 

if ( pthread_create( &pcap_thread, NULL, (void *)plog_handler, NULL)) {
        removelockfile();
        sagan_log(1, "[%s, line %d] Error creating libpcap handler thread.", __FILE__, __LINE__);
        }
}
#endif

droppriv(runas, fifo);		/* Become the Sagan user */
sagan_log(0, "---------------------------------------------------------------------------");

/* Create signal handler thread */ 

if (daemonize == 0) { 
if ( pthread_create( &sig_thread, NULL, (void *)sig_handler, &sig_thread_args )) {
        removelockfile();
        sagan_log(1, "[%s, line %d] Error creating signal handler thread.", __FILE__, __LINE__);
        }
}

/* Open sagan alert file */

if (( alertfp = fopen(alertlog, "a" )) == NULL ) {
removelockfile();
sagan_log(1, "[%s, line %d] Can't open %s!", __FILE__, __LINE__, alertlog);
}

if ( sagan_ext_flag ) sagan_log(0, "Max external threads : %d", max_ext_threads);

#ifdef HAVE_LIBESMTP
if ( sagan_esmtp_flag ) sagan_log(0, "Max SMTP threads     : %d", max_email_threads);
#endif

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
if ( logzilla_dbtype ) { 
sagan_log(0, "Max Logzilla threads : %d", max_logzilla_threads);
logzilla_db_connect();
}
#endif 

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

sig_thread_args[0].daemonize = daemonize;

if ( dbtype ) { 

sagan_log(0, "Max database threads : %d", maxdb_threads);

db_connect();
get_sensor_id( sagan_hostname, sagan_interface, sagan_filter, sagan_detail, dbtype);
sagan_log(0, "Sensor ID            : %d", sensor_id);
cid = get_cid( sensor_id, dbtype );
cid++;
sigcid=cid;
sagan_log(0, "Next CID             : %" PRIu64 "", cid);

}
#endif

#ifdef HAVE_LIBPRELUDE

if ( sagan_prelude_flag ) {

sagan_log(0, "Prelude profile: %s", sagan_prelude_profile);
sagan_log(0, "Max Prelude threads: %d", max_prelude_threads);
sagan_log(0, "");  /* libprelude dumps some information.  This is to make it pretty */

PreludeInit();
}

#endif

#ifdef HAVE_LIBDNET

Unified2Config *config = (Unified2Config *)SaganAlloc(sizeof(Unified2Config));

if ( sagan_unified2_flag ) { 

//Unified2Config *config = (Unified2Config *)SaganAlloc(sizeof(Unified2Config));
snprintf(config->filepath, sizeof(config->filepath), "%s", unified2_filepath);

config->limit = unified2_limit * 1024; 	//  Meg not bytes. :)
config->nostamp = 0;

sagan_log(0, "");
sagan_log(0, "Unified2 file: %s", config->filepath);
sagan_log(0, "Unified2 limit: %dM", unified2_limit );
Unified2InitFile( config );

}

#endif


sagan_log(0, "");

if ( fifoi == 0 ) { 
   if ( programmode == 0 ) sagan_log(0, "No FIFO option found,  assuming syslog-ng 'program' mode.");
   } else { 
   sagan_log(0, "Opening syslog FIFO (%s)", fifo);
   fd = open(fifo, O_RDONLY); 
   }


sagan_log(0, "");
sagan_log(0, " ,-._,-. 	-*> Sagan! <*-");
sagan_log(0, " \\/)\"(\\/	Version %s", VERSION);
sagan_log(0, "  (_o_)  	By Champ Clark III & The Softwink Team: http://www.softwink.com");
sagan_log(0, "  /   \\/)	Copyright (C) 2009-2011 Softwink, Inc., et al.");
sagan_log(0, " (|| ||) 	Using PCRE version: %s", pcre_version());
sagan_log(0, "  oo-oo     Sagan is processing events.....");
sagan_log(0, "");

/* Become a daemon if requested */

if (daemonize)
{

/* Unblock signals so the daemon can catch them */

sigfillset(&signal_set);

pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL );

signal (SIGHUP,  &sig_handler_daemon );
signal (SIGINT,  &sig_handler_daemon );
signal (SIGQUIT, &sig_handler_daemon );
signal (SIGTERM, &sig_handler_daemon );
signal (SIGABRT, &sig_handler_daemon );
signal (SIGSEGV, &sig_handler_daemon );
signal (SIGUSR1, &sig_handler_daemon );

sagan_log(0, "Becoming a daemon!");

pid_t pid = 0;
setsid();
pid = fork();
if (pid == 0) {} else { exit(0); }
} 

/* We don't want the key_handler() if we're in program/daemon mode! */

if (!daemonize && !programmode) { 

if (pthread_create( &key_thread, NULL, (void *)key_handler, NULL )) { ;
	removelockfile();
	sagan_log(1, "[%s, line %d] Error creating key_handler thread.", __FILE__, __LINE__);
	}

}


/* Check lock file _after_ thread.  If you don't it'll retreive the wrong pid
 * and incorrectly believe there is a stale lock file if --daemon */

checklockfile();

while(1) { 

		if ( fifoi == 1 ) { 

                if(fd < 0) {
		        removelockfile();
			sagan_log(1, "[%s, line %d] Error opening in FIFO! %s (Errno: %d)", __FILE__, __LINE__, fifo, errno);
               }

                i = read(fd, &c, 1);
                
		if(i < 0) {
  	               removelockfile();
                       sagan_log(1, "[%s, line %d] Error reading FIFO! %s (Errno: %d)", __FILE__, __LINE__, fifo, errno);
                        }

		/* Error on reading (FIFO writer left) and we have no 
		 * previous error state. */

		if (i == 0 && fifoerr == 0 ) { 
		   sagan_log(0, "FIFO closed (writer exited). Will start processing when writer resumes.");
		   fifoerr=1;
		   }

		/* If previous state was error,  now we see data,
		 * then the write is back online. */

		if ( fifoerr == 1 && i == 1 )  { 
		   sagan_log(0,"FIFO writer detected, resuming...");
		   fifoerr=0;  /* Rest error state */
		   }

		/* FIFO will return null and eat CPU.  We sleep to avoid
		 * this until the FIFO writer comes back online */

		if ( fifoerr == 1 ) sleep(1);  

                snprintf(syslogtmp, sizeof(syslogtmp), "%c", c);
                strncat(syslogstring, syslogtmp, 1); 

		} else { 


		if (!fgets(syslogstring, sizeof(syslogstring), stdin)) { 
		   sagan_log(0, "Dropped input in 'program' mode!");
		}
		}

		if ( c == '\n' || c == '\r' || fifoi == 0  ) 
                {

		sagantotal++;

		/* We have to check for values be "NULL" in the event that
		 * the program generating the message did so incorrectly
		 * *cough* Asterisk *cough*.  So we do a little checking 
		 * here.  If we 'see' a bad valid,  we attempt to correct 
		 * it */

		/* If fifoerr is set,  we've likely lost our FIFO writer. 
		 * If that's the case,  don't report because it's useless
		 * information & will fill our logs */

		syslog_host = strtok_r(syslogstring, "|", &tok);
		
		if (syslog_host == NULL ) { 
		   syslog_host = "SAGAN: HOST ERROR"; 
		   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'host'");
		   }
		
		syslog_facility=strtok_r(NULL, "|", &tok);
		if ( syslog_facility == NULL ) { 
		   syslog_facility = "SAGAN: FACILITY ERROR";
		   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'facility'");
		   }

                syslog_priority=strtok_r(NULL, "|", &tok);
		if ( syslog_priority == NULL ) { 
		   syslog_priority = "SAGAN: PRIORITY ERROR";
		   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'priority'");
		   }

                syslog_level=strtok_r(NULL, "|", &tok);
		if ( syslog_level == NULL ) { 
		   syslog_level = "SAGAN: LEVEL ERROR";
		   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'priority'");
		   }

                syslog_tag=strtok_r(NULL, "|", &tok);
                if ( syslog_tag == NULL ) {
                   syslog_tag = "SAGAN: TAG ERROR";
                   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'tag'");
                   }

                syslog_date=strtok_r(NULL, "|", &tok);
                if ( syslog_date == NULL ) {
                   syslog_date = "SAGAN: DATE ERROR";
                   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'date'");
                   }

                syslog_time=strtok_r(NULL, "|", &tok);
                if ( syslog_time == NULL ) {
                   syslog_time = "SAGAN: TIME ERROR";
                   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'time'");
                   }

                syslog_program=strtok_r(NULL, "|", &tok);
                if ( syslog_program == NULL ) {
                   syslog_program = "SAGAN: PROGRAM ERROR";
                   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'program'");
                   } else {
                   syslog_msg=syslog_program + strlen(syslog_program) + 1;
                   }

                if ( syslog_msg == NULL ) {
                   syslog_msg = "SAGAN: MESSAGE ERROR";
                   if ( !fifoerr ) sagan_log(0, "Sagan received a malformed 'message'");
                   }


if (debugsyslog) sagan_log(0, "Host:%s|Facility:%s|Pri:%s|Level:%s|Tag:%s|Date:%s|Time:%s|Prgm:%s|Msg:%s", syslog_host, syslog_facility, syslog_priority, syslog_level, syslog_tag, syslog_date, syslog_time, syslog_program, syslog_msg);

   syslog_msg[strcspn ( syslog_msg, "\n" )] = '\0';
   syslog_msg[strcspn ( syslog_msg, "\r" )] = '\0';

		/* Search for matches */

		/* First we search for 'program' and such.   This way,  we don't waste CPU
		 * time with pcre/content.  */

		for(b=0;b<rulecount;b++) {

                match = 0; program=""; facility=""; syspri=""; level=""; tag=""; content="";

                if ( strcmp(rulestruct[b].s_program, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_program);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                       if (!strcmp(ptmp, syslog_program)) match=0;
                       ptmp = strtok_r(NULL, "|", &tok2);
                       }
                }

                if ( strcmp(rulestruct[b].s_facility, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_facility);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                      if (!strcmp(ptmp, syslog_facility)) match=0;
                      ptmp = strtok_r(NULL, "|", &tok2);
                      }
                }

                if ( strcmp(rulestruct[b].s_syspri, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_syspri);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                      if (!strcmp(ptmp, syslog_priority)) match=0;
                      ptmp = strtok_r(NULL, "|", &tok2);
                      }
                  }

                if ( strcmp(rulestruct[b].s_level, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_level);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                      if (!strcmp(ptmp, syslog_level)) match=0;
                       ptmp = strtok_r(NULL, "|", &tok2);
                       }
                   }

                if ( strcmp(rulestruct[b].s_tag, "" )) {
                   snprintf(tmpbuf, sizeof(tmpbuf), "%s", rulestruct[b].s_tag);
                   ptmp = strtok_r(tmpbuf, "|", &tok2);
                   match=1;
                   while ( ptmp != NULL ) {
                      if (!strcmp(ptmp, syslog_tag)) match=0;
                      ptmp = strtok_r(NULL, "|", &tok2);
                      }
                }

		/* If there has been a match above,  or NULL on all,  then we continue with 
		 * PCRE/content search */

		/* Search via strstr (content:) */

		if ( match == 0 ) { 

		if ( rulestruct[b].content_count != 0 ) { 

		for(z=0; z<rulestruct[b].content_count; z++) {

		   /* If case insensitive */
		   if ( rulestruct[b].s_nocase == 1 ) {
		      snprintf(syslog_msg_origtmp,  sizeof(syslog_msg_origtmp), "%s", syslog_msg);
		      syslog_msg_case=syslog_msg_origtmp;
		      s_content_case=rulestruct[b].s_content[z];
		      toupperc(syslog_msg_case);
		      toupperc(s_content_case); 
		      if (strstr(syslog_msg_case, s_content_case )) pcrematch++;   // rc=1;
		      } else { 

		   /* If case sensitive */
		   if (strstr(syslog_msg, rulestruct[b].s_content[z] )) pcrematch++;  // rc=1;
		   }
		  }
		 }
	      
	       
	       	/* Search via PCRE */

		if ( rulestruct[b].pcre_count != 0 ) { 

		   for(z=0; z<rulestruct[b].pcre_count; z++) {
		
		   rc = pcre_exec( rulestruct[b].re_pcre[z], rulestruct[b].pcre_extra[z], syslog_msg, (int)strlen(syslog_msg), 0, 0, ovector, OVECCOUNT);

                   }  /* End of pcre if */

                if ( rc == 1 ) {
                   pcrematch++;
                   }
                }
		
		} /* End of content: & pcre */
	
		/* if you got match */

		if ( pcrematch != 0 && pcrematch == rulestruct[b].pcre_count + rulestruct[b].content_count )
		   {
		
		   if ( match == 0 ) { 

		   saganfound++;

		   ip_src=NULL;
		   ip_dst=NULL;
		   dst_port=0;
		   src_port=0;
		   
		   username=NULL;
		   uid=NULL;

#ifdef HAVE_LIBLOGNORM
		   if ( rulestruct[b].normalize == 1 )  
		      {
		      str = es_newStrFromCStr(syslog_msg, strlen(syslog_msg ));
		      ln_normalize(ctx, str, &lnevent);
                	if(lnevent != NULL) {
                        es_emptyStr(str);
                        ee_fmtEventToRFC5424(lnevent, &str);
                        cstr = es_str2cstr(str, NULL);
			
			if ( debugnormalize ) sagan_log(0, "Normalize output: %s", cstr);

			propName = es_newStrFromBuf("src-ip", 6);
			if((field = ee_getEventField(lnevent, propName)) != NULL) {
			   str = ee_getFieldValueAsStr(field, 0);
			   ip_src = es_str2cstr(str, NULL);
			   }

			propName = es_newStrFromBuf("dst-ip", 6);
		        if((field = ee_getEventField(lnevent, propName)) != NULL) {
			   str = ee_getFieldValueAsStr(field, 0);
			   ip_dst = es_str2cstr(str, NULL);
			   }

			propName = es_newStrFromBuf("src-port", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
			   cstr = es_str2cstr(str, NULL);
			   src_port = atoi(cstr);
                           }

                        propName = es_newStrFromBuf("dst-port", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           cstr = es_str2cstr(str, NULL);
			   dst_port = atoi(cstr);
                           }

                        propName = es_newStrFromBuf("username", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           username = es_str2cstr(str, NULL);
			   }

                        propName = es_newStrFromBuf("uid", 3);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           uid = es_str2cstr(str, NULL);
                           }

                        propName = es_newStrFromBuf("src-host", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
			   snprintf(ipbuf_src, sizeof(ipbuf_src), "%s", dns_lookup(es_str2cstr(str, NULL)));
			   ip_src=ipbuf_src;
                           }

                       propName = es_newStrFromBuf("dst-host", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
			   snprintf(ipbuf_dst, sizeof(ipbuf_dst), "%s", dns_lookup(es_str2cstr(str, NULL)));
			   ip_dst=ipbuf_dst;

                           }

                        free(cstr);
                        ee_deleteEvent(lnevent);
                        lnevent = NULL;
                	}

}
#endif

/* Normalization always over rides parse_ip/parse_port */ 

if ( rulestruct[b].normalize == 0 ) {

	/* parse_ip && parse_port - Simple means of parsing */

 if ( rulestruct[b].s_find_ip == 1 ) {

   snprintf(fip, sizeof(fip), "%s", parse_ip_simple(syslog_msg));

   if (strcmp(fip,"0")) {
      ip_src = fip; ip_dst = syslog_host;
       } else {
      ip_src = syslog_host; ip_dst = sagan_host;
      }
        } else {
      ip_src = syslog_host; ip_dst = sagan_host;
 }

if ( rulestruct[b].s_find_port == 1 ) {
   src_port = parse_port_simple(syslog_msg);
    } else {
   src_port = atoi(sagan_port);
   }
}

if ( ip_src == NULL ) ip_src=syslog_host;
if ( ip_dst == NULL ) ip_dst=syslog_host;

if ( src_port == 0 ) src_port=atoi(sagan_port);
if ( dst_port == 0 ) dst_port=rulestruct[b].dst_port;  

snprintf(s_msg, sizeof(s_msg), "%s", rulestruct[b].s_msg);

if (username != NULL ) {
    snprintf(tmpbuf, sizeof(tmpbuf), " [%s]", username);
    strlcat(s_msg, tmpbuf, sizeof(s_msg));
    }

if (uid != NULL ) { 
   snprintf(tmpbuf, sizeof(tmpbuf), " [uid: %s]", uid);
   strlcat(s_msg, tmpbuf, sizeof(s_msg));
   }

/* We don't want 127.0.0.1,  so remap it to something more useful */

if (!strcmp(ip_src, "127.0.0.1" )) ip_src=sagan_host;
if (!strcmp(ip_dst, "127.0.0.1" )) ip_dst=sagan_host;


thresh_log_flag = 0;

/*********************************************************/
/* Thresh holding                                        */
/*********************************************************/

if ( rulestruct[b].threshold_type != 0 ) { 

      t = time(NULL);
      now=localtime(&t);
      strftime(timet, sizeof(timet), "%s",  now);

      /* Thresholding by source IP address */
		      
      if ( rulestruct[b].threshold_src_or_dst == 1 ) { 
         thresh_flag = 0;
	
	 /* Check array for matching src / sid */

	 for (i = 0; i < thresh_count_by_src; i++ ) { 
	     if (!strcmp( threshbysrc[i].ipsrc, ip_src ) && !strcmp(threshbysrc[i].sid, rulestruct[b].s_sid )) { 
	        thresh_flag=1;
		threshbysrc[i].count++;
		thresh_oldtime_src = atol(timet) - threshbysrc[i].utime;
		threshbysrc[i].utime = atol(timet);
		if ( thresh_oldtime_src > rulestruct[b].threshold_seconds ) {
		   threshbysrc[i].count=1;
		   threshbysrc[i].utime = atol(timet);
		   thresh_log_flag=0;
		   }

		if ( rulestruct[b].threshold_count < threshbysrc[i].count ) 
			{ 
			thresh_log_flag = 1;
			sagan_log(0, "Threshold SID %s by source IP address. [%s]", threshbysrc[i].sid, ip_src);
			threshold_total++;
			}
  			
	     }
	 }
	
	 /* If not found,  add it to the array */
	
	 if ( thresh_flag == 0 ) { 
	    threshbysrc = (thresh_by_src *) realloc(threshbysrc, (thresh_count_by_src+1) * sizeof(thresh_by_src));
            snprintf(threshbysrc[thresh_count_by_src].ipsrc, sizeof(threshbysrc[thresh_count_by_src].ipsrc), "%s", ip_src);
	    snprintf(threshbysrc[thresh_count_by_src].sid, sizeof(threshbysrc[thresh_count_by_src].sid), "%s", rulestruct[b].s_sid );
	    threshbysrc[thresh_count_by_src].count = 1;
	    threshbysrc[thresh_count_by_src].utime = atol(timet);
	    thresh_count_by_src++;
	    }
	 }

      /* Thresholding by destination IP address */

	if ( rulestruct[b].threshold_src_or_dst == 2 ) {
            thresh_flag = 0;
       
	/* Check array for matching src / sid */

	for (i = 0; i < thresh_count_by_dst; i++ ) {
		if (!strcmp( threshbydst[i].ipdst, ip_dst ) && !strcmp(threshbydst[i].sid, rulestruct[b].s_sid )) {
                   thresh_flag=1;
                   threshbydst[i].count++;
                   thresh_oldtime_src = atol(timet) - threshbydst[i].utime;
                   threshbydst[i].utime = atol(timet);
                      if ( thresh_oldtime_src > rulestruct[b].threshold_seconds ) {
                         threshbydst[i].count=1;
                         threshbydst[i].utime = atol(timet);
                         thresh_log_flag=0;
                         }

	if ( rulestruct[b].threshold_count < threshbydst[i].count ) {
	   thresh_log_flag = 1;
	   sagan_log(0, "Threshold SID %s by source IP address. [%s]", threshbysrc[i].sid, ip_dst);
	   threshold_total++;
	   }
         }
       }

	/* If not found,  add it to the array */

	if ( thresh_flag == 0 ) {
           threshbydst = (thresh_by_dst *) realloc(threshbydst, (thresh_count_by_dst+1) * sizeof(thresh_by_dst));
           snprintf(threshbydst[thresh_count_by_dst].ipdst, sizeof(threshbydst[thresh_count_by_dst].ipdst), "%s", ip_dst);
           snprintf(threshbydst[thresh_count_by_dst].sid, sizeof(threshbydst[thresh_count_by_dst].sid), "%s", rulestruct[b].s_sid );
           threshbydst[thresh_count_by_dst].count = 1;
           threshbydst[thresh_count_by_dst].utime = atol(timet);
           thresh_count_by_dst++;
           }
        }
}  /* End of thresholding */

/****************************************************************************/
/* Populate the SaganEvent array with the information needed.  This info    */
/* will be passed to the threads.  No need to populate it _if_ we're in a   */
/* threshold state.                                                         */
/****************************************************************************/

if ( thresh_log_flag == 0 ) { 

threadid++;
if ( threadid >= MAX_THREADS ) threadid=0;

msgslot++;
if ( msgslot >= MAX_MSGSLOT ) msgslot=0;

/* We can't use the pointers from our syslog data.  If two (or more) event's
 * fire at the same time,  the two alerts will have corrupted information 
 * (due to threading).   So we populate the SaganEvent[threadid] with the
 * var[msgslot] information. - Champ Clark 02/02/2011
 */

snprintf(sysmsg[msgslot], sizeof(sysmsg[msgslot]), "%s", syslog_msg);
snprintf(syslog_timetmp[msgslot], sizeof(syslog_timetmp[msgslot]), "%s", syslog_time);
snprintf(syslog_datetmp[msgslot], sizeof(syslog_datetmp[msgslot]), "%s", syslog_date);
snprintf(syslog_leveltmp[msgslot], sizeof(syslog_leveltmp[msgslot]), "%s", syslog_level);
snprintf(syslog_tagtmp[msgslot], sizeof(syslog_tagtmp[msgslot]), "%s", syslog_tag);
snprintf(syslog_facilitytmp[msgslot], sizeof(syslog_facilitytmp[msgslot]), "%s", syslog_facility);
snprintf(syslog_programtmp[msgslot], sizeof(syslog_programtmp[msgslot]), "%s", syslog_program);
snprintf(ip_srctmp[msgslot], sizeof(ip_srctmp[msgslot]), "%s", ip_src);
snprintf(ip_dsttmp[msgslot], sizeof(ip_dsttmp[msgslot]), "%s", ip_dst);
snprintf(syslog_hosttmp[msgslot], sizeof(syslog_hosttmp[msgslot]), "%s", syslog_host);
snprintf(s_msgtmp[msgslot], sizeof(s_msgtmp[msgslot]), "%s", s_msg);
src_porttmp[msgslot] = src_port; 
dst_porttmp[msgslot] = dst_port;

SaganEvent[threadid].ip_src    =       ip_srctmp[msgslot];
SaganEvent[threadid].ip_dst    =       ip_dsttmp[msgslot];
SaganEvent[threadid].dst_port  =       dst_porttmp[msgslot];
SaganEvent[threadid].src_port  =       src_porttmp[msgslot];
SaganEvent[threadid].found     =       b;
SaganEvent[threadid].program   =       syslog_programtmp[msgslot];
SaganEvent[threadid].message   =       sysmsg[msgslot];
SaganEvent[threadid].endian    =       endianchk;
SaganEvent[threadid].time      =       syslog_timetmp[msgslot];
SaganEvent[threadid].date      =       syslog_datetmp[msgslot];
SaganEvent[threadid].f_msg     =       s_msgtmp[msgslot]; 
SaganEvent[threadid].facility  =       syslog_facilitytmp[msgslot];
SaganEvent[threadid].priority  =       syslog_leveltmp[msgslot];
SaganEvent[threadid].tag       =       syslog_tagtmp[msgslot];
SaganEvent[threadid].host      =       syslog_hosttmp[msgslot];
SaganEvent[threadid].event_time_sec = 	time(NULL);

}


/* Log alert to alert.log file */

if ( thresh_log_flag == 0 ) sagan_alert( &SaganEvent[threadid] );

/* Unified2 README */

#ifdef HAVE_LIBDNET

if ( sagan_unified2_flag ) {

if ( thresh_log_flag == 0 ) Sagan_Unified2( config,  &SaganEvent[threadid] );
if ( thresh_log_flag == 0 ) Sagan_Unified2LogPacketAlert( config, &SaganEvent[threadid] );

}

#endif

/****************************************************************************/
/* Prelude framework thread call (libprelude                                */
/****************************************************************************/

#if HAVE_LIBPRELUDE

if ( sagan_prelude_flag == 1 && thresh_log_flag == 0 ) {
	
if ( threadpreludec < max_prelude_threads ) {
	
	threadpreludec++;

	if ( threadpreludec > threadmaxpreludec ) threadmaxpreludec=threadpreludec;

	if ( pthread_create ( &threadprelude_id[threadid], &thread_prelude_attr, (void *)sagan_prelude, &SaganEvent[threadid] ) ) { 
		removelockfile();
	        sagan_log(1, "[%s, line %d] Error creating Prelude thread", __FILE__, __LINE__);
	        } 
	      	 } else { 
                sagandrop++;
                saganpreludedrop++;
                sagan_log(0, "Prelude thread call handler: Out of threads\n");
              	}
}
#endif


/****************************************************************************/
/* libesmtp thread call (SMTP/email)                                        */
/****************************************************************************/

#ifdef HAVE_LIBESMTP

if ( sagan_esmtp_flag == 1 && thresh_log_flag == 0 ) { 
		  
	/* E-mail only if over min_email_priority */ 

	if ( min_email_priority >= rulestruct[b].s_pri || min_email_priority == 0 ) { 

		if ( threademailc < max_email_threads ) { 
		  
		    threademailc++;

		    if ( threademailc > threadmaxemailc ) threadmaxemailc=threademailc;

                    if ( pthread_create( &threademail_id[threadid], &thread_email_attr, (void *)sagan_esmtp_thread, &SaganEvent[threadid] ) ) {
		       removelockfile();
                       sagan_log(1, "[%s, line %d] Error creating SMTP thread", __FILE__, __LINE__);
                       }

			} else { 
		       sagandrop++;
		       saganesmtpdrop++;
		       sagan_log(0, "SMTP thread call handler: Out of threads\n");
	        }
	}
}
#endif
		
/****************************************************************************/
/* External program thread call                                             */
/****************************************************************************/

if ( sagan_ext_flag == 1 && thresh_log_flag == 0 ) { 
		   
   if ( threadextc < max_ext_threads ) { 

	threadextc++;
		   
	if ( threadextc > threadmaxextc ) threadmaxextc=threadextc;
	
		if ( pthread_create( &threadext_id[threadid], &thread_ext_attr, (void *)sagan_ext_thread, &SaganEvent[threadid] ) ) { 
		     removelockfile();
		     sagan_log(1, "[%s, line %d] Error creating external call thread", __FILE__, __LINE__);
		     }
		      } else {
		     saganexternaldrop++;
		     sagandrop++; 
		     sagan_log(0, "External thread call handler: Out of threads\n");
		   }
}


/****************************************************************************/
/* Logzilla,  alert only,  thread call                                      */
/****************************************************************************/

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

if ( logzilla_dbtype != 0 && thresh_log_flag == 0 ) { 
		   
	if ( threadlogzillac < max_logzilla_threads) { 
		      
	        threadlogzillac++;
		      
		if ( threadlogzillac > threadmaxlogzillac ) threadmaxlogzillac=threadlogzillac;

                     if ( pthread_create( &threadlogzilla_id[threadid], &thread_logzilla_attr, (void *)sagan_logzilla_thread, &SaganEvent[threadid]) ) {
                          removelockfile();
                          sagan_log(1, "[%s, line %d] Error creating database thread.", __FILE__, __LINE__);
		        }
		           } else { 
		          saganlogzilladrop++;
		          sagandrop++;
		          sagan_log(0, "Logzilla thread handler: Out of threads");
		  }
}

#endif

/****************************************************************************/
/* Snort database thread call                                               */
/****************************************************************************/


#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

if ( dbtype != 0 && thresh_log_flag == 0 ) { 

        threaddbc++;

  		if ( threaddbc < maxdb_threads ) { 

			   if ( threaddbc > threadmaxdbc ) threadmaxdbc=threaddbc;

                
		   		cid++; 
		   		sigcid=cid;

				SaganEvent[threadid].cid = cid;

				if ( pthread_create( &threaddb_id[threadid], &thread_db_attr, (void *)sagan_db_thread, &SaganEvent[threadid]) ) { 
		    		   removelockfile();
		    		   sagan_log(1, "[%s, line %d] Error creating database thread.", __FILE__, __LINE__);
		    		   }
		    		    } else { 
		    		   sagansnortdrop++;
		    		   sagandrop++;
		    		   sagan_log(0, "Snort database thread handler: Out of threads");
	        		   }
}
#endif
	 	    
} /* End of match */
} /* End of pcre match */

match=0;  /* Reset match! */
pcrematch=0;
rc=0;
} /* End for for loop */

syslogstring[0]='\0';		/* Reset values */
syslogtmp[0]='\0';
}

} /* End of while(1) */
} /* End of main */


