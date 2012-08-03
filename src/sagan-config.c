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

/* sagan-config.c
 *
 * Loads the sagan.conf file into memory 
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#ifdef HAVE_LIBLOGNORM
#include <liblognorm.h>
#include <ptree.h>
#include <lognorm.h>
#endif

#include "version.h"

#include "sagan.h"

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/sagan-unified2.h"
#endif


#ifdef HAVE_LIBLOGNORM
struct liblognorm_struct *liblognormstruct;
int liblognorm_count;
#endif

struct _Rule_Struct *rulestruct;
struct _SaganCounters *counters;

void load_config( _SaganDebug *debug, _SaganConfig *config  ) { 

FILE *sagancfg; 

char normfile[MAXPATH];

char *filename;
char ruleset[MAXPATH];

char tmpbuf[CONFBUF];
char tmpstring[CONFBUF];

char *sagan_option=NULL;
char *sagan_var=NULL;
char *ptmp=NULL;

char *tok=NULL;

int i,check;

/* Set some system defaults */

snprintf(config->sagan_alert_filepath, sizeof(config->sagan_alert_filepath), "%s", ALERTLOG);
snprintf(config->sagan_lockfile, sizeof(config->sagan_lockfile), "%s", LOCKFILE);
snprintf(config->sagan_log_path, sizeof(config->sagan_log_path), "%s", SAGANLOGPATH);
config->sagan_proto = 17;		/* Default to UDP */
config->max_output_threads = MAX_OUTPUT_THREADS;
config->max_processor_threads = MAX_PROCESSOR_THREADS;

/* Start loading configuration */

rulestruct = (_Rule_Struct *) realloc(rulestruct, (counters->rulecount+1) * sizeof(_Rule_Struct));

/* Gather information for the master configuration file */


if ((sagancfg = fopen(config->sagan_config, "r")) == NULL) {
   fprintf(stderr, "[%s, line %d] Cannot open configuration file (%s)\n", __FILE__,  __LINE__, config->sagan_config);
   exit(1);
   }

while(fgets(tmpbuf, sizeof(tmpbuf), sagancfg) != NULL) {
     if (tmpbuf[0] == '#') continue;
     if (tmpbuf[0] == ';') continue;
     if (tmpbuf[0] == 10 ) continue;
     if (tmpbuf[0] == 32 ) continue;

     sagan_option = strtok_r(tmpbuf, " ", &tok);

     if (!strcmp(remrt(sagan_option), "max_output_threads")) { 
	 sagan_var = strtok_r(NULL, " ", &tok);
         config->max_output_threads = atol(sagan_var);
	 }

     if (!strcmp(remrt(sagan_option), "max_processor_threads")) {
	 sagan_var = strtok_r(NULL, " ", &tok);
         config->max_processor_threads = atol(sagan_var);
         }

     if (!strcmp(remrt(sagan_option), "disable_dns_warnings")) { 
         sagan_log(config, 0, "Supressing DNS warnings");
         config->disable_dns_warnings = 1;
	 }

     if (!strcmp(remrt(sagan_option), "syslog_src_lookup")) { 
         sagan_log(config, 0, "DNS lookup of source address supplied by syslog daemon");
	 config->syslog_src_lookup = 1; 
	 }


     if (!strcmp(sagan_option, "sagan_host")) {
        snprintf(config->sagan_host, sizeof(config->sagan_host)-1, "%s", strtok_r(NULL, " " , &tok));
        config->sagan_host[strlen(config->sagan_host)-1] = '\0';
        }

     if (!strcmp(sagan_option, "sagan_port")) {
         sagan_var = strtok_r(NULL, " ", &tok);
	 config->sagan_port = atoi(sagan_var);
         }

#ifndef HAVE_LIBESMTP
if (!strcmp(sagan_option, "send-to") || !strcmp(sagan_option, "min_email_priority")) 
   sagan_log(config,1, "\"libesmtp\" support not found. Re-compile with ESMTP support or disable in the sagan.conf.");
#endif

#ifdef HAVE_LIBESMTP

   if (!strcmp(sagan_option, "send-to")) { 
      sagan_var = strtok_r(NULL, " ", &tok);
      snprintf(config->sagan_esmtp_to, sizeof(config->sagan_esmtp_to), "%s", sagan_var);
      remrt(config->sagan_esmtp_to);
      config->sagan_esmtp_flag=1;
      config->sagan_sendto_flag=1;
      }

   if (!strcmp(sagan_option, "min_email_priority")) {
       sagan_var = strtok_r(NULL, " ", &tok);
       config->min_email_priority = atoi(sagan_var);
       }

#endif

#ifndef HAVE_LIBPCAP
if (!strcmp(sagan_option, "plog_interface") || !strcmp(sagan_option, "plog_logdev") || !strcmp(sagan_option, "plog_port")) 
   sagan_log(config,1, "\"libpcap\" support not found. Re-compile with PCAP support or disable in the sagan.conf.");
#endif

#ifdef HAVE_LIBPCAP

    if (!strcmp(sagan_option, "plog_interface")) { 
       snprintf(config->plog_interface, sizeof(config->plog_interface)-1, "%s", strtok_r(NULL, " ", &tok));
       config->plog_interface[strlen(config->plog_interface)-1] = '\0';
       config->plog_flag=1;
       }

    if (!strcmp(sagan_option, "plog_logdev")) { 
       snprintf(config->plog_logdev, sizeof(config->plog_logdev)-1, "%s", strtok_r(NULL, " ", &tok));
       config->plog_logdev[strlen(config->plog_logdev)-1] = '\0';
       config->plog_flag=1;
       }

    if (!strcmp(sagan_option, "plog_port")) {
       sagan_var = strtok_r(NULL, " ", &tok); 
       config->plog_port = atoi(sagan_var);
       config->plog_flag = 1;
       }

#endif

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

     if (!strcmp(sagan_option, "sagan_proto")) { 
        sagan_var = strtok_r(NULL, " ", &tok);
	config->sagan_proto = atoi(sagan_var);
	}
     
     if (!strcmp(sagan_option, "sagan_hostname")) { 
        snprintf(config->sagan_hostname, sizeof(config->sagan_hostname)-1, "%s", strtok_r(NULL, " ", &tok));
	config->sagan_hostname[strlen(config->sagan_hostname)-1] = '\0';
	}

     if (!strcmp(sagan_option, "sagan_interface")) { 
        snprintf(config->sagan_interface, sizeof(config->sagan_interface)-1, "%s", strtok_r(NULL, " ", &tok)); 
	config->sagan_interface[strlen(config->sagan_interface)-1] = '\0';
	}

     if (!strcmp(sagan_option, "sagan_filter")) { 
        snprintf(config->sagan_filter, sizeof(config->sagan_filter)-1, "%s", strtok_r(NULL, " ", &tok)); 
	config->sagan_filter[strlen(config->sagan_filter)-1] = '\0';
	}
    
     if (!strcmp(sagan_option, "sagan_detail")) {  
         sagan_var = strtok_r(NULL, " ", &tok);
         config->sagan_detail = atoi(sagan_var);
	 }

#endif

#ifndef HAVE_LIBLOGNORM
if (!strcmp(sagan_option, "normalize:")) {
   sagan_log(config, 0, "WARNING: Sagan was not compiled with \"liblognorm\" support!");
   sagan_log(config, 0, "WARNING: Sagan will continue,  but _without_ liblognorm!");
   }
#endif

#ifdef HAVE_LIBLOGNORM

/*
 We load the location for liblognorm's 'rule base/samples'.  We don't want to 
 load them quiet yet.  We only want to load samples we need,  so we do the
 actual ln_loadSamples() after the configuration file and all rules have
 been analyzed */

if (!strcmp(sagan_option, "normalize:")) {
	liblognormstruct = (liblognorm_struct *) realloc(liblognormstruct, (liblognorm_count+1) * sizeof(liblognorm_struct));
	
	sagan_var = strtok_r(NULL, ",", &tok);
	remspaces(sagan_var);
	snprintf(liblognormstruct[liblognorm_count].type, sizeof(liblognormstruct[liblognorm_count].type), "%s", sagan_var);

	snprintf(tmpstring, sizeof(tmpstring), "%s", strtok_r(NULL, ",", &tok));
	remspaces(tmpstring);
	tmpstring[strlen(tmpstring)-1] = '\0';
	strlcpy(normfile, sagan_replace_str(tmpstring, "$RULE_PATH", config->sagan_rule_path), sizeof(normfile));
	snprintf(liblognormstruct[liblognorm_count].filepath, sizeof(liblognormstruct[liblognorm_count].filepath), "%s", normfile);

	liblognorm_count++;
}

#endif

if (!strcmp(sagan_option, "output")) {
     
     config->output_thread_flag = 1;

     sagan_var = strtok_r(NULL," ", &tok);

     if (!strcmp(sagan_var, "external:")) {
        config->sagan_ext_flag=1;
        snprintf(config->sagan_extern, sizeof(config->sagan_extern), "%s", strtok_r(NULL, " ", &tok));
        if (strstr(strtok_r(NULL, " ", &tok), "parsable")) config->sagan_exttype=1;
        }


#ifdef WITH_SNORTSAM
if (!strcmp(sagan_var, "alert_fwsam:")) { 
       snprintf(config->sagan_fwsam_info, sizeof(config->sagan_fwsam_info), "%s", remrt(strtok_r(NULL, " ", &tok)));
       config->sagan_fwsam_flag=1; 
       }
#endif

#if !defined(HAVE_DNET_H) && !defined(HAVE_DUMBNET_H)
if (!strcmp(sagan_var, "unified2:")) { 
   sagan_log(config, 0,"\"libdnet\" support not found.  This is needed for unified2."); 
   sagan_log(config, 1, "Re-compile with libdnet support or disable in the sagan.conf.");
   }
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

if (!strcmp(sagan_var, "unified2:")) { 
  
  	   config->sagan_unified2_flag = 1;
	   
	   ptmp = sagan_var; 
	   remrt(ptmp);

	   while (ptmp != NULL ) {
	     
	     if (!strcmp(ptmp, "filename")) { 
	        ptmp = strtok_r(NULL, ",", &tok);
	 	snprintf(config->unified2_filepath, sizeof(config->unified2_filepath), "%s/%s", config->sagan_log_path, ptmp);
		}

	     if (!strcmp(ptmp, "limit")) { 
	        ptmp = strtok_r(NULL, " ", &tok);
	        config->unified2_limit = atoi(ptmp) * 1024 * 1024;
		}

             if (!strcmp(ptmp, "nostamp")) config->unified2_nostamp = 1;
	   
	   ptmp = strtok_r(NULL, " ", &tok);

	   }
}

#endif

#ifndef HAVE_LIBPRELUDE
	if (!strcmp(sagan_var, "prelude:"))
           sagan_log(config,1, " libprelude support not found. Re-compile with Prelude support or disable in the sagan.conf.");
#endif 

#ifdef HAVE_LIBPRELUDE
	
	if (!strcmp(sagan_var, "prelude:")) { 
	   ptmp = sagan_var; 

	   while (ptmp != NULL ) { 

	     if (!strcmp(ptmp, "profile")) { 
	         ptmp = strtok_r(NULL, " ", &tok);
		 snprintf(config->sagan_prelude_profile, sizeof(config->sagan_prelude_profile), "%s", ptmp); 
		 remrt(config->sagan_prelude_profile);
		 config->sagan_prelude_flag=1;
		 }
           
	   ptmp = strtok_r(NULL, "=", &tok);
	   }
	}
#endif


#ifdef HAVE_LIBESMTP

	if (!strcmp(sagan_var, "email:")) { 
	   ptmp = sagan_var;

	   while (ptmp != NULL ) { 

             if (!strcmp(ptmp, "from")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->sagan_esmtp_from, sizeof(config->sagan_esmtp_from), "%s", ptmp);
		remrt(config->sagan_esmtp_from);
                }

             if (!strcmp(ptmp, "smtpserver")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->sagan_esmtp_server, sizeof(config->sagan_esmtp_server), "%s", ptmp);
		remrt(config->sagan_esmtp_server);
                }

          ptmp = strtok_r(NULL, "=", &tok);    
	  }

	}
#endif


#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

	/* output type (database, etc) */

	if (!strcmp(sagan_var, "database:")) {
	   sagan_var = strtok_r(NULL, ",", &tok);
	
	   /* Type (only "log" is used right now */

	   if (!strcmp(sagan_var, "log")) { 
	      sagan_var = strtok_r(NULL, ",", &tok); 
	      }

	      /* MySQL/PostgreSQL/Oracle/etc */

	      remspaces(sagan_var);


	      if (!strcmp(sagan_var, "mysql" )) { 
#ifndef HAVE_LIBMYSQLCLIENT_R
   	         sagan_log(config, 1,"MySQL support not found. Re-compile with MySQL support or disable in the sagan.conf.");
#endif
	         config->dbtype=1; 
	         }

	      if (!strcmp(sagan_var, "postgresql" )) { 
#ifndef HAVE_LIBPQ
		 sagan_log(config, 1,"PostgreSQL support not found. Re-compile with PostgreSQL support or disable in the sagan.conf.");
#endif
		 config->dbtype=2; 
		 }


	      sagan_var = strtok_r(NULL, ",", &tok);
	      remrt(sagan_var);					/* rm NL */
	      
	      strlcpy(tmpbuf, sagan_var, sizeof(tmpbuf));

	      ptmp = strtok_r(tmpbuf, "=", &tok);

	      while (ptmp != NULL) { 
	        remspaces(ptmp); 

	        if (!strcmp(ptmp, "user")) { 
		   ptmp = strtok_r(NULL, " ", &tok);
		   snprintf(config->dbuser, sizeof(config->dbuser), "%s", ptmp);
		   }

                if (!strcmp(ptmp , "password")) {
		   ptmp = strtok_r(NULL, " ", &tok);
		   snprintf(config->dbpassword, sizeof(config->dbpassword), "%s", ptmp);
                   }

		if (!strcmp(ptmp, "dbname")) { 
		   ptmp = strtok_r(NULL, " ", &tok);
		   snprintf(config->dbname, sizeof(config->dbname), "%s", ptmp);
		   }

		if (!strcmp(ptmp, "host")) { 
		   ptmp = strtok_r(NULL, " ", &tok);
		   snprintf(config->dbhost, sizeof(config->dbhost), "%s", ptmp);
		   }

		if (!strcmp(ptmp, "port")) {
		   config->dbport = atoi(ptmp);
		   }

	      ptmp = strtok_r(NULL, "=", &tok);


	     }
	   
	   }
#endif      
   }
       
     /* "var" */

     if (!strcmp(sagan_option, "var")) {
         sagan_var = strtok_r(NULL, " ", &tok);

	if (config->sagan_fifo_flag == 0 ) { 		/* File overides FIFO settings */

        if (!strcmp(sagan_var, "FIFO" )) {
	   snprintf(config->sagan_fifo, sizeof(config->sagan_fifo), "%s", strtok_r(NULL, " ", &tok));
           config->sagan_fifo[strlen(config->sagan_fifo)-1] = '\0'; 
	   }
	
	}

        if (!strcmp(sagan_var, "RULE_PATH" )) {
	   snprintf(config->sagan_rule_path, sizeof(config->sagan_rule_path), "%s", strtok_r(NULL, " ", &tok));
	   config->sagan_rule_path[strlen(config->sagan_rule_path)-1] = '\0';
	   }

        if (!strcmp(sagan_var, "LOCKFILE" )) {
	   snprintf(config->sagan_lockfile, sizeof(config->sagan_lockfile), "%s", strtok_r(NULL, " ", &tok));
           config->sagan_lockfile[strlen(config->sagan_lockfile)-1] = '\0'; 
	   }

        if (!strcmp(sagan_var, "ALERTLOG" )) {
           snprintf(config->sagan_alert_filepath, sizeof(config->sagan_alert_filepath), "%s", strtok_r(NULL, " ", &tok));
           config->sagan_alert_filepath[strlen(config->sagan_alert_filepath)-1] = '\0'; 
	   }
	
	if (!strcmp(sagan_var, "SAGANLOGPATH" )) {
           snprintf(config->sagan_log_path, sizeof(config->sagan_log_path), "%s", strtok_r(NULL, " ", &tok));
           config->sagan_log_path[strlen(config->sagan_log_path)-1] = '\0';
           }
	}

/* "include */

     if (!strcmp(sagan_option, "include" )) {

         snprintf(tmpstring, sizeof(tmpstring), "%s", strtok_r(NULL, " ", &tok));

         tmpstring[strlen(tmpstring)-1] = '\0';
	
         strlcpy(ruleset, sagan_replace_str(tmpstring, "$RULE_PATH", config->sagan_rule_path), sizeof(ruleset));

	 filename=sagan_getfilename(ruleset);   /* Get the file name to figure out "what" we're loading */

         if (!strcmp(filename, "classification.config"))
            {
                   load_classifications(debug, config, ruleset);
            }

         if (!strcmp(filename, "reference.config"))
            {
                   load_reference(debug, config, ruleset);
            }

	 /* It's not a classifcations file or reference,  so it must be a ruleset */

         if (strcmp(filename, "reference.config") && strcmp(filename, "classification.config"))  {
                   
		   load_rules(debug, config,  ruleset);
          }
     }
}

fclose(sagancfg);

/* Check rules for duplicate sid.  We can't have that! */

for (i = 0; i < counters->rulecount; i++) {
   for ( check = i+1; check < counters->rulecount; check ++) {
       if (!strcmp (rulestruct[check].s_sid, rulestruct[i].s_sid ))
            sagan_log(config, 1, "[%s, line %d] Detected duplicate signature id [sid] number %s.  Please correct this.", __FILE__, __LINE__, rulestruct[check].s_sid, rulestruct[i].s_sid);
       }
   }

/* If we have the "send-to" option,  verify the configuration has the proper smtpserver, etc.  */

#ifdef HAVE_LIBESMTP

if (config->sagan_esmtp_flag && !strcmp(config->sagan_esmtp_server, "")) sagan_log(config, 1, "[%s, line %d] Configuration SMTP 'smtpserver' field is missing! |%s|", __FILE__, __LINE__, config->sagan_esmtp_server);
if (config->sagan_esmtp_flag && !strcmp(config->sagan_esmtp_from, "" )) sagan_log(config, 1, "[%s, line %d] Configuration SMTP 'from' field is missing!", __FILE__,  __LINE__);

#endif 

if (!strcmp(config->sagan_fifo, "")) sagan_log(config, 1, "No FIFO option found which is required! Aborting!");
if (!strcmp(config->sagan_host, "" )) sagan_log(config, 1, "The 'sagan_host' option was not found and is required.");
if ( config->sagan_port == 0 ) sagan_log(config, 1, "The 'sagan_port' option was not set and is required.");

}
