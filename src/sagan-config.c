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
struct _SaganDebug *debug;
struct _SaganConfig *config;
struct _SaganVar *var; 

void Load_Config( void ) { 

FILE *sagancfg; 

char *filename;
char ruleset[MAXPATH];
char normfile[MAXPATH];

char tmpbuf[CONFBUF];
char tmpstring[CONFBUF];

char *sagan_option=NULL;
char *sagan_var1=NULL;
char *sagan_var2=NULL;
char *ptmp=NULL;

char *tok=NULL;

int i,check;

/* Set some system defaults */

snprintf(config->sagan_alert_filepath, sizeof(config->sagan_alert_filepath), "%s", ALERTLOG);
snprintf(config->sagan_lockfile, sizeof(config->sagan_lockfile), "%s", LOCKFILE);
snprintf(config->sagan_log_path, sizeof(config->sagan_log_path), "%s", SAGANLOGPATH);
if ( config->sagan_fifo_flag != 1 ) snprintf(config->sagan_fifo, sizeof(config->sagan_fifo), "%s", FIFO); 
snprintf(config->sagan_rule_path, sizeof(config->sagan_rule_path), "%s", RULE_PATH);


config->sagan_proto = 17;		/* Default to UDP */
config->max_processor_threads = MAX_PROCESSOR_THREADS;

//config->home_any = 0; 
//config->external_any = 0; 

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

     if (!strcmp(Remove_Return(sagan_option), "max_processor_threads")) {
         sagan_var1 = strtok_r(NULL, " ", &tok);
         config->max_processor_threads = strtoull(sagan_var1, NULL, 10);
         }

     if (!strcmp(Remove_Return(sagan_option), "disable_dns_warnings")) { 
         Sagan_Log(0, "Supressing DNS warnings");
         config->disable_dns_warnings = 1;
	 }

     if (!strcmp(Remove_Return(sagan_option), "syslog_src_lookup")) { 
         Sagan_Log(0, "DNS lookup of source address supplied by syslog daemon");
	 config->syslog_src_lookup = 1; 
	 }


     if (!strcmp(sagan_option, "sagan_host")) {
        snprintf(config->sagan_host, sizeof(config->sagan_host)-1, "%s", strtok_r(NULL, " " , &tok));
        config->sagan_host[strlen(config->sagan_host)-1] = '\0';
        }

     if (!strcmp(sagan_option, "sagan_port")) {
         sagan_var1 = strtok_r(NULL, " ", &tok);
	 config->sagan_port = atoi(sagan_var1);
         }

#ifndef HAVE_LIBESMTP
if (!strcmp(sagan_option, "send-to") || !strcmp(sagan_option, "min_email_priority")) 
   Sagan_Log(1, "\"libesmtp\" support not found. Re-compile with ESMTP support or disable in the sagan.conf.");
#endif

#ifdef HAVE_LIBESMTP

   if (!strcmp(sagan_option, "send-to")) { 
      sagan_var1 = strtok_r(NULL, " ", &tok);
      snprintf(config->sagan_esmtp_to, sizeof(config->sagan_esmtp_to), "%s", sagan_var1);
      Remove_Return(config->sagan_esmtp_to);
      config->sagan_esmtp_flag=1;
      config->sagan_sendto_flag=1;
      }

   if (!strcmp(sagan_option, "min_email_priority")) {
       sagan_var1 = strtok_r(NULL, " ", &tok);
       config->min_email_priority = atoi(sagan_var1);
       }

#endif

#ifndef HAVE_LIBPCAP
if (!strcmp(sagan_option, "plog_interface") || !strcmp(sagan_option, "plog_logdev") || !strcmp(sagan_option, "plog_port")) 
   Sagan_Log(1, "\"libpcap\" support not found. Re-compile with PCAP support or disable in the sagan.conf.");
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
       sagan_var1 = strtok_r(NULL, " ", &tok); 
       config->plog_port = atoi(sagan_var1);
       config->plog_flag = 1;
       }

#endif

#ifndef HAVE_LIBLOGNORM
if (!strcmp(sagan_option, "normalize:")) {
   Sagan_Log(0, "WARNING: Sagan was not compiled with \"liblognorm\" support!");
   Sagan_Log(0, "WARNING: Sagan will continue,  but _without_ liblognorm!");
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
	
	sagan_var1 = strtok_r(NULL, ",", &tok);
	Remove_Spaces(sagan_var1);
	snprintf(liblognormstruct[liblognorm_count].type, sizeof(liblognormstruct[liblognorm_count].type), "%s", sagan_var1);

	snprintf(tmpstring, sizeof(tmpstring), "%s", strtok_r(NULL, ",", &tok));
	Remove_Spaces(tmpstring);
	tmpstring[strlen(tmpstring)-1] = '\0';

        strlcpy(normfile, Sagan_Var_To_Value(tmpstring), sizeof(normfile));
        Remove_Spaces(normfile);

	snprintf(liblognormstruct[liblognorm_count].filepath, sizeof(liblognormstruct[liblognorm_count].filepath), "%s", normfile);
	liblognorm_count++;
}

#endif

if (!strcmp(sagan_option, "drop_list:")) { 
   sagan_var1 = Remove_Return(strtok_r(NULL, " ", &tok)); 

   if ( sagan_var1 == NULL )  
      Sagan_Log(1, "[%s, line %d] No \"drop file\" specified in the sagan.conf file!", __FILE__, __LINE__);

   config->sagan_droplist_flag = 1; 
   snprintf(config->sagan_droplistfile, sizeof(config->sagan_droplistfile)-1, "%s", sagan_var1);
   }

if (!strcmp(sagan_option, "processor")) {
        sagan_var1 = strtok_r(NULL," ", &tok);

        if (!strcmp(sagan_var1, "sagan-track-clients:")) {
            sagan_var1 = strtok_r(NULL," ", &tok);

                if (!strcmp(sagan_var1, "client_timeout")) {
                   sagan_var1 = strtok_r(NULL," ", &tok);
                   config->pp_sagan_track_clients = atoi(sagan_var1);
                   config->sagan_track_clients_flag = 1;
                   }
		}


	if (!strcmp(sagan_var1, "blacklist:")) { 
	   
	   config->blacklist_flag=1;

	   ptmp = sagan_var1;

	   while (ptmp != NULL ) {

	     if (!strcmp(ptmp, "parse_depth")) { 
	        ptmp = strtok_r(NULL, " ", &tok);
	        config->blacklist_parse_depth = atoi(ptmp);
	        }

             if (!strcmp(ptmp, "blacklist")) { 
	        ptmp = strtok_r(NULL, " ", &tok);
		snprintf(config->blacklist_file, sizeof(config->blacklist_file), "%s", Remove_Return(ptmp)); 
		}
             
	     ptmp = strtok_r(NULL, "=", &tok);
	     
	     }		               
	   }

	
	if (!strcmp(sagan_var1, "search_nocase:")) { 

	   config->search_nocase_flag=1;

	   ptmp = sagan_var1; 

           while (ptmp != NULL ) {

             if (!strcmp(ptmp, "searchlist")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->search_nocase_file, sizeof(config->search_nocase_file), "%s", Remove_Return(ptmp));
                }

             ptmp = strtok_r(NULL, "=", &tok);

             }
           }

        if (!strcmp(sagan_var1, "search_case:")) {

           config->search_case_flag=1;

           ptmp = sagan_var1;

           while (ptmp != NULL ) {

             if (!strcmp(ptmp, "searchlist")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->search_case_file, sizeof(config->search_case_file), "%s", Remove_Return(ptmp));
                }

             ptmp = strtok_r(NULL, "=", &tok);

             }
           }




#ifdef WITH_WEBSENSE

        if (!strcmp(sagan_var1, "websense:")) {

	   config->websense_flag=1;

           ptmp = sagan_var1;

           while (ptmp != NULL ) {

             if (!strcmp(ptmp, "parse_depth")) {
                ptmp = strtok_r(NULL, " ", &tok);
		config->websense_parse_depth = atoi(ptmp);
                }

             if (!strcmp(ptmp, "auth")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->websense_auth, sizeof(config->websense_auth), "%s", ptmp);
                Remove_Return(config->websense_auth);
                }

             if (!strcmp(ptmp, "url")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->websense_url, sizeof(config->websense_url), "%s", ptmp);
                Remove_Return(config->websense_url);
                }
	
             if (!strcmp(ptmp, "max_cache")) {
                ptmp = strtok_r(NULL, " ", &tok);
		config->websense_max_cache = strtoull(ptmp, NULL, 10);
                }

	     if (!strcmp(ptmp, "cache_timeout")) { 
	        ptmp = strtok_r(NULL, " ", &tok);
		config->websense_timeout = atoi(ptmp) * 60;
		}

             if (!strcmp(ptmp, "ignore_list")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->websense_ignore_list, sizeof(config->websense_ignore_list), "%s", ptmp);
                Remove_Return(config->websense_ignore_list);
                }

          ptmp = strtok_r(NULL, "=", &tok);
          }

        }

	/* ERROR CHECKING HERE? */

#endif
}

if (!strcmp(sagan_option, "output")) {
     
     config->output_thread_flag = 1;

     sagan_var1 = strtok_r(NULL," ", &tok);

     if (!strcmp(sagan_var1, "external:")) {
        config->sagan_ext_flag=1;
	config->sagan_external_output_flag=1;
        snprintf(config->sagan_extern, sizeof(config->sagan_extern), "%s", strtok_r(NULL, " ", &tok));
        if (strstr(strtok_r(NULL, " ", &tok), "parsable")) config->sagan_exttype=1;
        }


#ifdef WITH_SNORTSAM
if (!strcmp(sagan_var1, "alert_fwsam:")) { 
       snprintf(config->sagan_fwsam_info, sizeof(config->sagan_fwsam_info), "%s", Remove_Return(strtok_r(NULL, " ", &tok)));
       config->sagan_fwsam_flag=1; 
       }
#endif

#if !defined(HAVE_DNET_H) && !defined(HAVE_DUMBNET_H)
if (!strcmp(sagan_var1, "unified2:")) { 
   Sagan_Log(0,"\"libdnet\" support not found.  This is needed for unified2."); 
   Sagan_Log(1, "Re-compile with libdnet support or disable in the sagan.conf.");
   }
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

if (!strcmp(sagan_var1, "unified2:")) { 
  
  	   config->sagan_unified2_flag = 1;
	   
	   ptmp = sagan_var1; 
	   Remove_Return(ptmp);

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

#ifdef HAVE_LIBESMTP

	if (!strcmp(sagan_var1, "email:")) { 

	   ptmp = sagan_var1;

	   while (ptmp != NULL ) { 

             if (!strcmp(ptmp, "from")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->sagan_esmtp_from, sizeof(config->sagan_esmtp_from), "%s", ptmp);
		Remove_Return(config->sagan_esmtp_from);
                }

             if (!strcmp(ptmp, "smtpserver")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(config->sagan_esmtp_server, sizeof(config->sagan_esmtp_server), "%s", ptmp);
		Remove_Return(config->sagan_esmtp_server);
                }

          ptmp = strtok_r(NULL, "=", &tok);    
	  }

	}
#endif
}
     
     /* var */

     if (!strcmp(sagan_option, "var")) { 
        sagan_var1 = strtok_r(NULL, " ", &tok);
	var = (_SaganVar *) realloc(var, (counters->var_count+1) * sizeof(_SaganVar));   /* Allocate memory */
	snprintf(var[counters->var_count].var_name, sizeof(var[counters->var_count].var_name), "$%s", sagan_var1);
	sagan_var2 = strtok_r(NULL, " ", &tok); /* Move to position of value of var */
	snprintf(var[counters->var_count].var_value, sizeof(var[counters->var_count].var_value), "%s", Remove_Return(sagan_var2));
	counters->var_count++;
	
	/* Required var's - all others are optional */ 

	if (!strcmp(sagan_var1, "FIFO") && config->sagan_fifo_flag != 1) snprintf(config->sagan_fifo, sizeof(config->sagan_fifo), "%s", sagan_var2);
	if (!strcmp(sagan_var1, "LOCKFILE" )) snprintf(config->sagan_lockfile, sizeof(config->sagan_lockfile), "%s", sagan_var2);
	if (!strcmp(sagan_var1, "ALERTLOG" )) snprintf(config->sagan_alert_filepath, sizeof(config->sagan_alert_filepath), "%s", sagan_var2);
	if (!strcmp(sagan_var1, "SAGANLOGPATH" )) snprintf(config->sagan_log_path, sizeof(config->sagan_log_path), "%s", sagan_var2);
/*
	if (!strcmp(sagan_var1, "HOME_NET" )) { 
	   if (strcasestr(sagan_var2, "any" )) config->home_any = 1; 
	   }

	if (!strcmp(sagan_var1, "EXTERNAL_NET" )) {
	   if (strcasestr(sagan_var2, "any" )) config->external_any = 1;
	   }
*/	
	}

/* "include */

     if (!strcmp(sagan_option, "include" )) {

         snprintf(tmpstring, sizeof(tmpstring), "%s", strtok_r(NULL, " ", &tok));

         tmpstring[strlen(tmpstring)-1] = '\0';
	
	 strlcpy(ruleset, Sagan_Var_To_Value(tmpstring), sizeof(ruleset)); 
	 Remove_Spaces(ruleset);

	 filename=Get_Filename(ruleset);   /* Get the file name to figure out "what" we're loading */

         if (!strcmp(filename, "classification.config")) Load_Classifications(ruleset);
         if (!strcmp(filename, "reference.config")) Load_Reference(ruleset);
         if (!strcmp(filename, "gen-msg.map")) Load_Gen_Map(ruleset);

	 /* It's not a classifcations file or reference,  so it must be a ruleset */

         if (strcmp(filename, "reference.config") && strcmp(filename, "classification.config") && strcmp(filename, "gen-msg.map"))  {
                   
		   Load_Rules(ruleset);
          }
     }
}

fclose(sagancfg);

/* Check rules for duplicate sid.  We can't have that! */

for (i = 0; i < counters->rulecount; i++) {
   for ( check = i+1; check < counters->rulecount; check ++) {
       if (!strcmp (rulestruct[check].s_sid, rulestruct[i].s_sid ))
            Sagan_Log(1, "[%s, line %d] Detected duplicate signature id [sid] number %s.  Please correct this.", __FILE__, __LINE__, rulestruct[check].s_sid, rulestruct[i].s_sid);
       }
   }

/* If we have the "send-to" option,  verify the configuration has the proper smtpserver, etc.  */

#ifdef HAVE_LIBESMTP

if (config->sagan_esmtp_flag && !strcmp(config->sagan_esmtp_server, "")) Sagan_Log(1, "[%s, line %d] Configuration SMTP 'smtpserver' field is missing! |%s|", __FILE__, __LINE__, config->sagan_esmtp_server);
if (config->sagan_esmtp_flag && !strcmp(config->sagan_esmtp_from, "" )) Sagan_Log(1, "[%s, line %d] Configuration SMTP 'from' field is missing!", __FILE__,  __LINE__);

#endif 

if (!strcmp(config->sagan_fifo, "")) Sagan_Log(1, "No FIFO option found which is required! Aborting!");
if (!strcmp(config->sagan_host, "" )) Sagan_Log(1, "The 'sagan_host' option was not found and is required.");
if ( config->sagan_port == 0 ) Sagan_Log(1, "The 'sagan_port' option was not set and is required.");

}
