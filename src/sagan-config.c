/*
** Copyright (C) 2009-2010 Softwink, Inc. 
** Copyright (C) 2009-2010 Champ Clark III <champ@softwink.com>
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

#include "version.h"
#include "sagan.h"

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

int  dbtype=0;

char dbusername[MAXUSER]="";
char dbpassword[MAXPASS]="";
char dbname[MAXDBNAME]="";
char dbhost[MAXHOST]="";

int  logzilla_log=0;
int  logzilla_dbtype=0;
char logzilla_user[MAXUSER]="";
char logzilla_password[MAXPASS]="";
char logzilla_dbname[MAXDBNAME]="";
char logzilla_dbhost[MAXHOST]="";
int maxdb_threads=MAX_DB_THREADS;

char sagan_hostname[MAXHOST];
char sagan_interface[50];
char sagan_filter[50];
int  sagan_detail;

char sagan_host[17];
char sagan_port[6]="514";
int  sagan_proto = 6;

int max_logzilla_threads=MAX_LOGZILLA_THREADS;

#endif

#ifdef HAVE_LIBESMTP
char sagan_esmtp_from[ESMTPSERVER];
char sagan_esmtp_to[255];
char sagan_esmtp_server[255];
int max_email_threads=MAX_EMAIL_THREADS;
int min_email_priority;
#endif

int max_ext_threads=MAX_EXT_THREADS;
int programmode;

struct rule_struct *rulestruct;
int rulecount,i,check;

int fifoi; 

char sagan_extern[MAXPATH];
int  sagan_exttype;
char saganconf[MAXPATH];
char fifo[MAXPATH];
char rule_path[MAXPATH];
FILE *sagancfg;

char *rulesetptr;
char ruleset[MAXPATH];

char *replace_str(char *str, char *orig, char *rep)
{
  static char buffer[4096];
  char *p;
  if(!(p = strstr(str, orig)))  return str;
  strlcpy(buffer, str, p-str); 
  buffer[p-str] = '\0';
  sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));
  rulesetptr=p+strlen(orig);
  return buffer;
}

void load_config( void ) { 

char tmpbuf[CONFBUF];
char tmplog[MAXPATH];
char tmpstring[CONFBUF];

char *sagan_option=NULL;
char *sagan_var=NULL;
char *ptmp=NULL;

char *tok=NULL;

/* Gather information for the master configuration file */

if ((sagancfg = fopen(saganconf, "r")) == NULL) {
   sagan_log(1, "[%s, line %d] Cannot open configuration file (%s)", __FILE__,  __LINE__, saganconf);
   }

while(fgets(tmpbuf, sizeof(tmpbuf), sagancfg) != NULL) {
     if (tmpbuf[0] == '#') continue;
     if (tmpbuf[0] == ';') continue;
     if (tmpbuf[0] == 10 ) continue;
     if (tmpbuf[0] == 32 ) continue;

     sagan_option = strtok_r(tmpbuf, " ", &tok);

     if (!strcmp(sagan_option, "max_ext_threads")) {
         sagan_var = strtok_r(NULL, " ", &tok);
         max_ext_threads = atoi(sagan_var);
         }


#ifdef HAVE_LIBESMTP

   if (!strcmp(sagan_option, "max_email_threads")) {
       sagan_var = strtok_r(NULL, " ", &tok);
       max_email_threads = atoi(sagan_var);
       }

   if (!strcmp(sagan_option, "min_email_priority")) {
       sagan_var = strtok_r(NULL, " ", &tok);
       min_email_priority = atoi(sagan_var);
       }

#endif

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

     if (!strcmp(sagan_option, "maxdb_threads")) {
        sagan_var = strtok_r(NULL, " " , &tok);
        maxdb_threads = atoi(sagan_var);
        }

     if (!strcmp(sagan_option, "max_logzilla_threads")) {
         sagan_var = strtok_r(NULL, " ", &tok);
         max_logzilla_threads = atoi(sagan_var);
         }

     if (!strcmp(sagan_option, "sagan_host")) {
        snprintf(sagan_host, sizeof(sagan_host)-1, "%s", strtok_r(NULL, " " , &tok));
	sagan_host[strlen(sagan_host)-1] = '\0';
        }
  
     if (!strcmp(sagan_option, "sagan_port")) {
         snprintf(sagan_port, sizeof(sagan_port), "%s", strtok_r(NULL, " " , &tok));
	 sagan_port[strlen(sagan_port)-1] = '\0'; 
         }
     
     if (!strcmp(sagan_option, "sagan_proto")) { 
        sagan_var = strtok_r(NULL, " ", &tok);
	sagan_proto = atoi(sagan_var);
	}
     
     if (!strcmp(sagan_option, "sagan_hostname")) { 
        snprintf(sagan_hostname, sizeof(sagan_hostname)-1, "%s", strtok_r(NULL, " ", &tok));
	sagan_hostname[strlen(sagan_hostname)-1] = '\0';
	}

     if (!strcmp(sagan_option, "sagan_interface")) { 
        snprintf(sagan_interface, sizeof(sagan_interface)-1, "%s", strtok_r(NULL, " ", &tok)); 
	sagan_interface[strlen(sagan_interface)-1] = '\0';
	}

     if (!strcmp(sagan_option, "sagan_filter")) { 
        snprintf(sagan_filter, sizeof(sagan_filter)-1, "%s", strtok_r(NULL, " ", &tok)); 
	sagan_filter[strlen(sagan_filter)-1] = '\0';
	}
    
     if (!strcmp(sagan_option, "sagan_detail")) {  
         sagan_var = strtok_r(NULL, " ", &tok);
         sagan_detail = atoi(sagan_var);
	 }

#endif


if (!strcmp(sagan_option, "output")) {
             sagan_var = strtok_r(NULL," ", &tok);

     if (!strcmp(sagan_var, "external:")) {
        snprintf(sagan_extern, sizeof(sagan_extern), "%s", strtok_r(NULL, " ", &tok));
           if (strstr(strtok_r(NULL, " ", &tok), "parsable")) sagan_exttype=1;
        }


#ifdef HAVE_LIBESMTP

	if (!strcmp(sagan_var, "email:")) { 
	   ptmp = sagan_var;

	   while (ptmp != NULL ) { 

	     if (!strcmp(ptmp, "to")) { 
	        ptmp = strtok_r(NULL, " ", &tok);
		snprintf(sagan_esmtp_to, sizeof(sagan_esmtp_to), "%s", ptmp);
		remrt(sagan_esmtp_to);
		}
             
             if (!strcmp(ptmp, "from")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(sagan_esmtp_from, sizeof(sagan_esmtp_from), "%s", ptmp);
		remrt(sagan_esmtp_from);
                }

             if (!strcmp(ptmp, "smtpserver")) {
                ptmp = strtok_r(NULL, " ", &tok);
                snprintf(sagan_esmtp_server, sizeof(sagan_esmtp_server), "%s", ptmp);
		remrt(sagan_esmtp_server);
                }

          ptmp = strtok_r(NULL, "=", &tok);    
	  }

	  if (!strcmp(sagan_esmtp_from, "" )) sagan_log(1, "[%s, line %d] Configuration SMTP 'from' field is missing!", __FILE__,  __LINE__);
	  if (!strcmp(sagan_esmtp_to, "" )) sagan_log(1, "[%s, line %d] Configuration SMTP 'to' field is missing!", __FILE__, __LINE__);
	  if (!strcmp(sagan_esmtp_server, "" )) sagan_log(1, "[%s, line %d] Configuration SMTP 'smtpserver' field is missing!", __FILE__, __LINE__);

	}
#endif


#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

	if (!strcmp(sagan_var, "logzilla:")) { 
	   sagan_var = strtok_r(NULL, ",", &tok); 
	   remspaces(sagan_var);

	   if ( !strcmp(sagan_var, "full" )) logzilla_log = 1;

	      sagan_var = strtok_r(NULL, ",", &tok); 
	      remspaces(sagan_var);

	      if (!strcmp(sagan_var, "mysql")) logzilla_dbtype = 1;
	      if (!strcmp(sagan_var, "postgresql")) logzilla_dbtype = 2;
	      
	      sagan_var = strtok_r(NULL, ",", &tok);

	   
	   remrt(sagan_var);

	   strlcpy(tmpbuf, sagan_var, sizeof(tmpbuf)); 
	   ptmp = strtok_r(tmpbuf, "=", &tok);

	   while (ptmp != NULL) { 
	      remspaces(ptmp);

	      if (!strcmp(ptmp, "user")) { 
	         ptmp = strtok_r(NULL, " ", &tok);
		 snprintf(logzilla_user, sizeof(logzilla_user), "%s", ptmp);
		 }

	      if (!strcmp(ptmp, "password")) { 
	         ptmp = strtok_r(NULL, " ", &tok);
		 snprintf(logzilla_password, sizeof(logzilla_password), "%s", ptmp);
		 }

	      if (!strcmp(ptmp, "dbname")) { 
	         ptmp = strtok_r(NULL, " ", &tok); 
		 snprintf(logzilla_dbname, sizeof(logzilla_dbname), "%s", ptmp);
		 }

	      if (!strcmp(ptmp, "host")) { 
	         ptmp = strtok_r(NULL, " ", &tok);
		 snprintf(logzilla_dbhost, sizeof(logzilla_dbhost), "%s", ptmp);
		 }

             ptmp = strtok_r(NULL, "=", &tok);
	     }


	   }

	/* output type (database, etc) */

	if (!strcmp(sagan_var, "database:")) {
	   sagan_var = strtok_r(NULL, ",", &tok);
	
	   /* Type (only "log" is used right now */

	   if (!strcmp(sagan_var, "log")) { 
	      sagan_var = strtok_r(NULL, ",", &tok); 
	      }

	      /* MySQL/PostgreSQL/Oracle/etc */

	      remspaces(sagan_var);

	      if (!strcmp(sagan_var, "mysql" )) dbtype=1; 
	      if (!strcmp(sagan_var, "postgresql" )) dbtype=2; 

	      sagan_var = strtok_r(NULL, ",", &tok);
	      remrt(sagan_var);					/* rm NL */
	      
	      strlcpy(tmpbuf, sagan_var, sizeof(tmpbuf));

	      ptmp = strtok_r(tmpbuf, "=", &tok);

	      while (ptmp != NULL) { 
	        remspaces(ptmp); 

	        if (!strcmp(ptmp, "user")) { 
		   ptmp = strtok_r(NULL, " ", &tok);
		   snprintf(dbusername, sizeof(dbusername), "%s", ptmp);
		   }

                if (!strcmp(ptmp , "password")) {
		   ptmp = strtok_r(NULL, " ", &tok);
		   snprintf(dbpassword, sizeof(dbpassword), "%s", ptmp);
                   }

		if (!strcmp(ptmp, "dbname")) { 
		   ptmp = strtok_r(NULL, " ", &tok);
		   snprintf(dbname, sizeof(dbname), "%s", ptmp);
		   }

		if (!strcmp(ptmp, "host")) { 
		   ptmp = strtok_r(NULL, " ", &tok);
		   snprintf(dbhost, sizeof(dbhost), "%s", ptmp);
		   }

	      ptmp = strtok_r(NULL, "=", &tok);


	     }
	   
	   }
#endif      
   }
       
     /* "var" */

     if (!strcmp(sagan_option, "var")) {
         sagan_var = strtok_r(NULL, " ", &tok);

        if (!strcmp(sagan_var, "FIFO" )) {
           snprintf(fifo, sizeof(fifo), "%s", strtok_r(NULL, " ", &tok));
           fifo[strlen(fifo)-1] = '\0'; 
	   if ( programmode != 1 ) {			// --program over rides configuration option.
	   fifoi = 1; 
	   } else { 
	   fifoi = 0;
	   }
        }

        if (!strcmp(sagan_var, "RULE_PATH" )) {
           snprintf(rule_path, sizeof(rule_path), "%s", strtok_r(NULL, " ", &tok));
           rule_path[strlen(rule_path)-1] = '\0'; }
        }

     /* "include */

     if (!strcmp(sagan_option, "include" )) {

         snprintf(tmpstring, sizeof(tmpstring), "%s", strtok_r(NULL, " ", &tok));

         tmpstring[strlen(tmpstring)-1] = '\0';

         strlcpy(ruleset, replace_str(tmpstring, "$RULE_PATH", rule_path), sizeof(ruleset));

         if (!strcmp(rulesetptr, "/classification.config") || !strcmp(rulesetptr, "classification.config" ))
            {
                    load_classifications();
            }

         if (!strcmp(rulesetptr, "/reference.config") || !strcmp(rulesetptr, "reference.config" ))
            {
                    load_reference();
            }
      if (strcmp(rulesetptr, "/reference.config") && strcmp(rulesetptr, "reference.config" ) &&
          strcmp(rulesetptr, "/classification.config") && strcmp(rulesetptr, "classification.config" ))  {
                   load_rules();
          }
     }
}

/* Check rules for duplicate sid.  We can't have that! */

for (i = 0; i < rulecount; i++) {
   for ( check = i+1; check < rulecount; check ++) {
       if (!strcmp (rulestruct[check].s_sid, rulestruct[i].s_sid ))
            sagan_log(1, "[%s, line %d] Detected duplicate signature id [sid] number %s.  Please correct this.", __FILE__, __LINE__, rulestruct[check].s_sid, rulestruct[i].s_sid);
       }
   }

}

