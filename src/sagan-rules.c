/*
** Copyright (C) 2009-2011 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2011 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-rules.c 
 *
 * Loads and parses the rule files into memory 
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
#include <pcre.h>

#include "version.h"

#include "sagan.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _SaganCounters *counters;

#ifdef HAVE_LIBLOGNORM
struct liblognorm_struct *liblognormstruct;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;
#endif

struct rule_struct *rulestruct;
struct class_struct *classstruct;

void load_rules( const char *ruleset ) { 

const char *error;
int erroffset;

FILE *rulesfile;

char *rulestring;
char *netstring; 

char *tokenrule;
char *tokennet;
char *rulesplit;
char *arg;
char *saveptrnet;
char *saveptrrule1;
char *saveptrrule2;
char *saveptrrule3;
char *tmptoken;
char *threshold_tmp;
char *thresh_tmp;

char netstr[RULEBUF];
char rulestr[RULEBUF];
char rulebuf[RULEBUF];
char pcrerule[RULEBUF];
char tmp2[512];
char tmp[2];

int linecount=0;
int netcount=0;
int ref_count=0;
int content_count=0;
int pcre_count=0;
sbool pcreflag=0;
int pcreoptions=0;

int i=0;
int a=0;

int forward=0;
int reverse=0;

/* Rule vars */

int ip_proto=0;
int dst_port=0;

#ifdef HAVE_LIBLOGNORM
sbool liblognorm_flag=0;
#endif

if (( rulesfile = fopen(ruleset, "r" )) == NULL ) {
   sagan_log(1, "[%s, line %d] Cannot open rule file (%s)", __FILE__, __LINE__, ruleset);
   }

sagan_log(0, "Loading %s rule file", ruleset);

while (fgets(rulebuf, sizeof(rulebuf), rulesfile) != NULL ) {
		   
	linecount++;
   
	if (rulebuf[0] == '#' || rulebuf[0] == 10 || rulebuf[0] == ';' || rulebuf[0] == 32) { 
        continue;
        } else { 
	/* Allocate memory for rules, but not comments */
	rulestruct = (rule_struct *) realloc(rulestruct, (counters->rulecount+1) * sizeof(rule_struct));
	}

remrt(rulebuf);

/* Parse forward for the first '(' */

for (i=0; i<strlen(rulebuf); i++) {
    if ( rulebuf[i] == '(' ) {
       forward=i; break;
       }
}

/* Parse reverse for the first ')' */

for (i=strlen(rulebuf); i>0; i--) {
    if ( rulebuf[i] == ')' ) {
       reverse=i; break;
       }
}

/* Get rule structure,  minus the ( ) */

for (i=forward+1; i<reverse; i++) {
    snprintf(tmp, sizeof(tmp), "%c", rulebuf[i]);
    strlcat(rulestr, tmp, sizeof(rulestr));
}

/* Get the network information, before the rule */

for (i=0; i<forward; i++) { 
    snprintf(tmp, sizeof(tmp), "%c", rulebuf[i]);
    strlcat(netstr, tmp, sizeof(netstr)); 
}

/* Assign pointer's to values */

netstring = netstr;
rulestring = rulestr;


/****************************************************************************/
/* Parse the section _before_ the rule set.  This is stuff like $HOME_NET,  */
/* $EXTERNAL_NET, etc                                                       */
/****************************************************************************/

tokennet = strtok_r(netstring, " ", &saveptrnet);
while ( tokennet != NULL ) {

   if ( netcount == 0 ) { 
      if (!strcmp(tokennet, "drop" )) 
         { 
	 rulestruct[counters->rulecount].drop = 1; 
	 } else {
	 rulestruct[counters->rulecount].drop = 0;
	 }
       }

   /* Protocol */
   if ( netcount == 1 ) { 
      ip_proto = config->sagan_proto;
      if (!strcmp(tokennet, "icmp" )) ip_proto = 1; 
      if (!strcmp(tokennet, "tcp"  )) ip_proto = 6;
      if (!strcmp(tokennet, "udp"  )) ip_proto = 17;
      }

      rulestruct[counters->rulecount].ip_proto = ip_proto;

   /* Destination Port */
   if ( netcount == 6 ) { 
      dst_port = config->sagan_port;
      if (strcmp(tokennet, "any")) dst_port = atoi(tokennet); 
      }
      
      rulestruct[counters->rulecount].dst_port = dst_port; 

   tokennet = strtok_r(NULL, " ", &saveptrnet);
   netcount++;
}


/*****************************************************************************/
/* Parse the rule set!                                                       */
/*****************************************************************************/


tokenrule = strtok_r(rulestring, ";", &saveptrrule1);

while ( tokenrule != NULL ) {

rulesplit = strtok_r(tokenrule, ":", &saveptrrule2);
remspaces(rulesplit);

	/* single flag options.  (nocase, find_port, etc) */

	if (!strcmp(rulesplit, "nocase")) { 
	       strtok_r(NULL, ":", &saveptrrule2);
	       rulestruct[counters->rulecount].s_nocase = 1;
	       }


        if (!strcmp(rulesplit, "parse_port")) {
               strtok_r(NULL, ":", &saveptrrule2);
               rulestruct[counters->rulecount].s_find_port = 1;
               }

        if (!strcmp(rulesplit, "parse_ip")) {
               strtok_r(NULL, ":", &saveptrrule2);
               rulestruct[counters->rulecount].s_find_ip = 1;
               }

	/* Non-quoted information (sid, reference, etc) */

	if (!strcmp(rulesplit, "rev" )) {
		arg = strtok_r(NULL, ":", &saveptrrule2);
		if (arg == NULL ) sagan_log(1, "The \"rev\" appears to be incomplete");
		snprintf(rulestruct[counters->rulecount].s_rev, sizeof(rulestruct[counters->rulecount].s_rev), "%s", remspaces(arg));
		}

	if (!strcmp(rulesplit, "classtype" )) { 
	        arg = strtok_r(NULL, ":", &saveptrrule2);
		if (arg == NULL ) sagan_log(1, "The \"classtype\" appears to be incomplete");
		snprintf(rulestruct[counters->rulecount].s_classtype, sizeof(rulestruct[counters->rulecount].s_classtype), "%s", remspaces(arg));

		for(i=0; i < counters->classcount; i++) {
			if (!strcmp(classstruct[i].s_shortname, rulestruct[counters->rulecount].s_classtype)) {
				rulestruct[counters->rulecount].s_pri = classstruct[i].s_priority;
                                }
                        }
		}
	
	if (!strcmp(rulesplit, "program" )) { 
		arg = strtok_r(NULL, ":", &saveptrrule2);
		if (arg == NULL ) sagan_log(1, "The \"program\" appears to be incomplete");
		snprintf(rulestruct[counters->rulecount].s_program, sizeof(rulestruct[counters->rulecount].s_program), "%s", remspaces(arg));
		}

	if (!strcmp(rulesplit, "reference" )) {
	 	arg = strtok_r(NULL, ":", &saveptrrule2);
		if (arg == NULL ) sagan_log(1, "The \"reference\" appears to be incomplete");
		snprintf(rulestruct[counters->rulecount].s_reference[ref_count], sizeof(rulestruct[counters->rulecount].s_reference[ref_count]), "%s", remspaces(arg));
		rulestruct[counters->rulecount].ref_count=ref_count;
		ref_count++;
		}

	if (!strcmp(rulesplit, "sid" )) { 
	        arg = strtok_r(NULL, ":", &saveptrrule2);
		if (arg == NULL ) sagan_log(1, "The \"sid\" appears to be incomplete");
		snprintf(rulestruct[counters->rulecount].s_sid, sizeof(rulestruct[counters->rulecount].s_sid), "%s", remspaces(arg));
		}
	
        if (!strcmp(rulesplit, "tag" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);
                if (arg == NULL ) sagan_log(1, "The \"tag\" appears to be incomplete");
                snprintf(rulestruct[counters->rulecount].s_tag, sizeof(rulestruct[counters->rulecount].s_tag), "%s", remspaces(arg));
                }

        if (!strcmp(rulesplit, "facility" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);
                if (arg == NULL ) sagan_log(1, "The \"facility\" appears to be incomplete");
                snprintf(rulestruct[counters->rulecount].s_facility, sizeof(rulestruct[counters->rulecount].s_facility), "%s", remspaces(arg));
                }

        if (!strcmp(rulesplit, "level" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);
                if (arg == NULL ) sagan_log(1, "The \"level\" appears to be incomplete");
                snprintf(rulestruct[counters->rulecount].s_level, sizeof(rulestruct[counters->rulecount].s_level), "%s", remspaces(arg));
                }


        if (!strcmp(rulesplit, "pri" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);
                if (arg == NULL ) sagan_log(1, "The \"priority\" appears to be incomplete");
		remspaces(arg);
		rulestruct[counters->rulecount].s_pri = atoi(arg);
                }

#ifdef HAVE_LIBESMTP
	
	if (!strcmp(rulesplit, "email" )) { 
		arg = strtok_r(NULL, " ", &saveptrrule2);
		if (arg == NULL ) sagan_log(1, "The \"email\" appears to be incomplete");
	        if (!strcmp(config->sagan_esmtp_server, "" )) sagan_log(1, "[%s, line %d] Line %d of %s has the \"email:\" option,  but no SMTP server is specified in the %s", __FILE__, __LINE__, linecount, ruleset, config->sagan_config);
		snprintf(rulestruct[counters->rulecount].email, sizeof(rulestruct[counters->rulecount].email), "%s", remspaces(arg));
		rulestruct[counters->rulecount].email_flag=1; 
		config->sagan_esmtp_flag=1;
		}
#endif

#ifdef HAVE_LIBLOGNORM
	
	if (!strcmp(rulesplit, "normalize" )) { 
		rulestruct[counters->rulecount].normalize = 1; 
		arg = strtok_r(NULL, ":", &saveptrrule2);
		if (arg == NULL ) sagan_log(1, "The \"normalize\" appears to be incomplete");
		remspaces(arg);

		/* Search for a normalize rule that fits the rule set's spec */

		for (i=0; i < liblognorm_count; i++) { 
		    if (!strcmp(liblognormstruct[i].type, arg )) { 

			liblognorm_flag=1;
			
		    	for (a=0; a < counters->liblognormtoload_count; a++) { 
			    if (!strcmp(liblognormstruct[i].type, liblognormtoloadstruct[a].type )) liblognorm_flag=0;
			}

			if ( liblognorm_flag == 1 ) { 
			   liblognormtoloadstruct = (liblognorm_toload_struct *) realloc(liblognormtoloadstruct, (counters->liblognormtoload_count+1) * sizeof(liblognorm_toload_struct));
			   snprintf(liblognormtoloadstruct[counters->liblognormtoload_count].type, sizeof(liblognormtoloadstruct[counters->liblognormtoload_count].type), "%s",  liblognormstruct[i].type);
			   snprintf(liblognormtoloadstruct[counters->liblognormtoload_count].filepath, sizeof(liblognormtoloadstruct[counters->liblognormtoload_count].filepath), "%s",  liblognormstruct[i].filepath);
			   counters->liblognormtoload_count++;
			}

		}
	        
	}
}

#endif

	/* Quoted information (content, pcre, msg)  */ 

        if (!strcmp(rulesplit, "msg" )) {
                arg = strtok_r(NULL, ";", &saveptrrule2);
		strlcpy(tmp2, betweenquotes(arg), sizeof(tmp2));
		if (tmp2 == NULL ) sagan_log(1, "The \"msg\" appears to be incomplete");
                snprintf(rulestruct[counters->rulecount].s_msg, sizeof(rulestruct[counters->rulecount].s_msg), "%s", tmp2);
                }

	if (!strcmp(rulesplit, "content" )) { 
		if ( content_count > MAX_CONTENT ) sagan_log(1, "There is to many \"content\" types in the rule");
		arg = strtok_r(NULL, ";", &saveptrrule2);
		strlcpy(tmp2, betweenquotes(arg), sizeof(tmp2));
		if (tmp2 == NULL ) sagan_log(1, "The \"content\" appears to be incomplete");
		snprintf(rulestruct[counters->rulecount].s_content[content_count], sizeof(rulestruct[counters->rulecount].s_content[content_count]), "%s", tmp2);
		content_count++;
		rulestruct[counters->rulecount].content_count=content_count;
		}


	/* PCRE needs a little extra "work" */

        if (!strcmp(rulesplit, "pcre" )) {
                if ( pcre_count > MAX_PCRE ) sagan_log(1, "There is to many \"pcre\" types in the rule");
		arg = strtok_r(NULL, ";", &saveptrrule2);
		strlcpy(tmp2, betweenquotes(arg), sizeof(tmp2));
                if (tmp2 == NULL ) sagan_log(1, "The \"pcre\" appears to be incomplete");

		pcreflag=0;
		strlcpy(pcrerule, "", sizeof(pcrerule));
		for ( i = 1; i < strlen(tmp2); i++) {
			
			if ( tmp2[i] == '/' && tmp2[i-1] != '\\' ) pcreflag++;
			
			if ( pcreflag == 0 ) { 
			snprintf(tmp, sizeof(tmp), "%c", tmp2[i]);
			strlcat(pcrerule, tmp, sizeof(pcrerule));
			}

			/* are we /past/ and at the args? */

			if ( pcreflag == 1 ) { 
			switch(tmp2[i]) {
		          case 'i':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_CASELESS; break;
                          case 's':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_DOTALL; break;
                          case 'm':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_MULTILINE; break;
                          case 'x':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_EXTENDED; break;
                          case 'A':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_ANCHORED; break;
                          case 'E':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_DOLLAR_ENDONLY; break;
                          case 'G':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_UNGREEDY; break;

                        /* PCRE options that aren't really used? */

                        /*
                          case 'f':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_FIRSTLINE; break;
                          case 'C':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_AUTO_CALLOUT; break;
                          case 'J':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_DUPNAMES; break;
                          case 'N':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_NO_AUTO_CAPTURE; break;
                          case 'X':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_EXTRA; break;
                          case '8':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_UTF8; break;
                          case '?':
                                if ( pcreflag == 1 ) pcreoptions |= PCRE_NO_UTF8_CHECK; break;
                                */
			
                            }
			}
		    }
		      
                      if ( pcreflag == 0 ) sagan_log(1, "[%s, line %d] Missing last '/' in pcre: %s at line %d", __FILE__, __LINE__, ruleset, linecount);

		      /* We store the compiled/study results.  This saves use some CPU tmpe during searching - Champ Clark III - 02/01/2011 */
		      
		      rulestruct[counters->rulecount].re_pcre[pcre_count] =  pcre_compile( pcrerule, pcreoptions, &error, &erroffset, NULL );
		      rulestruct[counters->rulecount].pcre_extra[pcre_count] = pcre_study( rulestruct[counters->rulecount].re_pcre[pcre_count], pcreoptions, &error);
		      
	                if (  rulestruct[counters->rulecount].re_pcre[pcre_count]  == NULL ) {
       		         removelockfile();
                 	 sagan_log(1, "[%s, line %d] PCRE failure at %d: %s", __FILE__, __LINE__, erroffset, error);
                	}

		      pcre_count++;
		      rulestruct[counters->rulecount].pcre_count=pcre_count;
                }


	if (!strcmp(rulesplit, "threshold" )) {
		threshold_tmp = strtok_r(NULL, ":", &saveptrrule2);
                tmptoken = strtok_r(threshold_tmp, ",", &saveptrrule2);

                      while( tmptoken != NULL ) {
                      if (strstr(tmptoken, "type")) {
                            if (strstr(tmptoken, "limit")) rulestruct[counters->rulecount].threshold_type = 1;
                            if (strstr(tmptoken, "threshold")) rulestruct[counters->rulecount].threshold_type = 2;
                            }

                      if (strstr(tmptoken, "track")) {
                            if (strstr(tmptoken, "by_src")) rulestruct[counters->rulecount].threshold_src_or_dst = 1;
                            if (strstr(tmptoken, "by_dst")) rulestruct[counters->rulecount].threshold_src_or_dst = 2;
                            }

                      if (strstr(tmptoken, "count")) {
                           thresh_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                           thresh_tmp = strtok_r(NULL, " ", &saveptrrule3);
                           rulestruct[counters->rulecount].threshold_count = atoi(thresh_tmp);
                           }

                      if (strstr(tmptoken, "seconds")) {
                           thresh_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                           thresh_tmp = strtok_r(NULL, " ", &saveptrrule3 );
                           rulestruct[counters->rulecount].threshold_seconds = atoi(thresh_tmp);
                           }

                        tmptoken = strtok_r(NULL, ",", &saveptrrule2);
		}
	}




tokenrule = strtok_r(NULL, ";", &saveptrrule1);
}

/* Some new stuff (normalization) stuff needs to be added */

if ( debug->debugload ) { 

sagan_log(0, "---[Rule %s]------------------------------------------------------\n", rulestruct[counters->rulecount].s_sid);

sagan_log(0, "= sid: %s", rulestruct[counters->rulecount].s_sid);
sagan_log(0, "= rev: %s", rulestruct[counters->rulecount].s_rev);
sagan_log(0, "= msg: %s", rulestruct[counters->rulecount].s_msg);
sagan_log(0, "= pri: %d", rulestruct[counters->rulecount].s_pri);
sagan_log(0, "= classtype: %s", rulestruct[counters->rulecount].s_classtype);
sagan_log(0, "= drop: %d", rulestruct[counters->rulecount].drop);

if ( rulestruct[counters->rulecount].s_nocase != 0 )    sagan_log(0, "= nocase");
if ( rulestruct[counters->rulecount].s_find_ip != 0 )   sagan_log(0, "= parse_ip");
if ( rulestruct[counters->rulecount].s_find_port != 0 ) sagan_log(0, "= parse_port");

for (i=0; i<content_count; i++) {
    sagan_log(0, "= [%d] content: %s", i, rulestruct[counters->rulecount].s_content[i]);
    }

for (i=0; i<ref_count; i++) {
    sagan_log(0, "= [%d] reference: %s", i,  rulestruct[counters->rulecount].s_reference[i]);
    }
}

/* Reset for next rule */

pcre_count=0;
content_count=0;
netcount=0;
ref_count=0;
strlcpy(netstr, "", 1);
strlcpy(rulestr, "", 1);
counters->rulecount++;

} /* end of while loop */

fclose(rulesfile);
}
