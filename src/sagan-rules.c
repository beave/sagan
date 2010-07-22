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

char *msg=NULL;
char *pcrerule=NULL;

char *content=NULL;
char *reference=NULL;
char *classtype="";
char *sid=NULL;
char *rev=NULL;
char *pri=NULL;
char *program=NULL;
char *facility=NULL;
char *syspri=NULL;
char *level=NULL;
char *tag=NULL;
int dst_port;
int ip_proto;
int sagan_proto;

char *defaultpri;

int rulecount;
int devdebug;
char sagan_port[6];

struct rule_struct *rulestruct;

char ruleset[MAXPATH];

void load_rules( void ) { 

	FILE *rulesfile;

	char *token;
	char *tmptoken;
	char rulebuf[RULEBUF];
	char *firststring=NULL;
	char *netstring=NULL;
	char *laststring=NULL;
	char *saveptr1=NULL;
	char *saveptr2=NULL;
	char *saveptr3=NULL;
	char *str1=NULL;
	char *threshold_tmp;
	char *thresh_tmp;

	char tmptoken2[128];

	int find_port=0;
	int nocase=0;

        int i;
	int pcre_count=0;
	char tmp[10];
	char *pcretmp;
	char pcretmp2[1024]="";
	int pcreoptions=0;
	int pcreflag;
	int content_count=0;
	int linecount=0;
	int ref_count=0;

         if (( rulesfile = fopen(ruleset, "r" )) == NULL ) {
            sagan_log(1, "[%s, line %d] Cannot open rule file (%s)", __FILE__, __LINE__, ruleset);
          }

         sagan_log(0, "Loading %s rule file", ruleset);

                while (fgets(rulebuf, sizeof(rulebuf), rulesfile) != NULL ) {
                   {
		   linecount++;
		   
		   if (rulebuf[0] == '#' || rulebuf[0] == 10 || rulebuf[0] == ';' || rulebuf[0] == 32) { 
		       continue;
		       } else { 
		       /* Allocate memory for rules, but not comments */
		       rulestruct = (rule_struct *) realloc(rulestruct, (rulecount+1) * sizeof(rule_struct));
		       }

                   firststring = strtok_r(rulebuf, "(", &saveptr2);
                   tmptoken = strtok_r(NULL, "(" , &saveptr2);
                   laststring = strtok_r(tmptoken, ")", &saveptr2);

		   netstring = strtok_r(firststring, " ", &saveptr1);

                   classtype=""; pcrerule=""; reference=""; sid=""; rev=""; pri="";
                   program=""; facility=""; syspri=""; level=""; tag=""; content="";
		   dst_port = atoi(sagan_port);

		   /* We aren't using $HOME_NET (yet).  We do need port information, 
		    * so we move to that position - ie $HOME_NET 22, we need the
		    * port 22 */

		   for ( i = 0; i < 1; i++) { 
		   token = strtok_r(NULL, " ", &saveptr1);
		   }

		   if ( strcmp(token, "tcp") && strcmp(token, "udp" ) && strcmp(token, "icmp" ) ) 
		       {
		       ip_proto = sagan_proto; // Unknown? Got with default
		       } else {
		       if (!strcmp(token, "icmp")) ip_proto = 1;
		       if (!strcmp(token, "tcp")) ip_proto = 6;
		       if (!strcmp(token, "udp")) ip_proto = 17;
		       }

                   for ( i = 1; i < 6; i++) {
                   token = strtok_r(NULL, " ", &saveptr1);
                   }

		   if ( token == NULL ) sagan_log(1, "[%s, line %d] Destination port error on line number %d in %s.", __FILE__, __LINE__, linecount, ruleset);
		   if (strcmp(token, "any")) dst_port = atoi(token); // If not any, fill with value.

                   for(i = 0, str1 = laststring; ;i++, str1 = NULL )
                      {
                      if ( i == 0 ) { token = strtok_r(laststring, ";", &saveptr2); } else { token = strtok_r(NULL, ";", &saveptr2);
                      }
			

                   if ( token==NULL) break;

		   snprintf(tmptoken2, sizeof(tmptoken2), "%s", token);
		   remspaces(tmptoken2);

                   if ( strstr(tmptoken2, "find_port" )) find_port=1;
		   if ( strstr(tmptoken2, "nocase" )) nocase=1;


		   if ( strstr(tmptoken2, "msg:" )) { 
		      strtok_r(token, "\"", &saveptr1 ); 
		      msg = strtok_r(NULL, "\"", &saveptr1 ); 
		      remquotes(msg); 
		   }
                  
		   if ( strstr(tmptoken2, "pcre:" )) { 
		      strtok_r(token, "\"", &saveptr1);
		      pcretmp = strtok_r(NULL, "\"", &saveptr1);
		      //pcre[strlen(pcre)+1] = '\0';
		      remquotes(pcretmp); 
		      
		      if ( pcretmp[0] != '/' ) sagan_log(1, "[%s, line %d] Missing first '/' in pcre: %s at line %d", __FILE__, __LINE__, ruleset, linecount);

		      pcreflag=0;
		      strcpy(pcretmp2, "");
		      for ( i = 1; i < strlen(pcretmp); i++) {

		        if ( pcretmp[i] == '/' && pcretmp[i-1] != '\\' ) pcreflag++;

			if ( pcreflag == 0 ) { 
		        snprintf(tmp, sizeof(tmp), "%c", pcretmp[i]);
			strlcat(pcretmp2, tmp, sizeof(pcretmp2));
			}

			switch(pcretmp[i]) {
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

		      if ( pcreflag == 0 ) sagan_log(1, "[%s, line %d] Missing last '/' in pcre: %s at line %d", __FILE__, __LINE__, ruleset, linecount);

		      pcrerule = pcretmp2;

		      snprintf(rulestruct[rulecount].s_pcre[pcre_count], sizeof(rulestruct[rulecount].s_pcre[pcre_count]), "%s", pcrerule);
		      rulestruct[rulecount].s_pcreoptions[pcre_count] = pcreoptions;

		      pcre_count++;
		      if ( pcre_count > MAX_CONTENT ) sagan_log(1, "[%s, line %d] To many \"pcre:\" flags in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
		      rulestruct[rulecount].pcre_count=pcre_count;
		   }

		   if ( strstr(tmptoken2, "reference:" )) { 
		      strtok_r(token, ":", &saveptr1);
		      reference=strtok_r(NULL, ":", &saveptr1); 
		      remspaces(reference);
		      snprintf(rulestruct[rulecount].s_reference[ref_count], sizeof(rulestruct[rulecount].s_reference[ref_count]), "%s", reference);
		      ref_count++;
		      if ( ref_count > MAX_CONTENT ) sagan_log(1, "[%s, line %d] To many \"reference:\" flags in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
		      rulestruct[rulecount].ref_count=ref_count;
		   }

                   if ( strstr(tmptoken2, "classtype:" )) { strtok_r(token, ":", &saveptr1); classtype = strtok_r(NULL, ";", &saveptr1); remspaces(classtype); }
                   if ( strstr(tmptoken2, "sid:" )) { strtok_r(token, ":", &saveptr1); sid = strtok_r(NULL, ";", &saveptr1); remspaces(sid); }
                   if ( strstr(tmptoken2, "rev:" )) { strtok_r(token, ":", &saveptr1); rev = strtok_r(NULL, ";", &saveptr1); remspaces(rev); }
                   if ( strstr(tmptoken2, "pri:" )) { strtok_r(token, ":", &saveptr1); pri = strtok_r(NULL, ";", &saveptr1); remspaces(pri); }
                   if ( strstr(tmptoken2, "program:")) { strtok_r(token, ":", &saveptr1); program = strtok_r(NULL, ";", &saveptr1); remspaces(program); }
                   if ( strstr(tmptoken2, "facility:")) { strtok_r(token, ":", &saveptr1); facility = strtok_r(NULL, ";", &saveptr1); remspaces(facility); }

                   if ( strstr(tmptoken2, "content:" )) { 
		      strtok_r(token, "\"", &saveptr1);
		      content = strtok_r(NULL, "\"", &saveptr1);
		      remquotes(content); 
		      snprintf(rulestruct[rulecount].s_content[content_count], sizeof(rulestruct[rulecount].s_content[content_count]), "%s", content);
		      content_count++;
		      if ( content_count > MAX_CONTENT ) sagan_log(1, "[%s, line %d] To many \"content:\" flags in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
		      rulestruct[rulecount].content_count=content_count;
		      }

                   if ( strstr(tmptoken2, "level:" )) { strtok_r(token, ":", &saveptr1); level = strtok_r(NULL, ";", &saveptr1); remspaces(level); }
                   if ( strstr(tmptoken2, "tag:" )) { strtok_r(token, ":", &saveptr1); tag = strtok_r(NULL, ";", &saveptr1); remspaces(tag); }

		   if ( strstr(tmptoken2, "threshold:" )) 
		      { 
		      strtok_r(token, ":", &saveptr1); 
		      threshold_tmp = strtok_r(NULL, ";", &saveptr1); 
		      tmptoken = strtok_r(threshold_tmp, ",", &saveptr1); 
		      
		      while( tmptoken != NULL ) { 
		      if (strstr(tmptoken, "type")) { 
		            if (strstr(tmptoken, "limit")) rulestruct[rulecount].threshold_type = 1; 
			    if (strstr(tmptoken, "threshold")) rulestruct[rulecount].threshold_type = 2;
			    }

		      if (strstr(tmptoken, "track")) { 
		            if (strstr(tmptoken, "by_src")) rulestruct[rulecount].threshold_src_or_dst = 1; 
			    if (strstr(tmptoken, "by_dst")) rulestruct[rulecount].threshold_src_or_dst = 2;
			    }

		      if (strstr(tmptoken, "count")) { 
			   thresh_tmp = strtok_r(tmptoken, " ", &saveptr3);
			   thresh_tmp = strtok_r(NULL, " ", &saveptr3 );
			   rulestruct[rulecount].threshold_count = atoi(thresh_tmp);
			   }
 
                      if (strstr(tmptoken, "seconds")) { 
		           thresh_tmp = strtok_r(tmptoken, " ", &saveptr3);
			   thresh_tmp = strtok_r(NULL, " ", &saveptr3 );
			   rulestruct[rulecount].threshold_seconds = atoi(thresh_tmp);
			   }

		      tmptoken = strtok_r(NULL, ",", &saveptr1);
		      }
		     }
                    }

		   
                   if ( pri == NULL || !strcmp(pri, "") ) pri=defaultpri;

                   snprintf(rulestruct[rulecount].s_msg, sizeof(rulestruct[rulecount].s_msg), "%s", msg);
                   snprintf(rulestruct[rulecount].s_classtype, sizeof(rulestruct[rulecount].s_classtype), "%s", classtype);
                   snprintf(rulestruct[rulecount].s_sid, sizeof(rulestruct[rulecount].s_sid), "%s", sid);
                   snprintf(rulestruct[rulecount].s_rev, sizeof(rulestruct[rulecount].s_rev), "%s", rev);
                   snprintf(rulestruct[rulecount].s_pri, sizeof(rulestruct[rulecount].s_pri), "%s", pri);
                   snprintf(rulestruct[rulecount].s_program, sizeof(rulestruct[rulecount].s_program), "%s", program);
                   snprintf(rulestruct[rulecount].s_facility, sizeof(rulestruct[rulecount].s_facility), "%s", facility);
                   snprintf(rulestruct[rulecount].s_level, sizeof(rulestruct[rulecount].s_level), "%s", level);
                   snprintf(rulestruct[rulecount].s_tag, sizeof(rulestruct[rulecount].s_tag), "%s", tag);
		   rulestruct[rulecount].dst_port = dst_port;
                   rulestruct[rulecount].s_nocase = nocase;
		   rulestruct[rulecount].ip_proto = ip_proto;
		   rulestruct[rulecount].s_find_port = find_port;

		   /* Minium for a rule to be a rule */
		  
		   if (!strcmp(sid,  "" )) sagan_log(1, "[%s, line %d] Error at line number %d in %s [missing sid:]", __FILE__, __LINE__, linecount, ruleset);
		   if (!strcmp(content, "") && !strcmp(pcrerule, "") ) sagan_log(1, "[%s, line %d] Error at line number %d in %s [missing pcre: and/or content:]", __FILE__, __LINE__, linecount, ruleset);

		   if (!strcmp(msg, "")) sagan_log(1, "[%s, line %d] Error at line number %d in %s [missing msg:]", __FILE__, __LINE__, linecount, ruleset);

                   if (devdebug == 1) {
                           printf("\n[D-%d] msg: %s\n", rulecount, rulestruct[rulecount].s_msg);

			   for (i=0; i<pcre_count; i++) { 
                           printf("pcre: |%s|\n", rulestruct[rulecount].s_pcre[i]);
			   }

			   for (i=0; i<content_count; i++) { 
			   printf("content: |%s|\n", rulestruct[rulecount].s_content[i]);
			   }

			   for (i=0; i<ref_count; i++) { 
			   printf("reference: %s\n", rulestruct[rulecount].s_reference[i]);
			   }

                           printf("classtype: %s\n", rulestruct[rulecount].s_classtype);
                           printf("sid: |%s|\n", rulestruct[rulecount].s_sid);
                           printf("rev: %s\n", rulestruct[rulecount].s_rev);
                           printf("nocase: %d\n", rulestruct[rulecount].s_nocase);
			   printf("find_port: %d\n", rulestruct[rulecount].s_find_port);
                           printf("pri: %s\n", rulestruct[rulecount].s_pri);
                           printf("program: |%s|\n", rulestruct[rulecount].s_program);
			   printf("facility: %s\n", rulestruct[rulecount].s_facility);
			   printf("level: %s\n", rulestruct[rulecount].s_level);
			   printf("tag: %s\n", rulestruct[rulecount].s_tag);
			   printf("dst_port: %d\n", rulestruct[rulecount].dst_port);
			   printf("ip_proto: %d\n", rulestruct[rulecount].ip_proto);
			   printf("ref_count: %d\n", rulestruct[rulecount].ref_count);
			   printf("threshold_type: %d\n", rulestruct[rulecount].threshold_type);
			   printf("threshold_src_dst: %d\n", rulestruct[rulecount].threshold_src_or_dst);
			   printf("threshold_count: %d\n", rulestruct[rulecount].threshold_count);
			   printf("threshold_seconds: %d\n", rulestruct[rulecount].threshold_seconds);
			   

                           }

                   pri=NULL;
                   rulecount++;

                   }
		   pcre_count=0;
		   content_count=0;
		   ref_count=0;
		   find_port=0;
		   nocase=0;

                }

fclose(rulesfile);
}
