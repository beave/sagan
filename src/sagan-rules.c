/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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
#include "sagan-defs.h"

#include "sagan-xbit.h"
#include "sagan-lockfile.h"
#include "sagan-classifications.h"
#include "sagan-rules.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

#ifdef WITH_BLUEDOT
#include "processors/sagan-bluedot.h"
#endif

struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;

#ifdef WITH_BLUEDOT

struct _Sagan_Bluedot_Cat_List *SaganBluedotCatList;

char *bluedot_time = NULL;
char *bluedot_type = NULL;

uintmax_t bluedot_time_u32 = 0;

#endif

#ifdef HAVE_LIBLOGNORM
#include "sagan-liblognorm.h"
struct liblognorm_struct *liblognormstruct;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;
#endif

/* For pre-8.20 PCRE compatibility */
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

struct _Rule_Struct *rulestruct;
struct _Class_Struct *classstruct;

void Load_Rules( const char *ruleset )
{

    struct stat filecheck;

    sbool found = 0;

    const char *error;
    int erroffset;

    FILE *rulesfile;
    char ruleset_fullname[MAXPATH];

    char *rulestring;
    char *netstring;
    char *nettmp = NULL;

    char tolower_tmp[512];

    char *tokenrule;
    char *tokennet;
    char *rulesplit;
    char *arg;
    char *saveptrnet;
    char *saveptrrule1;
    char *saveptrrule2;
    char *saveptrrule3=NULL;
    char *saveptrflow;
    char *saveptrrange;
    char *tmptoken;
    char *not;
    char *savenot=NULL;

    char *tok_tmp;
    char *tmptok_tmp;
    char *ptmp=NULL;
    char *tok = NULL;

    uintmax_t fwsam_time_tmp;

    char netstr[512];
    char rulestr[RULEBUF];
    char rulebuf[RULEBUF];
    char pcrerule[MAX_PCRE_SIZE];

    char tmp3[MAX_CHECK_FLOWS * 21];
    char tmp2[RULEBUF];
    char tmp[2];
    char final_content[512];
    char *flow_a;
    char *flow_b;
    char *flow_range;

    char alert_time_tmp[10];
    char alert_tmp_minute[3];
    char alert_tmp_hour[3];
    char alert_time_all[5];

    int linecount=0;
    int netcount=0;
    int ref_count=0;

    int content_count=0;
    int meta_content_count=0;
    int meta_content_converted_count=0;
    int pcre_count=0;
    int xbit_count;
    int flow_1_count=0;
    int flow_2_count=0;

    sbool pcreflag=0;
    int pcreoptions=0;

    int i=0;
    int d;

    int rc=0;

    int forward=0;
    int reverse=0;

    /* Rule vars */

    int ip_proto=0;
    int dst_port=0;
    int src_port=0;

    /* Store rule set names/path in memory for later usage dynamic loading, etc */

    strlcpy(ruleset_fullname, ruleset, sizeof(ruleset_fullname));

    if (( rulesfile = fopen(ruleset_fullname, "r" )) == NULL ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Cannot open rule file (%s - %s)", __FILE__, __LINE__, ruleset_fullname, strerror(errno));
    }

    Sagan_Log(S_NORMAL, "Loading %s rule file.", ruleset_fullname);

    while (fgets(rulebuf, sizeof(rulebuf), rulesfile) != NULL ) {

        int f1=0; /* Need for flow_direction, must reset every rule, not every group */
        int f2=0; /* Need for flow_direction, must reset every rule, not every group */

        linecount++;

        if (rulebuf[0] == '#' || rulebuf[0] == 10 || rulebuf[0] == ';' || rulebuf[0] == 32) {

            continue;

        } else {

            /* Allocate memory for rules, but not comments */

            rulestruct = (_Rule_Struct *) realloc(rulestruct, (counters->rulecount+1) * sizeof(_Rule_Struct));

            if ( rulestruct == NULL ) {
                Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for rulestruct. Abort!", __FILE__, __LINE__);
            }

        }

        Remove_Return(rulebuf);

        /****************************************/
        /* Some really basic rule sanity checks */
        /****************************************/

        if (!strchr(rulebuf, ';') || !strchr(rulebuf, ':') ||
            !strchr(rulebuf, '(') || !strchr(rulebuf, ')')) {
            Sagan_Log(S_ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.", __FILE__, __LINE__, ruleset_fullname, linecount);
        }

        if (!Sagan_strstr(rulebuf, "sid:")) {
            Sagan_Log(S_ERROR, "[%s, line %d] %s on line %d appears to not have a 'sid'", __FILE__, __LINE__, ruleset_fullname, linecount);
        }

        if (!Sagan_strstr(rulebuf, "rev:")) {
            Sagan_Log(S_ERROR, "[%s, line %d] %s on line %d appears to not have a 'rev'", __FILE__, __LINE__, ruleset_fullname, linecount);
        }

        if (!Sagan_strstr(rulebuf, "msg:")) {
            Sagan_Log(S_ERROR, "[%s, line %d] %s on line %d appears to not have a 'msg'", __FILE__, __LINE__, ruleset_fullname, linecount);
        }


        rc=0;

        if (!Sagan_strstr(rulebuf, "alert")) {
            rc++;
        }

        if (!Sagan_strstr(rulebuf, "drop")) {
            rc++;
        }

        if ( rc == 2 ) {
            Sagan_Log(S_ERROR, "[%s, line %d] %s on line %d appears to not have a 'alert' or 'drop'", __FILE__, __LINE__, ruleset_fullname, linecount);
        }

        rc=0;

        if (!Sagan_strstr(rulebuf, "tcp")) {
            rc++;
        }

        if (!Sagan_strstr(rulebuf, "udp")) {
            rc++;
        }

        if (!Sagan_strstr(rulebuf, "icmp")) {
            rc++;
        }

        if (!Sagan_strstr(rulebuf, "syslog")) {
            rc++;
        }

        if ( rc == 4 ) {
            Sagan_Log(S_ERROR, "[%s, line %d] %s on line %d appears to not have a protocol type (tcp/udp/icmp/syslog)", __FILE__, __LINE__, ruleset_fullname, linecount);
        }

        /* Parse forward for the first '(' */

        for (i=0; i<strlen(rulebuf); i++) {
            if ( rulebuf[i] == '(' ) {
                forward=i;
                break;
            }
        }

        /* Parse reverse for the first ')' */

        for (i=strlen(rulebuf); i>0; i--) {
            if ( rulebuf[i] == ')' ) {
                reverse=i;
                break;
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
                if (!strcmp(tokennet, "drop" )) {
                    rulestruct[counters->rulecount].drop = 1;
                } else {
                    rulestruct[counters->rulecount].drop = 0;
                }
            }

            /* Protocol */
            if ( netcount == 1 ) {
                ip_proto = config->sagan_proto;
                if (!strcmp(tokennet, "icmp" )) {
                    ip_proto = 1;
                }

                if (!strcmp(tokennet, "tcp"  )) {
                    ip_proto = 6;
                }

                if (!strcmp(tokennet, "udp"  )) {
                    ip_proto = 17;
                }
            }

            rulestruct[counters->rulecount].ip_proto = ip_proto;

            /* First flow */
            if ( netcount == 2 ) {
                flow_a = Remove_Spaces(Sagan_Var_To_Value(tokennet));
                if (!strcmp(flow_a, "any") || !strcmp(flow_a, Remove_Spaces(tokennet))) {
                    rulestruct[counters->rulecount].flow_1_var = 0;	  /* 0 = any */
                } else {
                    strlcpy(tmp3, flow_a, sizeof(tmp3));
                    for(tmptoken = strtok_r(tmp3, ",", &saveptrflow); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrflow)) {
                        if(!Is_IP(Strip_Chars(tmptoken, "not!"))) {
                            Sagan_Log(S_WARN,"[%s, line %d] Value is not a valid IP '%s'", __FILE__, __LINE__, tmptoken);
                        }
                        f1++;
                        if(strchr(tmptoken, '/')) {
                            if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3)) {
                                flow_range = Netaddr_To_Range(Strip_Chars(tmptoken, "not!"));

                                if(strchr(flow_range, '-')) {
                                    rulestruct[counters->rulecount].flow_1[flow_1_count].lo = atol(strtok_r(flow_range, "-", &saveptrrange));
                                    rulestruct[counters->rulecount].flow_1[flow_1_count].hi = atol(strtok_r(NULL, "-", &saveptrrange));
                                    rulestruct[counters->rulecount].flow_1_type[f1] = 0; /* 0 = not in group */
                                } else {
                                    rulestruct[counters->rulecount].flow_1[flow_1_count].lo = atol(flow_range);
                                    rulestruct[counters->rulecount].flow_1_type[f1] = 2; /* This was a /32, not a range */
                                }
                            } else {
                                flow_range = Netaddr_To_Range(tmptoken);
                                if(strchr(flow_range, '-')) {
                                    rulestruct[counters->rulecount].flow_1[flow_1_count].lo = atol(strtok_r(flow_range, "-", &saveptrrange));
                                    rulestruct[counters->rulecount].flow_1[flow_1_count].hi = atol(strtok_r(NULL, "-", &saveptrrange));
                                    rulestruct[counters->rulecount].flow_1_type[f1] = 1; /* 1 = in group */
                                } else {
                                    rulestruct[counters->rulecount].flow_1[flow_1_count].lo = atol(flow_range);
                                    rulestruct[counters->rulecount].flow_1_type[f1] = 3; /* This was a /32, not a range */
                                }
                            }
                        } else {
                            if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3)) {
                                rulestruct[counters->rulecount].flow_1_type[f1] = 2; /* 2 = not match ip */
                                rulestruct[counters->rulecount].flow_1[flow_1_count].lo = IP2Bit(Strip_Chars(tmptoken, "not!"));
                            } else {
                                rulestruct[counters->rulecount].flow_1_type[f1] = 3; /* 3 = match ip */
                                rulestruct[counters->rulecount].flow_1[flow_1_count].lo = IP2Bit(tmptoken);
                            }
                        }
                        flow_1_count++;
                        if( flow_1_count > 49 ) {
                            Sagan_Log(S_ERROR,"[%s, line %d] You have exceeded the amount of IP's for flow_1 '50'.", __FILE__, __LINE__);
                        }
                    }
                    rulestruct[counters->rulecount].flow_1_var = 1;   /* 1 = var */
                    rulestruct[counters->rulecount].flow_1_counter = flow_1_count;
                }
            }

            /* Source Port */
            if ( netcount == 3 ) {

                src_port = config->sagan_port;                            /* Set to default */

                if (strcmp(nettmp, "any")) {
                    src_port = atoi(nettmp);       /* If it's _NOT_ "any", set to default */
                }

                if (Is_Numeric(nettmp)) {
                    src_port = atoi(nettmp);          /* If it's a number (see Sagan_Var_To_Value),  then set to that */
                }

                if ( src_port == 0 ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Invalid source port on line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].src_port = src_port;      /* Set for the rule */
            }

            /* Direction */
            if ( netcount == 4 ) {

                if ( !strcmp(tokennet, "->") ) {
                    d = 1;  /* 1 = right */
                } else if( !strcmp(tokennet, "<>") || !strcmp(tokennet, "any") || !strcmp(tokennet, "<->") ) {
                    d = 0;  /* 0 = any */
                } else if( !strcmp(tokennet, "<-") ) {
                    d = 2;  /* 2 = left */
                } else {
                    d = 0;  /* 0 = any */
                }
                rulestruct[counters->rulecount].direction = d;
            }

            /* Second flow */
            if ( netcount == 5 ) {
                flow_b = Remove_Spaces(Sagan_Var_To_Value(tokennet));
                if (!strcmp(flow_b, "any") || !strcmp(flow_b, Remove_Spaces(tokennet))) {
                    rulestruct[counters->rulecount].flow_2_var = 0;     /* 0 = any */
                } else {
                    strlcpy(tmp3, flow_b, sizeof(tmp3));
                    for(tmptoken = strtok_r(tmp3, ",", &saveptrflow); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrflow)) {
                        if(!Is_IP(Strip_Chars(tmptoken, "not!"))) {
                            Sagan_Log(S_WARN,"[%s, line %d] Value is not a valid IP '%s'", __FILE__, __LINE__, tmptoken);
                        }
                        f2++;
                        if(strchr(tmptoken, '/')) {
                            if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3)) {
                                flow_range = Netaddr_To_Range(Strip_Chars(tmptoken, "not!"));

                                if(strchr(flow_range, '-')) {
                                    rulestruct[counters->rulecount].flow_2[flow_2_count].lo = atol(strtok_r(flow_range, "-", &saveptrrange));
                                    rulestruct[counters->rulecount].flow_2[flow_2_count].hi = atol(strtok_r(NULL, "-", &saveptrrange));
                                    rulestruct[counters->rulecount].flow_2_type[f2] = 0; /* 0 = not in group */
                                } else {
                                    rulestruct[counters->rulecount].flow_2[flow_2_count].lo = atol(flow_range);
                                    rulestruct[counters->rulecount].flow_2_type[f2] = 2; /* This was a /32, not a range */
                                }
                            } else {
                                flow_range = Netaddr_To_Range(tmptoken);
                                if(strchr(flow_range, '-')) {
                                    rulestruct[counters->rulecount].flow_2[flow_2_count].lo = atol(strtok_r(flow_range, "-", &saveptrrange));
                                    rulestruct[counters->rulecount].flow_2[flow_2_count].hi = atol(strtok_r(NULL, "-", &saveptrrange));
                                    rulestruct[counters->rulecount].flow_2_type[f2] = 1; /* 1 = in group */
                                } else {
                                    rulestruct[counters->rulecount].flow_2[flow_2_count].lo = atol(flow_range);
                                    rulestruct[counters->rulecount].flow_2_type[f2] = 3; /* This was a /32, not a range */
                                }
                            }
                        } else {
                            if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3)) {
                                rulestruct[counters->rulecount].flow_2_type[f2] = 2; /* 2 = not match ip */
                                rulestruct[counters->rulecount].flow_2[flow_2_count].lo = IP2Bit(Strip_Chars(tmptoken, "not!"));
                            } else {
                                rulestruct[counters->rulecount].flow_2_type[f2] = 3; /* 3 = match ip */
                                rulestruct[counters->rulecount].flow_2[flow_2_count].lo = IP2Bit(tmptoken);
                            }
                        }
                        flow_2_count++;
                        if( flow_2_count > 49 ) {
                            Sagan_Log(S_ERROR,"[%s, line %d] You have exceeded the amount of entries for follow_flow_2 '50'.", __FILE__, __LINE__);
                        }

                    }
                    rulestruct[counters->rulecount].flow_2_var = 1;   /* 1 = var */
                    rulestruct[counters->rulecount].flow_2_counter = flow_2_count;
                }
            }

            /* Used later for a single check to determine if a rule has a flow or not
               - Champ Clark III (06/12/2016) */

            if ( rulestruct[counters->rulecount].flow_1_var != 0 || rulestruct[counters->rulecount].flow_2_var != 0 ) {
                rulestruct[counters->rulecount].has_flow = 1;
            }

            /* Destination Port */
            if ( netcount == 6 ) {

                dst_port = config->sagan_port;				/* Set to default */

                if (strcmp(nettmp, "any")) {
                    dst_port = atoi(nettmp);	/* If it's _NOT_ "any", set to default */
                }

                if (Is_Numeric(nettmp)) {
                    dst_port = atoi(nettmp);		/* If it's a number (see Sagan_Var_To_Value),  then set to that */
                }

                if ( dst_port == 0 ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Invalid destination port on line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].dst_port = dst_port;	/* Set for the rule */
            }


            tokennet = strtok_r(NULL, " ", &saveptrnet);
            nettmp = Sagan_Var_To_Value(tokennet); 			/* Convert $VAR to values per line */
            Remove_Spaces(nettmp);

            netcount++;
        }


        /*****************************************************************************/
        /* Parse the rule set!                                                       */
        /*****************************************************************************/


        tokenrule = strtok_r(rulestring, ";", &saveptrrule1);

        while ( tokenrule != NULL ) {

            rulesplit = strtok_r(tokenrule, ":", &saveptrrule2);
            Remove_Spaces(rulesplit);

            /* single flag options.  (nocase, find_port, etc) */

            /*
            		    if (!strcmp(rulesplit, "normalize"))
            			{
            		            rulestruct[counters->rulecount].normalize = 1;
            			}
            */

            if (!strcmp(rulesplit, "parse_port")) {
                strtok_r(NULL, ":", &saveptrrule2);
                rulestruct[counters->rulecount].s_find_port = 1;
            }

            if (!strcmp(rulesplit, "parse_proto")) {
                strtok_r(NULL, ":", &saveptrrule2);
                rulestruct[counters->rulecount].s_find_proto = 1;
            }

            if (!strcmp(rulesplit, "parse_proto_program")) {
                strtok_r(NULL, ":", &saveptrrule2);
                rulestruct[counters->rulecount].s_find_proto_program = 1;
            }

            if (!strcmp(rulesplit, "parse_src_ip")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);
                rulestruct[counters->rulecount].s_find_src_ip = 1;

                if ( arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"parse_src_ip\" option appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].s_find_src_pos = atoi(arg);
            }

            if (!strcmp(rulesplit, "parse_dst_ip")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);
                rulestruct[counters->rulecount].s_find_dst_ip = 1;

                if ( arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"parse_dst_ip\" option appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].s_find_dst_pos = atoi(arg);
            }

            if (!strcmp(rulesplit, "parse_hash")) {

                arg = strtok_r(NULL, ":", &saveptrrule2);

                if ( arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"parse_hash\" option appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                Remove_Spaces(arg);

                if (!strcmp(arg, "md5")) {
                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_MD5;
                }

                else if (!strcmp(arg, "sha1")) {
                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_SHA1;
                }

                else if (!strcmp(arg, "sha256")) {
                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_SHA256;
                }

                else if (!strcmp(arg, "all")) {
                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_ALL;
                }

                if ( rulestruct[counters->rulecount].s_find_hash_type == 0 ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"parse_hash\" option appears to be invalid at line %d in %s. Valid values are 'md5', 'sha1' and 'sha256'.", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

            }

            /* Non-quoted information (sid, reference, etc) */

            if (!strcmp(rulesplit, "flowbits") || !strcmp(rulesplit, "xbits")) {

                arg = strtok_r(NULL, ":", &saveptrrule2);
                tmptoken = Remove_Spaces(strtok_r(arg, ",", &saveptrrule2));

                if (strcmp(tmptoken, "nounified2") && strcmp(tmptoken, "noalert") && strcmp(tmptoken, "set") && strcmp(tmptoken, "unset") && strcmp(tmptoken, "isset") && strcmp(tmptoken, "isnotset")) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Expected 'nounified2', 'noalert', 'set', 'unset', 'isnotset' or 'isset' but got '%s' at line %d in %s", __FILE__, __LINE__, tmptoken, linecount, ruleset_fullname);
                }

                if (!strcmp(tmptoken, "noalert")) {
                    rulestruct[counters->rulecount].xbit_noalert=1;
                }

                if (!strcmp(tmptoken, "nounified2")) {
                    rulestruct[counters->rulecount].xbit_nounified2=1;
                }

                /* SET */

                if (!strcmp(tmptoken, "set")) {
                    tmptoken = Remove_Spaces(strtok_r(NULL, ",", &saveptrrule2));

                    if ( tmptoken == NULL ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Expected xbit name at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                    }

                    rulestruct[counters->rulecount].xbit_flag = 1; 				/* We have xbit in the rule! */
                    rulestruct[counters->rulecount].xbit_set_count++;
                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 1;		/* set */

                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                    rulestruct[counters->rulecount].xbit_timeout[xbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                    if ( rulestruct[counters->rulecount].xbit_timeout[xbit_count] == 0 ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Expected xbit valid expire time for \"set\" at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                    }

                    xbit_count++;
                    counters->xbit_total_counter++;

                }

                /* UNSET */

                if (!strcmp(tmptoken, "unset")) {

                    tmptoken = Remove_Spaces(strtok_r(NULL, ",", &saveptrrule2));

                    if ( tmptoken == NULL ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Expected \"direction\" at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                    }

                    rulestruct[counters->rulecount].xbit_direction[xbit_count] = Sagan_Xbit_Type(tmptoken, linecount, ruleset_fullname);

                    rulestruct[counters->rulecount].xbit_flag = 1;               			/* We have xbit in the rule! */
                    rulestruct[counters->rulecount].xbit_set_count++;
                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 2;                	/* unset */

                    tmptoken = Remove_Spaces(strtok_r(NULL, ",", &saveptrrule2));

                    if ( tmptoken == NULL ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Expected xbit name at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                    }

                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                    xbit_count++;

                }

                /* ISSET */

                if (!strcmp(tmptoken, "isset")) {

                    tmptoken = Remove_Spaces(strtok_r(NULL, ",", &saveptrrule2));

                    if ( tmptoken == NULL ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Expected xbit name at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                    }

                    rulestruct[counters->rulecount].xbit_direction[xbit_count] = Sagan_Xbit_Type(tmptoken, linecount, ruleset_fullname);

                    rulestruct[counters->rulecount].xbit_flag = 1;               			/* We have xbit in the rule! */
                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 3;               	/* isset */

                    tmptoken = Remove_Spaces(strtok_r(NULL, ",", &saveptrrule2));

                    if ( tmptoken == NULL ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Expected xbit name at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                    }

                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                    /* If we have multiple xbit conditions (bit1&bit2),
                     * we alter the xbit_conditon_count to reflect that.
                     * |'s are easy.  We just test to see if one of the
                     * xbits matched or not!
                     */

                    if (Sagan_strstr(rulestruct[counters->rulecount].xbit_name[xbit_count], "&")) {
                        rulestruct[counters->rulecount].xbit_condition_count = Sagan_Character_Count(rulestruct[counters->rulecount].xbit_name[xbit_count], "&") + 1;
                    } else {
                        rulestruct[counters->rulecount].xbit_condition_count++;
                    }

                    xbit_count++;
                }

                /* ISNOTSET */

                if (!strcmp(tmptoken, "isnotset")) {

                    tmptoken = Remove_Spaces(strtok_r(NULL, ",", &saveptrrule2));

                    if ( tmptoken == NULL ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Expected xbit name at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                    }

                    rulestruct[counters->rulecount].xbit_direction[xbit_count] = Sagan_Xbit_Type(tmptoken, linecount, ruleset_fullname);

                    rulestruct[counters->rulecount].xbit_flag = 1;                               	/* We have xbit in the rule! */
                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 4;               	/* isnotset */

                    tmptoken = Remove_Spaces(strtok_r(NULL, ",", &saveptrrule2));

                    if ( tmptoken == NULL ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] Expected xbit name at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                    }

                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                    /* If we have multiple xbit conditions (bit1&bit2),
                     * we alter the xbit_conditon_count to reflect that.
                     * |'s are easy.  We just test to see if one of the
                     * xbits matched or not!
                     */

                    if (Sagan_strstr(rulestruct[counters->rulecount].xbit_name[xbit_count], "&")) {
                        rulestruct[counters->rulecount].xbit_condition_count = Sagan_Character_Count(rulestruct[counters->rulecount].xbit_name[xbit_count], "&") + 1;
                    } else {
                        rulestruct[counters->rulecount].xbit_condition_count++;
                    }

                    xbit_count++;

                }

                rulestruct[counters->rulecount].xbit_count = xbit_count;

            }

            /* "Dynamic" rule loading.  This allows Sagan to load rules when it "detects" new types */

            if (!strcmp(rulesplit, "dynamic_load")) {

                if ( config->dynamic_load_sample_rate == 0 ) {

                    Sagan_Log(S_ERROR, "[%s, line %d] Attempting to load a dynamic rule but the 'dynamic_load' processor hasn't been configured.  Abort", __FILE__, __LINE__, linecount, ruleset_fullname);

                }


                arg = strtok_r(NULL, ":", &saveptrrule2);

                if ( arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] 'dynamic_load' specified but not complete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].dynamic_ruleset, Remove_Spaces(Sagan_Var_To_Value(arg)), sizeof(rulestruct[counters->rulecount].dynamic_ruleset));
                rulestruct[counters->rulecount].type = DYNAMIC_RULE;
                counters->dynamic_rule_count++;

            }

#ifdef HAVE_LIBMAXMINDDB

            if (!strcmp(rulesplit, "country_code")) {

                /* Have the requirements for GeoIP2 been loaded (Maxmind DB, etc) */

                if (!config->have_geoip2) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Rule %s at line %d has GeoIP2 option,  but Sagan configuration lacks GeoIP2!", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

                arg = strtok_r(NULL, ":", &saveptrrule2);
                tmptoken = strtok_r(arg, " ", &saveptrrule2);

                if (strcmp(tmptoken, "track")) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Expected 'track' in 'country_code' option at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                tmptoken = Remove_Spaces(strtok_r(NULL, ",", &saveptrrule2));

                if (strcmp(tmptoken, "by_src") && strcmp(tmptoken, "by_dst")) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Expected 'by_src' or 'by_dst' in 'country_code' option at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                if (!strcmp(tmptoken, "by_src")) {
                    rulestruct[counters->rulecount].geoip2_src_or_dst = 1;
                }

                if (!strcmp(tmptoken, "by_dst")) {
                    rulestruct[counters->rulecount].geoip2_src_or_dst = 2;
                }

                tmptoken = Remove_Spaces(strtok_r(NULL, " ", &saveptrrule2));

                if (strcmp(tmptoken, "is") && strcmp(tmptoken, "isnot")) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Expected 'is' or 'isnot' in 'country_code' option at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                if (!strcmp(tmptoken, "isnot")) {
                    rulestruct[counters->rulecount].geoip2_type = 1;
                }

                if (!strcmp(tmptoken, "is" )) {
                    rulestruct[counters->rulecount].geoip2_type = 2;
                }

                tmptoken = Sagan_Var_To_Value(strtok_r(NULL, ";", &saveptrrule2));           /* Grab country codes */
                Remove_Spaces(tmptoken);

                strlcpy(rulestruct[counters->rulecount].geoip2_country_codes, tmptoken, sizeof(rulestruct[counters->rulecount].geoip2_country_codes));
                rulestruct[counters->rulecount].geoip2_flag = 1;
            }
#endif

#ifndef HAVE_LIBMAXMINDDB
            if (!strcmp(rulesplit, "country_code")) {
                Sagan_Log(S_WARN, "** WARNING: Rule %d of %s has \"country_code:\" tracking but Sagan lacks GeoIP2 support!", linecount, ruleset_fullname);
                Sagan_Log(S_WARN, "** WARNING: Rebuild Sagan with \"--enable-geoip2\" or disable this rule!");
            }
#endif

            if (!strcmp(rulesplit, "meta_content")) {

                if ( meta_content_count > MAX_META_CONTENT ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] There is to many \"meta_content\" types in the rule at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                arg = strtok_r(NULL, ":", &saveptrrule2);
                tmptoken = strtok_r(arg, ",", &saveptrrule2);

                if ( tmptoken == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Expected a meta_content 'helper',  but none was found at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(tmp2, Between_Quotes(tmptoken), sizeof(tmp2));

                strlcpy(rulestruct[counters->rulecount].meta_content_help[meta_content_count], Sagan_Content_Pipe(tmp2, linecount, ruleset_fullname), sizeof(rulestruct[counters->rulecount].meta_content_help[meta_content_count]));

                tmptoken = Sagan_Var_To_Value(strtok_r(NULL, ";", &saveptrrule2));           /* Grab Search data */

                if ( tmptoken == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Expected some sort of meta_content,  but none was found at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                Remove_Spaces(tmptoken);

                strlcpy(tmp2, tmptoken, sizeof(tmp2));

                ptmp = strtok_r(tmp2, ",", &tok);
                meta_content_converted_count = 0;

                while (ptmp != NULL) {

                    strlcpy(rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_content_converted[meta_content_converted_count], Sagan_Replace_Sagan(rulestruct[counters->rulecount].meta_content_help[meta_content_count], ptmp), sizeof(rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_content_converted[meta_content_converted_count]));

                    meta_content_converted_count++;

                    ptmp = strtok_r(NULL, ",", &tok);
                }

                rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_counter = meta_content_converted_count;

                rulestruct[counters->rulecount].meta_content_flag = 1;

                tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                not = strtok_r(arg, "\"", &savenot);

                if (Sagan_strstr(not, "!")) {
                    rulestruct[counters->rulecount].meta_content_not[meta_content_count] = 1;
                }

                meta_content_count++;
                rulestruct[counters->rulecount].meta_content_count=meta_content_count;

            }

            /* Like "nocase" for content,  but for "meta_nocase".  This is a "single option" but works better here */

            if (!strcmp(rulesplit, "meta_nocase")) {
                strtok_r(NULL, ":", &saveptrrule2);
                rulestruct[counters->rulecount].meta_content_case[meta_content_count-1] = 1;
                strlcpy(tolower_tmp, To_LowerC(rulestruct[counters->rulecount].meta_content[meta_content_count-1]), sizeof(tolower_tmp));
                strlcpy(rulestruct[counters->rulecount].meta_content[meta_content_count-1], tolower_tmp, sizeof(rulestruct[counters->rulecount].meta_content[meta_content_count-1]));
            }


            if (!strcmp(rulesplit, "rev" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"rev\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].s_rev, Remove_Spaces(arg), sizeof(rulestruct[counters->rulecount].s_rev));
            }

            if (!strcmp(rulesplit, "classtype" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"classtype\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].s_classtype, Remove_Spaces(arg), sizeof(rulestruct[counters->rulecount].s_classtype));

                found = 0;

                for(i=0; i < counters->classcount; i++) {
                    if (!strcmp(classstruct[i].s_shortname, rulestruct[counters->rulecount].s_classtype)) {
                        rulestruct[counters->rulecount].s_pri = classstruct[i].s_priority;
                        found = 1;
                    }
                }

                if ( found == 0 ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The classtype \"%s\" was not found on line %d in %s! "
                              "Are you attempting loading a rule set before loading the classification.config?", __FILE__, __LINE__, rulestruct[counters->rulecount].s_classtype, linecount, ruleset_fullname);
                }

            }

            if (!strcmp(rulesplit, "program" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"program\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].s_program, Remove_Spaces(Sagan_Var_To_Value(arg)), sizeof(rulestruct[counters->rulecount].s_program));

            }

            if (!strcmp(rulesplit, "reference" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"reference\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].s_reference[ref_count], Remove_Spaces(arg), sizeof(rulestruct[counters->rulecount].s_reference[ref_count]));
                rulestruct[counters->rulecount].ref_count=ref_count;
                ref_count++;
            }

            if (!strcmp(rulesplit, "sid" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"sid\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].s_sid, Remove_Spaces(arg), sizeof(rulestruct[counters->rulecount].s_sid));
            }

            if (!strcmp(rulesplit, "tag" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"tag\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].s_tag, Remove_Spaces(arg), sizeof(rulestruct[counters->rulecount].s_tag));
            }

            if (!strcmp(rulesplit, "facility" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"facility\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].s_facility, Remove_Spaces(arg), sizeof(rulestruct[counters->rulecount].s_facility));
            }

            if (!strcmp(rulesplit, "level" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"level\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }
                strlcpy(rulestruct[counters->rulecount].s_level, Remove_Spaces(arg), sizeof(rulestruct[counters->rulecount].s_level));
            }


            if (!strcmp(rulesplit, "pri" )) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"priority\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                Remove_Spaces(arg);
                rulestruct[counters->rulecount].s_pri = atoi(arg);
            }

#ifdef HAVE_LIBESMTP

            if (!strcmp(rulesplit, "email" )) {
                arg = strtok_r(NULL, " ", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"email\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                if (!strcmp(config->sagan_esmtp_server, "" )) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Line %d of %s has the \"email:\" option,  but no SMTP server is specified in the %s", __FILE__, __LINE__, linecount, ruleset_fullname, config->sagan_config);
                }

                strlcpy(rulestruct[counters->rulecount].email, Remove_Spaces(arg), sizeof(rulestruct[counters->rulecount].email));
                rulestruct[counters->rulecount].email_flag=1;
                config->sagan_esmtp_flag=1;
            }
#endif


#ifdef HAVE_LIBLOGNORM

            /* Our Liblognorm friends changed the way it works!  We use to load normalization rule base files
               as they were needed. ln_loadSample no longer accepts multiple calls.  This means that _all_
               liblognorm rules need to be loaded from one file at one time.  This depreciates "normalize: type;"
                       in favor of a simple "normalize"; */

            if (!strcmp(rulesplit, "normalize" )) {
                rulestruct[counters->rulecount].normalize = 1;

                /* Test for old liblognorm/Sagan usage.  If old method is found,  produce a warning */

                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg != NULL ) {
                    Sagan_Log(S_WARN, "Detected a rule that uses the older \'normalize\' method.  Please consider updating \'%s\' at line %d", ruleset_fullname, linecount);
                }
            }

#endif

            /* Quoted information (content, pcre, msg)  */

            if (!strcmp(rulesplit, "msg" )) {
                arg = strtok_r(NULL, ";", &saveptrrule2);
                strlcpy(tmp2, Between_Quotes(arg), sizeof(tmp2));

                if (tmp2[0] == '\0' ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"msg\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                strlcpy(rulestruct[counters->rulecount].s_msg, tmp2, sizeof(rulestruct[counters->rulecount].s_msg));
            }

            if (!strcmp(rulesplit, "content" )) {
                if ( content_count > MAX_CONTENT ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] There is to many \"content\" types in the rule at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                arg = strtok_r(NULL, ";", &saveptrrule2);
                strlcpy(tmp2, Between_Quotes(arg), sizeof(tmp2));

                if (tmp2[0] == '\0' ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"content\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }


                /* Convert HEX encoded data */

                strlcpy(final_content, Sagan_Content_Pipe(tmp2, linecount, ruleset_fullname), sizeof(final_content));

                /* For content: ! "something" */

                not = strtok_r(arg, "\"", &savenot);

                if (Sagan_strstr(not, "!")) {
                    rulestruct[counters->rulecount].content_not[content_count] = 1;
                }

                strlcpy(rulestruct[counters->rulecount].s_content[content_count], final_content, sizeof(rulestruct[counters->rulecount].s_content[content_count]));
                final_content[0] = '\0';
                content_count++;
                rulestruct[counters->rulecount].content_count=content_count;
            }

            /* Single option,  but "nocase" works better here */

            if (!strcmp(rulesplit, "nocase")) {
                strtok_r(NULL, ":", &saveptrrule2);
                rulestruct[counters->rulecount].s_nocase[content_count - 1] = 1;
                strlcpy(tolower_tmp, To_LowerC(rulestruct[counters->rulecount].s_content[content_count - 1]), sizeof(tolower_tmp));
                strlcpy(rulestruct[counters->rulecount].s_content[content_count-1], tolower_tmp, sizeof(rulestruct[counters->rulecount].s_content[content_count-1]));

            }

            if (!strcmp(rulesplit, "offset")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"offset\" appears to be missing at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].s_offset[content_count - 1] = atoi(arg);
            }

            if (!strcmp(rulesplit, "meta_offset")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"meta_offset\" appears to be missing at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].meta_offset[meta_content_count - 1] = atoi(arg);
            }


            if (!strcmp(rulesplit, "depth")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"depth\" appears to be missing at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].s_depth[content_count - 1] = atoi(arg);
            }

            if (!strcmp(rulesplit, "meta_depth")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"meta_depth\" appears to be missing at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].meta_depth[meta_content_count - 1] = atoi(arg);
            }


            if (!strcmp(rulesplit, "distance")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"distance\" appears to be missing at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].s_distance[content_count - 1] = atoi(arg);
            }

            if (!strcmp(rulesplit, "meta_distance")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"meta_distance\" appears to be missing at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                rulestruct[counters->rulecount].meta_distance[meta_content_count - 1] = atoi(arg);
            }


            if (!strcmp(rulesplit, "within")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"within\" appears to be missing at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }
                rulestruct[counters->rulecount].s_within[content_count - 1] = atoi(arg);
            }


            if (!strcmp(rulesplit, "meta_within")) {
                arg = strtok_r(NULL, ":", &saveptrrule2);

                if (arg == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] The \"meta_within\" appears to be missing at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }
                rulestruct[counters->rulecount].meta_within[meta_content_count - 1] = atoi(arg);
            }


            /* PCRE needs a little extra "work" */

            if (!strcmp(rulesplit, "pcre" )) {

                if ( pcre_count > MAX_PCRE ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] There is to many \"pcre\" types in the rule at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                arg = strtok_r(NULL, ";", &saveptrrule2);
                strlcpy(tmp2, Between_Quotes(arg), sizeof(tmp2));

                if (tmp2[0] == '\0' ) {
                    Sagan_Log(S_ERROR, "The \"pcre\" appears to be incomplete at line %d in %s", __FILE__, __LINE__, linecount, ruleset_fullname);
                }

                pcreflag=0;
                memset(pcrerule, 0, sizeof(pcrerule));

                for ( i = 1; i < strlen(tmp2); i++) {

                    if ( tmp2[i] == '/' && tmp2[i-1] != '\\' ) {
                        pcreflag++;
                    }

                    if ( pcreflag == 0 ) {
                        snprintf(tmp, sizeof(tmp), "%c", tmp2[i]);
                        strlcat(pcrerule, tmp, sizeof(pcrerule));
                    }

                    /* are we /past/ and at the args? */

                    if ( pcreflag == 1 ) {

                        switch(tmp2[i]) {

                        case 'i':
                            if ( pcreflag == 1 ) pcreoptions |= PCRE_CASELESS;
                            break;
                        case 's':
                            if ( pcreflag == 1 ) pcreoptions |= PCRE_DOTALL;
                            break;
                        case 'm':
                            if ( pcreflag == 1 ) pcreoptions |= PCRE_MULTILINE;
                            break;
                        case 'x':
                            if ( pcreflag == 1 ) pcreoptions |= PCRE_EXTENDED;
                            break;
                        case 'A':
                            if ( pcreflag == 1 ) pcreoptions |= PCRE_ANCHORED;
                            break;
                        case 'E':
                            if ( pcreflag == 1 ) pcreoptions |= PCRE_DOLLAR_ENDONLY;
                            break;
                        case 'G':
                            if ( pcreflag == 1 ) pcreoptions |= PCRE_UNGREEDY;
                            break;


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


                if ( pcreflag == 0 ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] Missing last '/' in pcre: %s at line %d", __FILE__, __LINE__, ruleset_fullname, linecount);
                }


                /* We store the compiled/study results.  This saves us some CPU time during searching - Champ Clark III - 02/01/2011 */

                rulestruct[counters->rulecount].re_pcre[pcre_count] =  pcre_compile( pcrerule, pcreoptions, &error, &erroffset, NULL );

#ifdef PCRE_HAVE_JIT

                if ( config->pcre_jit == 1 ) {
                    pcreoptions |= PCRE_STUDY_JIT_COMPILE;
                }
#endif

                rulestruct[counters->rulecount].pcre_extra[pcre_count] = pcre_study( rulestruct[counters->rulecount].re_pcre[pcre_count], pcreoptions, &error);

#ifdef PCRE_HAVE_JIT

                if ( config->pcre_jit == 1 ) {
                    int jit = 0;
                    rc = 0;

                    rc = pcre_fullinfo(rulestruct[counters->rulecount].re_pcre[pcre_count], rulestruct[counters->rulecount].pcre_extra[pcre_count], PCRE_INFO_JIT, &jit);

                    if (rc != 0 || jit != 1) {
                        Sagan_Log(S_WARN, "[%s, line %d] PCRE JIT does not support regexp in %s at line %d (pcre: \"%s\"). Continuing without PCRE JIT enabled for this rule.", __FILE__, __LINE__, ruleset_fullname, linecount, pcrerule);
                    }
                }

#endif

                if (  rulestruct[counters->rulecount].re_pcre[pcre_count]  == NULL ) {
                    Remove_Lock_File();
                    Sagan_Log(S_ERROR, "[%s, line %d] PCRE failure at %d: %s", __FILE__, __LINE__, erroffset, error);
                }

                pcre_count++;
                rulestruct[counters->rulecount].pcre_count=pcre_count;
            }


            /* Snortsam */

            /* fwsam: src, 24 hours; */

            if (!strcmp(rulesplit, "fwsam" )) {

                /* Set some defaults - needs better error checking! */

                rulestruct[counters->rulecount].fwsam_src_or_dst=1;	/* by src */
                rulestruct[counters->rulecount].fwsam_seconds = 86400;   /* 1 day */

                tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                tmptoken = strtok_r(tok_tmp, ",", &saveptrrule2);

                if (Sagan_strstr(tmptoken, "src")) {
                    rulestruct[counters->rulecount].fwsam_src_or_dst=1;
                }

                if (Sagan_strstr(tmptoken, "dst")) {
                    rulestruct[counters->rulecount].fwsam_src_or_dst=2;
                }

                /* Error checking?!!? */

                tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);

                fwsam_time_tmp=atol(tmptok_tmp);	/* Digit/time */
                tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3); /* Type - hour/minute */

                rulestruct[counters->rulecount].fwsam_seconds = Sagan_Value_To_Seconds(tmptok_tmp, fwsam_time_tmp);

            }


            /* Time based alerting */

            if (!strcmp(rulesplit, "alert_time")) {

                rulestruct[counters->rulecount].alert_time_flag = 1;

                tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                strlcpy(tmp2, Sagan_Var_To_Value(tok_tmp), sizeof(tmp2));

                tmptoken = strtok_r(tmp2, ",", &saveptrrule2);

                while( tmptoken != NULL ) {

                    if (Sagan_strstr(tmptoken, "days")) {
                        tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                        tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                        Remove_Spaces(tmptok_tmp);

                        if (strlen(tmptok_tmp) > 7 ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] To many days (%s) in 'alert_time' in %s at line %d.", __FILE__, __LINE__, tmptok_tmp, ruleset_fullname, linecount);
                        }

                        strlcpy(alert_time_tmp, tmptok_tmp, sizeof(alert_time_tmp));

                        for (i=0; i<strlen(alert_time_tmp); i++) {
                            snprintf(tmp, sizeof(tmp), "%c", alert_time_tmp[i]);

                            if (!Is_Numeric(tmp)) {
                                Sagan_Log(S_ERROR, "[%s, line %d] The day '%c' 'alert_time / days' is invalid in %s at line %d.", __FILE__, __LINE__,  alert_time_tmp[i], ruleset_fullname, linecount);
                            }

                            if ( atoi(tmp) == 0 ) rulestruct[counters->rulecount].alert_days ^= SUNDAY;
                            if ( atoi(tmp) == 1 ) rulestruct[counters->rulecount].alert_days ^= MONDAY;
                            if ( atoi(tmp) == 2 ) rulestruct[counters->rulecount].alert_days ^= TUESDAY;
                            if ( atoi(tmp) == 3 ) rulestruct[counters->rulecount].alert_days ^= WEDNESDAY;
                            if ( atoi(tmp) == 4 ) rulestruct[counters->rulecount].alert_days ^= THURSDAY;
                            if ( atoi(tmp) == 5 ) rulestruct[counters->rulecount].alert_days ^= FRIDAY;
                            if ( atoi(tmp) == 6 ) rulestruct[counters->rulecount].alert_days ^= SATURDAY;

                        }

                    }

                    if (Sagan_strstr(tmptoken, "hours")) {

                        tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                        tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                        Remove_Spaces(tmptok_tmp);

                        if ( strlen(tmptok_tmp) > 9 || strlen(tmptok_tmp) < 9 ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] Improper 'alert_time' format in %s at line %d.", __FILE__, __LINE__, ruleset_fullname, linecount);
                        }

                        snprintf(alert_time_tmp, sizeof(alert_time_tmp), "%s", tmptok_tmp);

                        /* Start hour */

                        snprintf(alert_tmp_hour, sizeof(alert_tmp_hour), "%c%c", alert_time_tmp[0], alert_time_tmp[1]);

                        if ( atoi(alert_tmp_hour) > 23 ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] Starting 'alert_time' hour cannot be over 23 in %s at line %d.",  __FILE__, __LINE__, ruleset_fullname, linecount);
                        }

                        snprintf(alert_tmp_minute, sizeof(alert_tmp_minute), "%c%c", alert_time_tmp[2], alert_time_tmp[3]);

                        if ( atoi(alert_tmp_minute) > 59 ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] Starting 'alert_time' minute cannot be over 59 in %s at line %d.",  __FILE__, __LINE__, ruleset_fullname, linecount);
                        }

                        snprintf(alert_time_all, sizeof(alert_time_all), "%s%s", alert_tmp_hour, alert_tmp_minute);
                        rulestruct[counters->rulecount].aetas_start = atoi(alert_time_all);

                        /* End hour */

                        snprintf(alert_tmp_hour, sizeof(alert_tmp_hour), "%c%c", alert_time_tmp[5], alert_time_tmp[6]);

                        if ( atoi(alert_tmp_hour) > 23 ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] Ending 'alert_time' hour cannot be over 23 in %s at line %d.",  __FILE__, __LINE__, ruleset_fullname, linecount);
                        }

                        snprintf(alert_tmp_minute, sizeof(alert_tmp_minute), "%c%c", alert_time_tmp[7], alert_time_tmp[8]);

                        if ( atoi(alert_tmp_minute) > 59 ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] Ending 'alert_time' minute cannot be over 59 in %s at line %d.",  __FILE__, __LINE__, ruleset_fullname, linecount);
                        }

                        snprintf(alert_time_all, sizeof(alert_time_all), "%s%s", alert_tmp_hour, alert_tmp_minute);

                        rulestruct[counters->rulecount].aetas_end = atoi(alert_time_all);

                    }

                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                }

            }


            /* Thresholding */

            if (!strcmp(rulesplit, "threshold" )) {

                tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                tmptoken = strtok_r(tok_tmp, ",", &saveptrrule2);

                while( tmptoken != NULL ) {

                    if (Sagan_strstr(tmptoken, "type")) {

                        if (Sagan_strstr(tmptoken, "limit")) {
                            rulestruct[counters->rulecount].threshold_type = 1;
                        }

                        if (Sagan_strstr(tmptoken, "threshold")) {
                            rulestruct[counters->rulecount].threshold_type = 2;
                        }
                    }

                    if (Sagan_strstr(tmptoken, "track")) {

                        if (Sagan_strstr(tmptoken, "by_src")) {
                            rulestruct[counters->rulecount].threshold_method = 1;
                        }

                        if (Sagan_strstr(tmptoken, "by_dst")) {
                            rulestruct[counters->rulecount].threshold_method = 2;
                        }

                        if (Sagan_strstr(tmptoken, "by_username")) {
                            rulestruct[counters->rulecount].threshold_method = 3;
                        }

                        if (Sagan_strstr(tmptoken, "by_srcport")) {
                            rulestruct[counters->rulecount].threshold_method = 4;
                        }

                        if (Sagan_strstr(tmptoken, "by_dstport")) {
                            rulestruct[counters->rulecount].threshold_method = 5;
                        }
                    }

                    if (Sagan_strstr(tmptoken, "count")) {
                        tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                        tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                        rulestruct[counters->rulecount].threshold_count = atoi(tmptok_tmp);
                    }

                    if (Sagan_strstr(tmptoken, "seconds")) {
                        tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                        tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3 );
                        rulestruct[counters->rulecount].threshold_seconds = atoi(tmptok_tmp);
                    }

                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                }
            }


            /* "after"; similar to thresholding,  but the opposite direction */

            if (!strcmp(rulesplit, "after" )) {
                tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                tmptoken = strtok_r(tok_tmp, ",", &saveptrrule2);

                while( tmptoken != NULL ) {

                    if (Sagan_strstr(tmptoken, "track")) {

                        /* DEBUG/FIXME: This needs to line up with sagan-defs! */

                        if (Sagan_strstr(tmptoken, "by_src")) {
                            rulestruct[counters->rulecount].after_method = 1;
                        }

                        if (Sagan_strstr(tmptoken, "by_dst")) {
                            rulestruct[counters->rulecount].after_method = 2;
                        }

                        if (Sagan_strstr(tmptoken, "by_username")) {
                            rulestruct[counters->rulecount].after_method = 3;
                        }

                        if (Sagan_strstr(tmptoken, "by_srcport")) {
                            rulestruct[counters->rulecount].after_method = 4;
                        }

                        if (Sagan_strstr(tmptoken, "by_dstport")) {
                            rulestruct[counters->rulecount].after_method = 5;
                        }

                    }

                    if (Sagan_strstr(tmptoken, "count")) {
                        tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                        tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                        rulestruct[counters->rulecount].after_count = atoi(tmptok_tmp);
                    }

                    if (Sagan_strstr(tmptoken, "seconds")) {
                        tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                        tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3 );
                        rulestruct[counters->rulecount].after_seconds = atoi(tmptok_tmp);
                    }

                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                }
            }


            /* Blacklist */

            if (!strcmp(rulesplit, "blacklist")) {
                tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                if ( tok_tmp == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.  \"blacklist:\" options appear incomplete.", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

                Remove_Spaces(tok_tmp);

                tmptoken = strtok_r(tok_tmp, "," , &saveptrrule3);

                while( tmptoken != NULL ) {

                    found = 0;

                    if (!strcmp(tmptoken, "by_src")) {
                        rulestruct[counters->rulecount].blacklist_ipaddr_src = 1;
                        rulestruct[counters->rulecount].blacklist_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "by_dst")) {
                        rulestruct[counters->rulecount].blacklist_ipaddr_dst = 1;
                        rulestruct[counters->rulecount].blacklist_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "both")) {
                        rulestruct[counters->rulecount].blacklist_ipaddr_both = 1;
                        rulestruct[counters->rulecount].blacklist_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "all")) {
                        rulestruct[counters->rulecount].blacklist_ipaddr_all = 1;
                        rulestruct[counters->rulecount].blacklist_flag = 1;
                        found = 1;
                    }

                    tmptoken = strtok_r(NULL, ",", &saveptrrule3);
                }

            }

            /* Bro Intel */

            if (!strcmp(rulesplit, "bro-intel")) {
                tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                if ( tok_tmp == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.  \"bro-intel:\" options appear incomplete.", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

                Remove_Spaces(tok_tmp);

                tmptoken = strtok_r(tok_tmp, "," , &saveptrrule3);

                while( tmptoken != NULL ) {

                    found = 0;

                    if (!strcmp(tmptoken, "by_src")) {
                        rulestruct[counters->rulecount].brointel_ipaddr_src = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "by_dst")) {
                        rulestruct[counters->rulecount].brointel_ipaddr_dst = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "both")) {
                        rulestruct[counters->rulecount].brointel_ipaddr_both = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "all")) {
                        rulestruct[counters->rulecount].brointel_ipaddr_all = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "domain")) {
                        rulestruct[counters->rulecount].brointel_domain = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "file_hash")) {
                        rulestruct[counters->rulecount].brointel_file_hash = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "url")) {
                        rulestruct[counters->rulecount].brointel_url = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "software")) {
                        rulestruct[counters->rulecount].brointel_software = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "email")) {
                        rulestruct[counters->rulecount].brointel_email = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "user_name")) {
                        rulestruct[counters->rulecount].brointel_user_name = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "file_name")) {
                        rulestruct[counters->rulecount].brointel_file_name = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if (!strcmp(tmptoken, "cert_hash")) {
                        rulestruct[counters->rulecount].brointel_cert_hash = 1;
                        rulestruct[counters->rulecount].brointel_flag = 1;
                        found = 1;
                    }

                    if ( found == 0 ) {
                        Sagan_Log(S_ERROR, "[%s, line %d] %s on line %d has an unknown \"brointel\" option \"%s\".", __FILE__, __LINE__, ruleset_fullname, linecount, tmptoken);
                    }

                    tmptoken = strtok_r(NULL, ",", &saveptrrule3);
                }

            }

            if (!strcmp(rulesplit, "external")) {

                tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                if ( tok_tmp == NULL ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has 'external' option  but not external 'program' is specified!", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

                Remove_Spaces(tok_tmp);

                if (stat(tok_tmp, &filecheck) != 0 ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has 'external' option but external program '%s' does not exist! Abort!", __FILE__, __LINE__, ruleset_fullname, linecount, tok_tmp);
                }

                if (access(tok_tmp, X_OK) == -1) {
                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has 'external' option but external program '%s' is not executable! Abort!", __FILE__, __LINE__, ruleset_fullname, linecount, tok_tmp);
                }

                rulestruct[counters->rulecount].external_flag = 1;
                strlcpy(rulestruct[counters->rulecount].external_program, tok_tmp, sizeof(rulestruct[counters->rulecount].external_program));

            }

#ifdef WITH_BLUEDOT

            if (!strcmp(rulesplit, "bluedot")) {

                if ( config->bluedot_flag == 0 ) {
                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has 'bluedot' option enabled,  but 'processor bluedot' is not configured!", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

                tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                if (!Sagan_strstr(tmptoken, "type")) {
                    Sagan_Log(S_ERROR, "[%s, line %d] No Bluedot 'type' found in %s at line %d", __FILE__, __LINE__, ruleset_fullname, linecount);
                }

                if ( Sagan_strstr(tmptoken, "type" )) {

                    if ( Sagan_strstr(tmptoken, "ip_reputation" )) {

                        tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                        if ( Sagan_strstr(tmptoken, "track" )) {

                            /* 1 == src,  2 == dst,  3 == both,  4 == all */

                            if ( Sagan_strstr(tmptoken, "by_src" )) {
                                rulestruct[counters->rulecount].bluedot_ipaddr_type  = 1;
                            }

                            if ( Sagan_strstr(tmptoken, "by_dst" )) {
                                rulestruct[counters->rulecount].bluedot_ipaddr_type  = 2;
                            }

                            if ( Sagan_strstr(tmptoken, "both" )) {
                                rulestruct[counters->rulecount].bluedot_ipaddr_type  = 3;
                            }

                            if ( Sagan_strstr(tmptoken, "all" )) {
                                rulestruct[counters->rulecount].bluedot_ipaddr_type  = 4;
                            }

                            if ( rulestruct[counters->rulecount].bluedot_ipaddr_type == 0 ) {
                                Sagan_Log(S_ERROR, "[%s, line %d] No Bluedot by_src, by_dst, both or all specified in %s at line %d.", __FILE__, __LINE__, ruleset_fullname, linecount);
                            }

                        }

                        tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                        if (!Sagan_strstr(tmptoken, "mdate_effective_period" ) && !Sagan_strstr(tmptoken, "cdate_effective_period" ) && !Sagan_strstr(tmptoken, "none" )) {
                            Sagan_Log(S_ERROR, "[%s, line %d] No Bluedot 'mdate_effective_period', 'cdate_effective_period' or 'none' not specified in %s at line %d", __FILE__, __LINE__, ruleset_fullname, linecount);
                        }

                        if (!Sagan_strstr(tmptoken, "none")) {

                            tok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);

                            if (Sagan_strstr(tmptoken, "mdate_effective_period" )) {

                                bluedot_time = strtok_r(NULL, " ", &saveptrrule3);

                                if ( bluedot_time == NULL ) {
                                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has no Bluedot numeric time value.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                                bluedot_type = strtok_r(NULL, " ", &saveptrrule3);

                                if ( bluedot_type == NULL ) {
                                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has not Bluedot timeframe type (hour, week, month, year, etc) specified.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                                Remove_Spaces(bluedot_time);
                                Remove_Spaces(bluedot_type);

                                bluedot_time_u32 = atol(bluedot_time);

                                if ( bluedot_time_u32 == 0 ) {
                                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has no or invalid Bluedot timeframe.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                                rulestruct[counters->rulecount].bluedot_mdate_effective_period = Sagan_Value_To_Seconds(bluedot_type, bluedot_time_u32);
                            } else if (Sagan_strstr(tmptoken, "cdate_effective_period" )) {
                                bluedot_time = strtok_r(NULL, " ", &saveptrrule3);

                                if ( bluedot_time == NULL ) {
                                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has no Bluedot numeric time value.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                                bluedot_type = strtok_r(NULL, " ", &saveptrrule3);

                                if ( bluedot_type == NULL ) {
                                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has not Bluedot timeframe type (hour, week, month, year, etc) specified.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                                Remove_Spaces(bluedot_time);
                                Remove_Spaces(bluedot_type);

                                bluedot_time_u32 = atol(bluedot_time);

                                if ( bluedot_time_u32 == 0 ) {
                                    Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has no or invalid Bluedot timeframe.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                                rulestruct[counters->rulecount].bluedot_cdate_effective_period = Sagan_Value_To_Seconds(bluedot_type, bluedot_time_u32);
                            }

                        } else {

                            rulestruct[counters->rulecount].bluedot_mdate_effective_period = 0;
                            rulestruct[counters->rulecount].bluedot_cdate_effective_period = 0;

                        }

                        tmptoken = strtok_r(NULL, ";", &saveptrrule2);

                        if ( tmptoken == NULL ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined!", __FILE__, __LINE__, ruleset_fullname, linecount);
                        }

                        Remove_Spaces(tmptoken);

                        Sagan_Verify_Categories( tmptoken, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_IP);


                    }

                    if ( Sagan_strstr(tmptoken, "file_hash" )) {
                        rulestruct[counters->rulecount].bluedot_file_hash = 1;

                        tmptok_tmp = Sagan_Var_To_Value(strtok_r(NULL, ";", &saveptrrule2));   /* Support var's */

                        if ( tmptok_tmp == NULL ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined!", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                        }

                        Sagan_Verify_Categories( tmptok_tmp, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_HASH);
                    }

                    if ( Sagan_strstr(tmptoken, "url" ))

                    {
                        rulestruct[counters->rulecount].bluedot_url = 1;

                        tmptok_tmp = Sagan_Var_To_Value(strtok_r(NULL, ";", &saveptrrule2));   /* Support var's */

                        if ( tmptok_tmp == NULL ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined!", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                        }

                        Sagan_Verify_Categories( tmptok_tmp, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_URL);
                    }


                    if ( Sagan_strstr(tmptoken, "filename" )) {
                        rulestruct[counters->rulecount].bluedot_filename = 1;

                        tmptok_tmp = Sagan_Var_To_Value(strtok_r(NULL, ";", &saveptrrule2));   /* Support var's */

                        if ( tmptok_tmp == NULL ) {
                            Sagan_Log(S_ERROR, "[%s, line %d] %s at line %d has no Bluedot categories defined!", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                        }

                        Sagan_Verify_Categories( tmptok_tmp, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_FILENAME);
                    }

                    /* Error  check (  set flag? */
                }
            }

#endif

#ifndef WITH_BLUEDOT

            if (!strcmp(rulesplit, "bluedot")) {
                Sagan_Log(S_ERROR, "%s has Bluedot rules,  but support isn't compiled in! Abort!", ruleset_fullname);
            }
#endif


            /* -< Go to next line >- */

            tokenrule = strtok_r(NULL, ";", &saveptrrule1);
        }

        /* Some new stuff (normalization) stuff needs to be added */

        if ( debug->debugload ) {

            Sagan_Log(S_DEBUG, "---[Rule %s]------------------------------------------------------", rulestruct[counters->rulecount].s_sid);

            Sagan_Log(S_DEBUG, "= sid: %s", rulestruct[counters->rulecount].s_sid);
            Sagan_Log(S_DEBUG, "= rev: %s", rulestruct[counters->rulecount].s_rev);
            Sagan_Log(S_DEBUG, "= msg: %s", rulestruct[counters->rulecount].s_msg);
            Sagan_Log(S_DEBUG, "= pri: %d", rulestruct[counters->rulecount].s_pri);
            Sagan_Log(S_DEBUG, "= classtype: %s", rulestruct[counters->rulecount].s_classtype);
            Sagan_Log(S_DEBUG, "= drop: %d", rulestruct[counters->rulecount].drop);
            Sagan_Log(S_DEBUG, "= dst_port: %d", rulestruct[counters->rulecount].dst_port);

            if ( rulestruct[counters->rulecount].s_find_src_ip != 0 ) {
                Sagan_Log(S_DEBUG, "= parse_src_ip");
            }

            if ( rulestruct[counters->rulecount].s_find_port != 0 ) {
                Sagan_Log(S_DEBUG, "= parse_port");
            }

            for (i=0; i<content_count; i++) {
                Sagan_Log(S_DEBUG, "= [%d] content: \"%s\"", i, rulestruct[counters->rulecount].s_content[i]);
            }

            for (i=0; i<ref_count; i++) {
                Sagan_Log(S_DEBUG, "= [%d] reference: \"%s\"", i,  rulestruct[counters->rulecount].s_reference[i]);
            }
        }

        /* Reset for next rule */

        pcre_count=0;
        content_count=0;
        meta_content_count=0;
        meta_content_converted_count=0;
        xbit_count=0;
        netcount=0;
        ref_count=0;
        flow_1_count=0;
        flow_2_count=0;
        memset(netstr, 0, sizeof(netstr));
        memset(rulestr, 0, sizeof(rulestr));

        counters->rulecount++;

    } /* end of while loop */

    fclose(rulesfile);
}
