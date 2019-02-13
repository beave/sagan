/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>
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

/* rules.c
 *
 * Loads and parses the rule files into memory
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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

#include "flexbit.h"
#include "flexbit-mmap.h"
#include "lockfile.h"
#include "classifications.h"
#include "rules.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
#endif

struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;

#ifdef WITH_BLUEDOT

struct _Sagan_Bluedot_Cat_List *SaganBluedotCatList;

char *bluedot_time = NULL;
char *bluedot_type = NULL;

uint64_t bluedot_time_u32 = 0;

#endif

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
struct liblognorm_struct *liblognormstruct;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;
#endif

/* For pre-8.20 PCRE compatibility */
#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

struct _Rule_Struct *rulestruct = NULL;
struct _Class_Struct *classstruct = NULL;
struct _Sagan_Ruleset_Track *Ruleset_Track = NULL;

void Load_Rules( const char *ruleset )
{

    struct stat filecheck;

    bool found = 0;
    bool bad_rule = 0;

    const char *error;
    int erroffset;

    FILE *rulesfile;
    char ruleset_fullname[MAXPATH];

    char *rulestring;
    char *netstring;

    char nettmp[64];

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
    char *saveptrport;
    char *saveptrportrange;
    char *tmptoken;

    char *tok_tmp;
    char *tmptok_tmp;
    char *ptmp=NULL;
    char *tok = NULL;

    char *after_value1;
    char *after_value2;
    char *after_value3;

    char tmp_help[CONFBUF];
    char tok_help[64];
    char tok_help2[64];

    uint64_t fwsam_time_tmp;

    char netstr[RULEBUF] = { 0 };
    char rulestr[RULEBUF] = { 0 };
    char rulebuf[RULEBUF] = { 0 };

    char pcrerule[MAX_PCRE_SIZE] = { 0 };

    char tmp4[MAX_CHECK_FLOWS * 10] = { 0 };
    char tmp3[MAX_CHECK_FLOWS * 21] = { 0 };
    char tmp2[RULEBUF] = { 0 };
    char tmp[2] = { 0 };
    char tmp1[CONFBUF] = { 0 };

    char rule_tmp[RULEBUF] = { 0 };

    char final_content[512] = { 0 };

    char flow_a[1024] = { 0 };
    char flow_b[1024] = { 0 };

    char alert_time_tmp[10] = { 0 };
    char alert_tmp_minute[3] = { 0 };
    char alert_tmp_hour[3] = { 0 };
    char alert_time_all[5] = { 0 } ;

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
    int port_1_count=0;
    int port_2_count=0;

    bool pcreflag=0;
    int pcreoptions=0;

    int i=0;
    int d;

    int rc=0;

    int forward=0;
    int reverse=0;

    int is_masked = 0;

    int ruleset_track_id = 0;

    /* Store rule set names/path in memory for later usage dynamic loading, etc */

    strlcpy(ruleset_fullname, ruleset, sizeof(ruleset_fullname));

    if (( rulesfile = fopen(ruleset_fullname, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open rule file (%s - %s)", __FILE__, __LINE__, ruleset_fullname, strerror(errno));
        }



    Ruleset_Track = (_Sagan_Ruleset_Track *) realloc(Ruleset_Track, (counters->ruleset_track_count+1) * sizeof(_Sagan_Ruleset_Track));

    if ( Ruleset_Track == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Sagan_Ruleset_Track. Abort!", __FILE__, __LINE__);
        }

    memset(&Ruleset_Track[counters->ruleset_track_count], 0, sizeof(struct _Sagan_Ruleset_Track));
    memcpy(Ruleset_Track[counters->ruleset_track_count].ruleset, ruleset_fullname, sizeof(Ruleset_Track[counters->ruleset_track_count].ruleset));

    ruleset_track_id = counters->ruleset_track_count;

    __atomic_add_fetch(&counters->ruleset_track_count, 1, __ATOMIC_SEQ_CST);

    Sagan_Log(NORMAL, "Loading %s rule file.", ruleset_fullname);

    while ( fgets(rulebuf, sizeof(rulebuf), rulesfile) != NULL )
        {
            /* Reset for next rule */

            bad_rule = 0;
            pcre_count=0;
            content_count=0;
            meta_content_count=0;
            meta_content_converted_count=0;
            xbit_count=0;
            netcount=0;
            ref_count=0;
            flow_1_count=0;
            flow_2_count=0;
            port_1_count=0;
            port_2_count=0;

            memset(netstr, 0, sizeof(netstr));
            memset(rulestr, 0, sizeof(rulestr));

            int f1=0; /* Need for flow_direction, must reset every rule, not every group */
            int f2=0; /* Need for flow_direction, must reset every rule, not every group */
            int g1=0; /* Need for port_direction, must reset every rule, not every group */
            int g2=0; /* Need for port_direction, must reset every rule, not every group */

            linecount++;

            if (rulebuf[0] == '#' || rulebuf[0] == 10 || rulebuf[0] == ';' || rulebuf[0] == 32)
                {

                    continue;

                }
            else
                {

                    /* Allocate memory for rules, but not comments */

                    rulestruct = (_Rule_Struct *) realloc(rulestruct, (counters->rulecount+1) * sizeof(_Rule_Struct));
                    if ( rulestruct == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for rulestruct. Abort!", __FILE__, __LINE__);
                        }

                    memset(&rulestruct[counters->rulecount], 0, sizeof(struct _Rule_Struct));

                }

            Remove_Return(rulebuf);

            /****************************************/
            /* Some really basic rule sanity checks */
            /****************************************/

            if (!strchr(rulebuf, ';') || !strchr(rulebuf, ':') ||
                    !strchr(rulebuf, '(') || !strchr(rulebuf, ')'))
                {
                    Sagan_Log(WARN, "[%s, line %d]  %s on line %d appears to be incorrect, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                    continue;
                }

            if (!Sagan_strstr(rulebuf, "sid:"))
                {
                    Sagan_Log(WARN, "[%s, line %d] %s on line %d appears to not have a 'sid', skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                    continue;
                }

            if (!Sagan_strstr(rulebuf, "rev:"))
                {
                    Sagan_Log(WARN, "[%s, line %d] %s on line %d appears to not have a 'rev', skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                    continue;
                }

            if (!Sagan_strstr(rulebuf, "msg:"))
                {
                    Sagan_Log(WARN, "[%s, line %d] %s on line %d appears to not have a 'msg', skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                    continue;
                }


            rc=0;

            if (!Sagan_strstr(rulebuf, "alert"))
                {
                    rc++;
                }

            if (!Sagan_strstr(rulebuf, "drop"))
                {
                    rc++;
                }

            if ( rc == 2 )
                {
                    Sagan_Log(WARN, "[%s, line %d] %s on line %d appears to not have a 'alert' or 'drop', skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                    continue;
                }

            rc=0;

            if (!Sagan_strstr(rulebuf, "alert any ") && !Sagan_strstr(rulebuf, "drop any "))
                {
                    rc++;
                }

            if (!Sagan_strstr(rulebuf, "alert ip ") && !Sagan_strstr(rulebuf, "drop ip "))
                {
                    rc++;
                }

            if (!Sagan_strstr(rulebuf, "alert tcp ") && !Sagan_strstr(rulebuf, "drop tcp "))
                {
                    rc++;
                }

            if (!Sagan_strstr(rulebuf, "alert udp ") && !Sagan_strstr(rulebuf, "drop udp "))
                {
                    rc++;
                }

            if (!Sagan_strstr(rulebuf, "alert icmp ") && !Sagan_strstr(rulebuf, "drop icmp "))
                {
                    rc++;
                }

            if (!Sagan_strstr(rulebuf, "alert syslog ") && !Sagan_strstr(rulebuf, "drop syslog "))
                {
                    rc++;
                }

            if ( rc >= 6 )
                {
                    Sagan_Log(WARN, "[%s, line %d] %s on line %d appears to not have a protocol type (any/tcp/udp/icmp/syslog), skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                    continue;
                }

            /* Parse forward for the first '(' */

            for (i=0; i<strlen(rulebuf); i++)
                {
                    if ( rulebuf[i] == '(' )
                        {
                            forward=i;
                            break;
                        }
                }

            /* Parse reverse for the first ')' */

            for (i=strlen(rulebuf); i>0; i--)
                {
                    if ( rulebuf[i] == ')' )
                        {
                            reverse=i;
                            break;
                        }
                }

            /* Get rule structure,  minus the ( ) */

            for (i=forward+1; i<reverse; i++)
                {
                    snprintf(tmp, sizeof(tmp), "%c", rulebuf[i]);
                    strlcat(rulestr, tmp, sizeof(rulestr));
                }

            /* Get the network information, before the rule */

            for (i=0; i<forward; i++)
                {
                    snprintf(tmp, sizeof(tmp), "%c", rulebuf[i]);
                    strlcat(netstr, tmp, sizeof(netstr));
                }

            /* Assign pointer's to values */

            netstring = netstr;
            rulestring = rulestr;

            /* Assigned ruleset "id" to track when rules "fire" */

            rulestruct[counters->rulecount].ruleset_id = ruleset_track_id;


            /****************************************************************************/
            /* Parse the section _before_ the rule set.  This is stuff like $HOME_NET,  */
            /* $EXTERNAL_NET, etc                                                       */
            /****************************************************************************/

            tokennet = strtok_r(netstring, " ", &saveptrnet);

            while ( tokennet != NULL && !bad_rule)
                {

                    Remove_Spaces(tokennet);

                    if ( netcount == 0 )
                        {

                            if (!strcmp(tokennet, "drop" ))
                                {

                                    rulestruct[counters->rulecount].drop = true;

                                }
                            else
                                {

                                    rulestruct[counters->rulecount].drop = false;

                                }
                        }

                    /* Protocol */

                    if ( netcount == 1 )
                        {
                            if (!strcmp(tokennet, "any" ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 0;
                                }

                            else if (!strcmp(tokennet, "ip" ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 0;
                                }

                            else if (!strcmp(tokennet, "icmp" ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 1;
                                }

                            else if (!strcmp(tokennet, "tcp"  ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 6;
                                }

                            else if (!strcmp(tokennet, "udp"  ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = 17;
                                }

                            else if (!strcmp(tokennet, "syslog"  ))
                                {
                                    rulestruct[counters->rulecount].ip_proto = config->sagan_proto;
                                }
                        }

                    /* First flow */

                    if ( netcount == 2 )
                        {


                            Var_To_Value(tokennet, flow_a, sizeof(flow_a));

                            Remove_Spaces(flow_a);

                            /* Quick sanity check for [] (if used) */

                            if ( ( flow_a[0] == '['  &&  flow_a[strlen(flow_a)-1] != ']') ||
                                    ( ( flow_a[strlen(flow_a)-1] == ']'  &&  flow_a[0] != '[' )) )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Unbalanced flow_a set in '%s' line %d", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if (!strcmp(flow_a, "any")) //  || !strcmp(flow_a, tokennet))
                                {
                                    rulestruct[counters->rulecount].flow_1_var = 0;	  /* 0 = any */

                                }
                            else
                                {

                                    strlcpy(tmp3, flow_a, sizeof(tmp3));

                                    /* Nuke [] */

                                    if ( flow_a[0] == '[' && flow_a[ strlen(flow_a) - 1 ] == ']' )
                                        {
                                            for ( i = 1; i < strlen(flow_a)-1; i++ )
                                                {
                                                    tmp3[i-1] = flow_a[i];
                                                    tmp3[i] = '\0';
                                                }
                                        }


                                    for(tmptoken = strtok_r(tmp3, ",", &saveptrflow); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrflow))
                                        {

                                            Strip_Chars(tmptoken, "not!", tok_help);

                                            if ( !Is_IP_Range(tok_help) )
                                                {
                                                    Sagan_Log(WARN,"[%s, line %d] Value is not a valid IPv4/IPv6 '%s'", __FILE__, __LINE__, tok_help);
                                                }

                                            f1++;

                                            is_masked = Netaddr_To_Range(tmptoken, (unsigned char *)&rulestruct[counters->rulecount].flow_1[flow_1_count].range);

                                            if(strchr(tmptoken, '/'))
                                                {

                                                    if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3))
                                                        {

                                                            rulestruct[counters->rulecount].flow_1_type[f1] = is_masked ? 0 : 2; /* 0 = not in group, 2 == IP not range */
                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].flow_1_type[f1] = is_masked ? 1 : 3; /* 1 = in group, 3 == IP not range */
                                                        }
                                                }
                                            else if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3))
                                                {

                                                    rulestruct[counters->rulecount].flow_1_type[f1] = 2; /* 2 = not match ip */
                                                }
                                            else
                                                {

                                                    rulestruct[counters->rulecount].flow_1_type[f1] = 3; /* 3 = match ip */
                                                }

                                            flow_1_count++;

                                            if( flow_1_count > MAX_CHECK_FLOWS )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN,"[%s, line %d] You have exceeded the amount of IP's for flow_1 '50', skipping rule.", __FILE__, __LINE__);
                                                    continue;
                                                }
                                        }

                                    rulestruct[counters->rulecount].flow_1_var = 1;   /* 1 = var */
                                    rulestruct[counters->rulecount].flow_1_counter = flow_1_count;
                                }
                        }

                    /* Source Port */

                    if ( netcount == 3 )
                        {
                            if (!strcmp(nettmp, "any"))
                                {
                                    rulestruct[counters->rulecount].port_1_var = 0;	  /* 0 = any */
                                }
                            else
                                {
                                    rulestruct[counters->rulecount].port_1_var = 1;	  /* 1 = var */
                                    strlcpy(tmp4, nettmp, sizeof(tmp4));
                                    for (tmptoken = strtok_r(tmp4, ",", &saveptrport); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrport))
                                        {
                                            Strip_Chars(tmptoken, "not!", tok_help2);
                                            g1++;
                                            if (Is_Numeric(nettmp))
                                                {
                                                    rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(nettmp);          /* If it's a number (see Var_To_Value),  then set to that */
                                                }

                                            if (!strncmp(tmptoken,"!", 1) || !strncmp("not", tmptoken, 3))
                                                {
                                                    if(strchr(tok_help2,':'))
                                                        {

                                                            rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(strtok_r(tok_help2, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_1[port_1_count].hi = atoi(strtok_r(NULL, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_1_type[g1] = 0; /* 0 = not in group */

                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(tok_help2);
                                                            rulestruct[counters->rulecount].port_1_type[g1] = 2; /* This was a single port, not a range */

                                                        }
                                                }
                                            else
                                                {
                                                    if(strchr(tok_help2, ':'))
                                                        {

                                                            rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(strtok_r(tok_help2, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_1[port_1_count].hi = atoi(strtok_r(NULL, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_1_type[g1] = 1; /* 1 = in group */

                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].port_1[port_1_count].lo = atoi(tok_help2);
                                                            rulestruct[counters->rulecount].port_1_type[g1] = 3; /* This was a single port, not a range */

                                                        }

                                                }
                                            port_1_count++;

                                            if( port_1_count > MAX_CHECK_FLOWS )
                                                {
                                                    Sagan_Log(WARN,"[%s, line %d] You have exceeded the amount of Ports for port_1 '%d', skipping rule.", __FILE__, __LINE__, MAX_CHECK_FLOWS);
                                                    bad_rule = true;
                                                    continue;
                                                }

                                        }
                                    rulestruct[counters->rulecount].port_1_counter = port_1_count;
                                }

                        }


                    /* Direction */

                    if ( netcount == 4 )
                        {

                            if ( !strcmp(tokennet, "->") )
                                {
                                    d = 1;  /* 1 = right */
                                }
                            else if( !strcmp(tokennet, "<>") || !strcmp(tokennet, "any") || !strcmp(tokennet, "<->") )
                                {
                                    d = 0;  /* 0 = any */
                                }
                            else if( !strcmp(tokennet, "<-") )
                                {
                                    d = 2;  /* 2 = left */
                                }
                            else
                                {
                                    d = 0;  /* 0 = any */
                                }
                            rulestruct[counters->rulecount].direction = d;
                        }

                    /* Second flow */

                    if ( netcount == 5 )
                        {

                            Var_To_Value(tokennet, flow_b, sizeof(flow_b));

                            Remove_Spaces(flow_b);

                            if ( ( flow_b[0] == '['  &&  flow_b[strlen(flow_b)-1] != ']') ||
                                    ( ( flow_b[strlen(flow_b)-1] == ']'  &&  flow_b[0] != '[' )) )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Unbalanced flow_b set in '%s' line %d", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }

                            if (!strcmp(flow_b, "any")) //  || !strcmp(flow_b, tokennet))
                                {
                                    rulestruct[counters->rulecount].flow_2_var = 0;     /* 0 = any */

                                }
                            else
                                {

                                    strlcpy(tmp3, flow_b, sizeof(tmp3));

                                    /* Nuke [] */

                                    if ( flow_b[0] == '[' && flow_b[ strlen(flow_b) - 1 ] == ']' )
                                        {
                                            for ( i = 1; i < strlen(flow_b)-1; i++ )
                                                {
                                                    tmp3[i-1] = flow_b[i];
                                                    tmp3[i] = '\0';
                                                }
                                        }


                                    for(tmptoken = strtok_r(tmp3, ",", &saveptrflow); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrflow))
                                        {

                                            Strip_Chars(tmptoken, "not!", tok_help);

                                            if ( !Is_IP_Range(tok_help) )
                                                {
                                                    Sagan_Log(WARN,"[%s, line %d] Value is not a valid IPv4/IPv6 '%s'", __FILE__, __LINE__, tok_help);
                                                }

                                            f2++;

                                            is_masked = Netaddr_To_Range(tmptoken, (unsigned char *)&rulestruct[counters->rulecount].flow_2[flow_2_count].range);

                                            if(strchr(tmptoken, '/'))
                                                {
                                                    if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3))
                                                        {
                                                            rulestruct[counters->rulecount].flow_2_type[f2] = is_masked ? 0 : 2; /* 0 = not in group, 2 == IP not range */
                                                        }
                                                    else
                                                        {
                                                            rulestruct[counters->rulecount].flow_2_type[f2] = is_masked ? 1 : 3; /* 1 = in group, 3 == IP not range */
                                                        }
                                                }
                                            else if( !strncmp(tmptoken, "!", 1) || !strncmp("not", tmptoken, 3))
                                                {
                                                    rulestruct[counters->rulecount].flow_2_type[f2] = 2; /* 2 = not match ip */
                                                }
                                            else
                                                {
                                                    rulestruct[counters->rulecount].flow_2_type[f2] = 3; /* 3 = match ip */
                                                }

                                            flow_2_count++;

                                            if( flow_2_count > MAX_CHECK_FLOWS )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN,"[%s, line %d] You have exceeded the amount of entries for follow_flow_2 '50', skipping.", __FILE__, __LINE__);
                                                    continue;
                                                }
                                        }

                                    rulestruct[counters->rulecount].flow_2_var = 1;   /* 1 = var */
                                    rulestruct[counters->rulecount].flow_2_counter = flow_2_count;
                                }
                        }

                    /* Destination Port */

                    if ( netcount == 6 )
                        {
                            if (!strcmp(nettmp, "any"))
                                {
                                    rulestruct[counters->rulecount].port_2_var = 0;	  /* 0 = any */
                                }
                            else
                                {
                                    rulestruct[counters->rulecount].port_2_var = 1;	  /* 1 = var */
                                    strlcpy(tmp4, nettmp, sizeof(tmp4));

                                    for (tmptoken = strtok_r(tmp4, ",", &saveptrport); tmptoken; tmptoken = strtok_r(NULL, ",", &saveptrport))
                                        {
                                            Strip_Chars(tmptoken, "not!", tok_help2);
                                            g2++;
                                            if (Is_Numeric(nettmp))
                                                {
                                                    rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(nettmp);          /* If it's a number (see Var_To_Value),  then set to that */
                                                }

                                            if (!strncmp(tmptoken,"!", 1) || !strncmp("not", tmptoken, 3))
                                                {
                                                    if(strchr(tok_help2,':'))
                                                        {

                                                            rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(strtok_r(tok_help2, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_2[port_2_count].hi = atoi(strtok_r(NULL, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_2_type[g2] = 0; /* 0 = not in group */

                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(tok_help2);
                                                            rulestruct[counters->rulecount].port_2_type[g2] = 2; /* This was a single port, not a range */

                                                        }
                                                }
                                            else
                                                {
                                                    if(strchr(tok_help2, ':'))
                                                        {

                                                            rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(strtok_r(tok_help2, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_2[port_2_count].hi = atoi(strtok_r(NULL, ":", &saveptrportrange));
                                                            rulestruct[counters->rulecount].port_2_type[g2] = 1; /* 1 = in group */

                                                        }
                                                    else
                                                        {

                                                            rulestruct[counters->rulecount].port_2[port_2_count].lo = atoi(tok_help2);
                                                            rulestruct[counters->rulecount].port_2_type[g2] = 3; /* This was a single port, not a range */

                                                        }

                                                }
                                            port_2_count++;

                                            if( port_2_count > MAX_CHECK_FLOWS )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN,"[%s, line %d] You have exceeded the amount of Ports for port_2 '%d', skipping.", __FILE__, __LINE__, MAX_CHECK_FLOWS);
                                                    continue;
                                                }

                                        }
                                    rulestruct[counters->rulecount].port_2_counter = port_2_count;
                                }

                        }

                    /* Used later for a single check to determine if a rule has a flow or not
                        - Champ Clark III (06/12/2016) */

                    if ( rulestruct[counters->rulecount].ip_proto != 0 || rulestruct[counters->rulecount].flow_1_var != 0 || rulestruct[counters->rulecount].port_1_var != 0 || rulestruct[counters->rulecount].flow_2_var != 0 || rulestruct[counters->rulecount].port_2_var != 0 )
                        {
                            rulestruct[counters->rulecount].has_flow = 1;
                        }

                    tokennet = strtok_r(NULL, " ", &saveptrnet);
                    Var_To_Value(tokennet, nettmp, sizeof(nettmp));
                    Remove_Spaces(nettmp);

                    netcount++;
                }

            if (bad_rule)
                {
                    continue;
                }

            /*****************************************************************************/
            /* Parse the rule set!                                                       */
            /*****************************************************************************/

            /* Set some defaults outside the option parsing */

            rulestruct[counters->rulecount].default_proto = config->sagan_proto;
            rulestruct[counters->rulecount].default_src_port = config->sagan_port;
            rulestruct[counters->rulecount].default_dst_port = config->sagan_port;

            tokenrule = strtok_r(rulestring, ";", &saveptrrule1);

            while ( tokenrule != NULL && !bad_rule )
                {

                    rulesplit = strtok_r(tokenrule, ":", &saveptrrule2);
                    Remove_Spaces(rulesplit);

                    /* single flag options.  (nocase, parse_port, etc) */

                    if (!strcmp(rulesplit, "parse_port"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_port = true;
                        }

                    if (!strcmp(rulesplit, "parse_proto"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_proto = true;
                        }

                    if (!strcmp(rulesplit, "parse_proto_program"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_proto_program = true;
                        }

                    if (!strcmp(rulesplit, "flexbit_upause"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"xbit_upause\" option appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].xbit_upause_time = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "default_proto"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"default_proto\" option appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            if (!strcmp(tmp1, "icmp") || !strcmp(tmp1, "1"))
                                {
                                    rulestruct[counters->rulecount].default_proto = 1;
                                }

                            else if (!strcmp(tmp1, "tcp" ) || !strcmp(tmp1, "6" ))
                                {
                                    rulestruct[counters->rulecount].default_proto = 6;
                                }

                            else if (!strcmp(tmp1, "udp" ) || !strcmp(tmp1, "17" ))
                                {
                                    rulestruct[counters->rulecount].default_proto = 17;
                                }

                        }

                    if (!strcmp(rulesplit, "default_src_port"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"default_src_port\" option appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            rulestruct[counters->rulecount].default_src_port = atoi(tmp1);

                        }

                    if (!strcmp(rulesplit, "default_dst_port"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"default_dst_port\" option appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);


                            rulestruct[counters->rulecount].default_dst_port = atoi(tmp1);

                        }



                    if (!strcmp(rulesplit, "parse_src_ip"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_src_ip = true;

                            if ( arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"parse_src_ip\" option appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].s_find_src_pos = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "parse_dst_ip"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_find_dst_ip = 1;

                            if ( arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"parse_dst_ip\" option appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].s_find_dst_pos = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "parse_hash"))
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"parse_hash\" option appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);

                            if (!strcmp(arg, "md5"))
                                {
                                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_MD5;
                                }

                            else if (!strcmp(arg, "sha1"))
                                {
                                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_SHA1;
                                }

                            else if (!strcmp(arg, "sha256"))
                                {
                                    rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_SHA256;
                                }
                            /*
                                                        else if (!strcmp(arg, "all"))
                                                            {
                                                                rulestruct[counters->rulecount].s_find_hash_type = PARSE_HASH_ALL;
                                                            }
                            */

                            if ( rulestruct[counters->rulecount].s_find_hash_type == 0 )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"parse_hash\" option appears to be invalid at line %d in %s. Valid values are 'md5', 'sha1' and 'sha256', skipping rule.", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }


                        }

                    /* Non-quoted information (sid, reference, etc) */

                    if ( !strcmp(rulesplit, "flowbits") || !strcmp(rulesplit, "xbits") || !strcmp(rulesplit, "flexbits") )
                        {

                            arg = strtok_r(NULL, ":", &saveptrrule2);
                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Incomplete 'xbit' option at %d in '%s', skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(tmptoken);


                            if ( strcmp(tmptoken, "nounified2") && strcmp(tmptoken, "noalert") && strcmp(tmptoken, "set") &&
                                    strcmp(tmptoken, "unset") && strcmp(tmptoken, "isset") && strcmp(tmptoken, "isnotset") &&
                                    strcmp(tmptoken, "set_srcport") && strcmp(tmptoken, "set_dstport") && strcmp(tmptoken, "set_ports") &&
                                    strcmp(tmptoken, "count") && strcmp(tmptoken, "noeve" ) )
                                {


                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Expected 'nounified2', 'noalert', 'set', 'unset', 'isnotset', 'isset', 'noeve'  or 'count' but got '%s' at line %d in %s, skipping rule", __FILE__, __LINE__, tmptoken, linecount, ruleset);
                                    continue;

                                }

                            if (!strcmp(tmptoken, "noalert"))
                                {
                                    rulestruct[counters->rulecount].xbit_noalert=true;
                                }

                            if (!strcmp(tmptoken, "nounified2"))
                                {
                                    rulestruct[counters->rulecount].xbit_nounified2=true;
                                }

                            if (!strcmp(tmptoken, "noeve"))
                                {
                                    rulestruct[counters->rulecount].xbit_noeve=true;
                                }


                            /* SET */

                            if (!strcmp(tmptoken, "set"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].xbit_flag = 1; 				/* We have xbit in the rule! */
                                    rulestruct[counters->rulecount].xbit_set_count++;
                                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 1;		/* set */

                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    rulestruct[counters->rulecount].xbit_timeout[xbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                                    if ( rulestruct[counters->rulecount].xbit_timeout[xbit_count] == 0 )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit valid expire time for \"set\" at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    xbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);

                                }

                            /* UNSET */

                            else if (!strcmp(tmptoken, "unset"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected \"direction\" at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].xbit_direction[xbit_count] = Flexbit_Type(tmptoken, linecount, ruleset_fullname);

                                    rulestruct[counters->rulecount].xbit_flag = 1;               			/* We have xbit in the rule! */
                                    rulestruct[counters->rulecount].xbit_set_count++;
                                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 2;                	/* unset */

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    xbit_count++;

                                }

                            /* ISSET */

                            else if (!strcmp(tmptoken, "isset"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].xbit_direction[xbit_count] = Flexbit_Type(tmptoken, linecount, ruleset_fullname);

                                    rulestruct[counters->rulecount].xbit_flag = 1;               			/* We have xbit in the rule! */
                                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 3;               	/* isset */

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    rulestruct[counters->rulecount].xbit_condition_count++;
                                    xbit_count++;

                                }

                            /* ISNOTSET */

                            else if (!strcmp(tmptoken, "isnotset"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].xbit_direction[xbit_count] = Flexbit_Type(tmptoken, linecount, ruleset_fullname);

                                    rulestruct[counters->rulecount].xbit_flag = 1;                               	/* We have xbit in the rule! */
                                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 4;               	/* isnotset */

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    Remove_Return(tmptoken);

                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    rulestruct[counters->rulecount].xbit_condition_count++;
                                    xbit_count++;

                                }

                            /* SET_SRCPORT */

                            else if (!strcmp(tmptoken, "set_srcport"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].xbit_flag = 1; 				/* We have xbit in the rule! */
                                    rulestruct[counters->rulecount].xbit_set_count++;
                                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 5;		/* set_srcport */

                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    rulestruct[counters->rulecount].xbit_timeout[xbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                                    if ( rulestruct[counters->rulecount].xbit_timeout[xbit_count] == 0 )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit valid expire time for \"set\" at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                            continue;
                                        }

                                    xbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);

                                }

                            /* SET_DSTPORT */

                            else if (!strcmp(tmptoken, "set_dstport"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].xbit_flag = 1; 				/* We have xbit in the rule! */
                                    rulestruct[counters->rulecount].xbit_set_count++;
                                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 6;		/* set_dstport */

                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    rulestruct[counters->rulecount].xbit_timeout[xbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                                    if ( rulestruct[counters->rulecount].xbit_timeout[xbit_count] == 0 )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit valid expire time for \"set\" at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;
                                        }

                                    xbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);

                                }

                            /* SET_PORTS */

                            else if (!strcmp(tmptoken, "set_ports"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    rulestruct[counters->rulecount].xbit_flag = 1; 				/* We have xbit in the rule! */
                                    rulestruct[counters->rulecount].xbit_set_count++;
                                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 7;		/* set_ports */

                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    rulestruct[counters->rulecount].xbit_timeout[xbit_count] = atoi(strtok_r(NULL, ",", &saveptrrule2));

                                    if ( rulestruct[counters->rulecount].xbit_timeout[xbit_count] == 0 )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit valid expire time for \"set\" at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;
                                        }

                                    xbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);

                                }

                            /* COUNTER */

                            else if (!strcmp(tmptoken, "count"))
                                {

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);

                                    if ( strcmp(tmptoken, "by_src") && strcmp(tmptoken, "by_dst") )
                                        {

                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected count 'by_src' or 'by_dst'.  Got '%s' instead at line %d in %s, skipping rule", __FILE__, __LINE__, tmptoken, linecount, ruleset);
                                            continue;

                                        }

                                    if ( !strcmp(tmptoken, "by_src") )
                                        {

                                            rulestruct[counters->rulecount].xbit_direction[xbit_count] = 2;

                                        }
                                    else
                                        {

                                            rulestruct[counters->rulecount].xbit_direction[xbit_count] = 3;

                                        }

                                    rulestruct[counters->rulecount].xbit_flag = 1;
                                    rulestruct[counters->rulecount].xbit_set_count++;
                                    rulestruct[counters->rulecount].xbit_type[xbit_count]  = 8;         /* count */

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit name to count at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);
                                    strlcpy(rulestruct[counters->rulecount].xbit_name[xbit_count], tmptoken, sizeof(rulestruct[counters->rulecount].xbit_name[xbit_count]));

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected xbit value to count at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;
                                        }

                                    strlcpy(tmp1, tmptoken, sizeof(tmp1));
                                    Remove_Spaces(tmp1);

                                    if ( tmp1[0] != '>' && tmp1[0] != '<' && tmp1[0] != '=' )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected '>', '<' or '=' operator in xbit count at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;

                                        }

                                    /* Determine the xbit counter operator */

                                    if ( tmp1[0] == '>' )
                                        {
                                            rulestruct[counters->rulecount].xbit_count_gt_lt[xbit_count] = 0;
                                            tmptoken = strtok_r(tmp1, ">", &saveptrrule3);
                                        }

                                    else if ( tmp1[0] == '<' )
                                        {
                                            rulestruct[counters->rulecount].xbit_count_gt_lt[xbit_count] = 1;
                                            tmptoken = strtok_r(tmp1, "<", &saveptrrule3);
                                        }

                                    else if ( tmp1[0] == '=' )
                                        {
                                            rulestruct[counters->rulecount].xbit_count_gt_lt[xbit_count] = 2;
                                            tmptoken = strtok_r(tmp1, "=", &saveptrrule3);
                                        }

                                    if ( tmptoken == NULL )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] Expected value to look for in xbit count at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset);
                                            continue;
                                        }

                                    Remove_Spaces(tmptoken);
                                    rulestruct[counters->rulecount].xbit_count_counter[xbit_count] = atoi(tmptoken);
                                    rulestruct[counters->rulecount].xbit_count_flag = true;

                                    xbit_count++;
                                    __atomic_add_fetch(&counters->flexbit_total_counter, 1, __ATOMIC_SEQ_CST);
                                    rulestruct[counters->rulecount].xbit_count_count++;
                                }

                            rulestruct[counters->rulecount].xbit_count = xbit_count;

                        }

                    /* "Dynamic" rule loading.  This allows Sagan to load rules when it "detects" new types */

                    if (!strcmp(rulesplit, "dynamic_load"))
                        {

                            if ( config->dynamic_load_sample_rate == 0 )
                                {

                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Attempting to load a dynamic rule but the 'dynamic_load' processor hasn't been configured, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;

                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] 'dynamic_load' specified but not complete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            strlcpy(rulestruct[counters->rulecount].dynamic_ruleset, tmp1, sizeof(rulestruct[counters->rulecount].dynamic_ruleset));
                            rulestruct[counters->rulecount].type = DYNAMIC_RULE;
                            __atomic_add_fetch(&counters->dynamic_rule_count, 1, __ATOMIC_SEQ_CST);

                        }

#ifdef HAVE_LIBMAXMINDDB

                    if (!strcmp(rulesplit, "country_code"))
                        {

                            /* Have the requirements for GeoIP2 been loaded (Maxmind DB, etc) */

                            if (!config->have_geoip2)
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Rule %s at line %d has GeoIP option,  but Sagan configuration lacks GeoIP - skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                                    continue;
                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);
                            tmptoken = strtok_r(arg, " ", &saveptrrule2);

                            if (strcmp(tmptoken, "track"))
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Expected 'track' in 'country_code' option at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Incomplete country_code option at %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(tmptoken);

                            if (strcmp(tmptoken, "by_src") && strcmp(tmptoken, "by_dst"))
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Expected 'by_src' or 'by_dst' in 'country_code' option at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            if (!strcmp(tmptoken, "by_src"))
                                {
                                    rulestruct[counters->rulecount].geoip2_src_or_dst = 1;
                                }

                            if (!strcmp(tmptoken, "by_dst"))
                                {
                                    rulestruct[counters->rulecount].geoip2_src_or_dst = 2;
                                }

                            tmptoken = strtok_r(NULL, " ", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Incomplete country_code option at %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(tmptoken);

                            if (strcmp(tmptoken, "is") && strcmp(tmptoken, "isnot"))
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Expected 'is' or 'isnot' in 'country_code' option at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            if (!strcmp(tmptoken, "isnot"))
                                {
                                    rulestruct[counters->rulecount].geoip2_type = 1;
                                }

                            if (!strcmp(tmptoken, "is" ))
                                {
                                    rulestruct[counters->rulecount].geoip2_type = 2;
                                }

                            tmptoken = strtok_r(NULL, ";", &saveptrrule2);           /* Grab country codes */

                            Var_To_Value(tmptoken, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            strlcpy(rulestruct[counters->rulecount].geoip2_country_codes, tmp1, sizeof(rulestruct[counters->rulecount].geoip2_country_codes));

                            rulestruct[counters->rulecount].geoip2_flag = 1;
                        }
#endif

#ifndef HAVE_LIBMAXMINDDB
                    if (!strcmp(rulesplit, "country_code"))
                        {
                            Sagan_Log(WARN, "** WARNING: Rule %d of %s has \"country_code:\" tracking but Sagan lacks GeoIP support!", linecount, ruleset_fullname);
                            Sagan_Log(WARN, "** WARNING: Rebuild Sagan with \"--enable-geoip2\" or disable this rule!");
                        }
#endif

                    if (!strcmp(rulesplit, "meta_content"))
                        {

                            if ( meta_content_count > MAX_META_CONTENT )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] There is to many \"meta_content\" types in the rule at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if ( Check_Content_Not(arg) == true )
                                {
                                    rulestruct[counters->rulecount].meta_content_not[meta_content_count] = true;
                                }

                            tmptoken = strtok_r(arg, ",", &saveptrrule2);

                            if ( tmptoken == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Expected a meta_content 'helper',  but none was found at line %d in %s - skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Between_Quotes(tmptoken, tmp2, sizeof(tmp2));

                            Content_Pipe(tmp2, linecount, ruleset_fullname, rule_tmp, sizeof(rule_tmp));

                            strlcpy(rulestruct[counters->rulecount].meta_content_help[meta_content_count], rule_tmp, sizeof(rulestruct[counters->rulecount].meta_content_help[meta_content_count]));

                            tmptoken = strtok_r(NULL, ";", &saveptrrule2);           /* Grab Search data */

                            if ( tmptoken == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Expected some sort of meta_content,  but none was found at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Var_To_Value(tmptoken, tmp1, sizeof(tmp1));
                            Content_Pipe(tmp1, linecount, ruleset_fullname, rule_tmp, sizeof(rule_tmp));
                            Remove_Spaces(rule_tmp);

                            strlcpy(tmp2, rule_tmp, sizeof(tmp2));

                            ptmp = strtok_r(tmp2, ",", &tok);
                            meta_content_converted_count = 0;

                            while (ptmp != NULL)
                                {

                                    Replace_Sagan(rulestruct[counters->rulecount].meta_content_help[meta_content_count], ptmp, tmp_help, sizeof(tmp_help));
                                    strlcpy(rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_content_converted[meta_content_converted_count], tmp_help, sizeof(rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_content_converted[meta_content_converted_count]));

                                    meta_content_converted_count++;

                                    if ( meta_content_converted_count > MAX_META_ITEM_SIZE )
                                        {

                                            Sagan_Log(ERROR, "[%s, line %d] To many meta_content string values at %d in %s.  Max is %d", __FILE__, __LINE__, linecount, ruleset_fullname, MAX_META_ITEM_SIZE);

                                        }

                                    ptmp = strtok_r(NULL, ",", &tok);
                                }

                            rulestruct[counters->rulecount].meta_content_containers[meta_content_count].meta_counter = meta_content_converted_count;

                            rulestruct[counters->rulecount].meta_content_flag = true;

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                            meta_content_count++;
                            rulestruct[counters->rulecount].meta_content_count=meta_content_count;

                        }

                    /* Like "nocase" for content,  but for "meta_nocase".  This is a "single option" but works better here */

                    if (!strcmp(rulesplit, "meta_nocase"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].meta_content_case[meta_content_count-1] = 1;
                            To_LowerC(rulestruct[counters->rulecount].meta_content[meta_content_count-1]);
                            strlcpy(tolower_tmp, rulestruct[counters->rulecount].meta_content[meta_content_count-1], sizeof(tolower_tmp));
                            strlcpy(rulestruct[counters->rulecount].meta_content[meta_content_count-1], tolower_tmp, sizeof(rulestruct[counters->rulecount].meta_content[meta_content_count-1]));
                        }


                    if (!strcmp(rulesplit, "rev" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"rev\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);

                            rulestruct[counters->rulecount].s_rev = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "classtype" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"classtype\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_classtype, arg, sizeof(rulestruct[counters->rulecount].s_classtype));

                            found = 0;

                            for(i=0; i < counters->classcount; i++)
                                {
                                    if (!strcmp(classstruct[i].s_shortname, rulestruct[counters->rulecount].s_classtype))
                                        {
                                            rulestruct[counters->rulecount].s_pri = classstruct[i].s_priority;
                                            found = 1;
                                        }
                                }

                            if ( found == 0 )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The classtype \"%s\" was not found on line %d in %s! "
                                              "Are you attempting loading a rule set before loading the classification.config? - skipping rule", __FILE__, __LINE__, rulestruct[counters->rulecount].s_classtype, linecount, ruleset_fullname);
                                    continue;
                                }

                        }

                    if (!strcmp(rulesplit, "program" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"program\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Var_To_Value(arg, tmp1, sizeof(tmp1));
                            Remove_Spaces(tmp1);

                            strlcpy(rulestruct[counters->rulecount].s_program, tmp1, sizeof(rulestruct[counters->rulecount].s_program));

                        }

                    if (!strcmp(rulesplit, "reference" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"reference\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_reference[ref_count], arg, sizeof(rulestruct[counters->rulecount].s_reference[ref_count]));
                            rulestruct[counters->rulecount].ref_count=ref_count;
                            ref_count++;
                        }

                    if (!strcmp(rulesplit, "sid" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"sid\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            rulestruct[counters->rulecount].s_sid = atol(arg);
                        }


                    rulestruct[counters->rulecount].s_tag[0] = '\0';

                    if (!strcmp(rulesplit, "syslog_tag" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"tag\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_tag, arg, sizeof(rulestruct[counters->rulecount].s_tag));
                        }


                    rulestruct[counters->rulecount].s_facility[0] = '\0';

                    if (!strcmp(rulesplit, "syslog_facility" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"facility\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_facility, arg, sizeof(rulestruct[counters->rulecount].s_facility));
                        }

                    rulestruct[counters->rulecount].s_level[0] = '\0';

                    if (!strcmp(rulesplit, "syslog_level" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"level\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_level, arg, sizeof(rulestruct[counters->rulecount].s_level));
                        }

                    rulestruct[counters->rulecount].s_syspri[0] = '\0';

                    if (!strcmp(rulesplit, "syslog_priority" ))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"syslog_priority\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].s_syspri, arg, sizeof(rulestruct[counters->rulecount].s_syspri));
                        }


                    if ( !strcmp(rulesplit, "pri" ) || !strcmp(rulesplit, "priority" ) )
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"priority\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            rulestruct[counters->rulecount].s_pri = atoi(arg);
                        }

#ifdef HAVE_LIBESMTP

                    if (!strcmp(rulesplit, "email" ))
                        {
                            arg = strtok_r(NULL, " ", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"email\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            if (!strcmp(config->sagan_esmtp_server, "" ))
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Line %d of %s has the \"email:\" option,  but no SMTP server is specified in the %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname, config->sagan_config);
                                    continue;
                                }

                            Remove_Spaces(arg);
                            strlcpy(rulestruct[counters->rulecount].email, arg, sizeof(rulestruct[counters->rulecount].email));
                            rulestruct[counters->rulecount].email_flag=1;
                            config->sagan_esmtp_flag=1;
                        }
#endif


#ifdef HAVE_LIBLOGNORM

                    /* Our Liblognorm friends changed the way it works!  We use to load normalization rule base files
                       as they were needed. ln_loadSample no longer accepts multiple calls.  This means that _all_
                       liblognorm rules need to be loaded from one file at one time.  This depreciates "normalize: type;"
                               in favor of a simple "normalize"; */

                    if (!strcmp(rulesplit, "normalize" ))
                        {
                            rulestruct[counters->rulecount].normalize = 1;

                            /* Test for old liblognorm/Sagan usage.  If old method is found,  produce a warning */

                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg != NULL )
                                {
                                    Sagan_Log(WARN, "Detected a rule that uses the older \'normalize\' method.  Please consider updating \'%s\' at line %d", ruleset_fullname, linecount);
                                }
                        }

#endif

                    /* Quoted information (content, pcre, msg)  */

                    if (!strcmp(rulesplit, "msg" ))
                        {
                            arg = strtok_r(NULL, ";", &saveptrrule2);

                            Between_Quotes(arg, tmp2, sizeof(tmp2));

                            if (tmp2[0] == '\0' )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"msg\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            strlcpy(rulestruct[counters->rulecount].s_msg, tmp2, sizeof(rulestruct[counters->rulecount].s_msg));
                        }

                    /* Good ole "content" style search */

                    if (!strcmp(rulesplit, "content" ))
                        {
                            if ( content_count > MAX_CONTENT )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] There is to many \"content\" types in the rule at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            arg = strtok_r(NULL, ";", &saveptrrule2);

                            /* For content: ! "something" */

                            if ( Check_Content_Not(arg) == true )
                                {
                                    rulestruct[counters->rulecount].content_not[content_count] = true;
                                }

                            Between_Quotes(arg, tmp2, sizeof(tmp2));

                            if (tmp2[0] == '\0' )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"content\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            /* Convert HEX encoded data */

                            Content_Pipe(tmp2, linecount, ruleset_fullname, rule_tmp, sizeof(rule_tmp));
                            strlcpy(final_content, rule_tmp, sizeof(final_content));

                            strlcpy(rulestruct[counters->rulecount].s_content[content_count], final_content, sizeof(rulestruct[counters->rulecount].s_content[content_count]));
                            final_content[0] = '\0';
                            content_count++;
                            rulestruct[counters->rulecount].content_count=content_count;
                        }

                    /* Single option,  but "nocase" works better here */

                    if (!strcmp(rulesplit, "nocase"))
                        {
                            strtok_r(NULL, ":", &saveptrrule2);
                            rulestruct[counters->rulecount].s_nocase[content_count - 1] = 1;
                            To_LowerC(rulestruct[counters->rulecount].s_content[content_count - 1]);
                            strlcpy(tolower_tmp, rulestruct[counters->rulecount].s_content[content_count - 1], sizeof(tolower_tmp));
                            strlcpy(rulestruct[counters->rulecount].s_content[content_count-1], tolower_tmp, sizeof(rulestruct[counters->rulecount].s_content[content_count-1]));

                        }

                    if (!strcmp(rulesplit, "offset"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"offset\" appears to be missing at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].s_offset[content_count - 1] = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "meta_offset"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"meta_offset\" appears to be missing at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].meta_offset[meta_content_count - 1] = atoi(arg);
                        }


                    if (!strcmp(rulesplit, "depth"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"depth\" appears to be missing at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].s_depth[content_count - 1] = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "meta_depth"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"meta_depth\" appears to be missing at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].meta_depth[meta_content_count - 1] = atoi(arg);
                        }


                    if (!strcmp(rulesplit, "distance"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"distance\" appears to be missing at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].s_distance[content_count - 1] = atoi(arg);
                        }

                    if (!strcmp(rulesplit, "meta_distance"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"meta_distance\" appears to be missing at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            rulestruct[counters->rulecount].meta_distance[meta_content_count - 1] = atoi(arg);
                        }


                    if (!strcmp(rulesplit, "within"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"within\" appears to be missing at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }
                            rulestruct[counters->rulecount].s_within[content_count - 1] = atoi(arg);
                        }


                    if (!strcmp(rulesplit, "meta_within"))
                        {
                            arg = strtok_r(NULL, ":", &saveptrrule2);

                            if (arg == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] The \"meta_within\" appears to be missing at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }
                            rulestruct[counters->rulecount].meta_within[meta_content_count - 1] = atoi(arg);
                        }


                    /* PCRE needs a little extra "work" */

                    if (!strcmp(rulesplit, "pcre" ))
                        {

                            if ( pcre_count > MAX_PCRE )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] There is to many \"pcre\" types in the rule at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                    continue;
                                }

                            arg = strtok_r(NULL, ";", &saveptrrule2);

                            Between_Quotes(arg, tmp2, sizeof(tmp2));

                            if (tmp2[0] == '\0' )
                                {
                                    Sagan_Log(WARN, "The \"pcre\" appears to be incomplete at line %d in %s, skipping rule", __FILE__, __LINE__, linecount, ruleset_fullname);
                                }

                            pcreflag=0;
                            memset(pcrerule, 0, sizeof(pcrerule));

                            for ( i = 1; i < strlen(tmp2); i++)
                                {

                                    if ( tmp2[i] == '/' && tmp2[i-1] != '\\' )
                                        {
                                            pcreflag++;
                                        }

                                    if ( pcreflag == 0 )
                                        {
                                            snprintf(tmp, sizeof(tmp), "%c", tmp2[i]);
                                            strlcat(pcrerule, tmp, sizeof(pcrerule));
                                        }

                                    /* are we /past/ and at the args? */

                                    if ( pcreflag == 1 )
                                        {

                                            switch(tmp2[i])
                                                {

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


                            if ( pcreflag == 0 )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] Missing last '/' in pcre: %s at line %d, skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                                    continue;
                                }


                            /* We store the compiled/study results.  This saves us some CPU time during searching - Champ Clark III - 02/01/2011 */

                            rulestruct[counters->rulecount].re_pcre[pcre_count] =  pcre_compile( pcrerule, pcreoptions, &error, &erroffset, NULL );

#ifdef PCRE_HAVE_JIT

                            if ( config->pcre_jit == 1 )
                                {
                                    pcreoptions |= PCRE_STUDY_JIT_COMPILE;
                                }
#endif

                            rulestruct[counters->rulecount].pcre_extra[pcre_count] = pcre_study( rulestruct[counters->rulecount].re_pcre[pcre_count], pcreoptions, &error);

#ifdef PCRE_HAVE_JIT

                            if ( config->pcre_jit == 1 )
                                {
                                    int jit = 0;
                                    rc = 0;

                                    rc = pcre_fullinfo(rulestruct[counters->rulecount].re_pcre[pcre_count], rulestruct[counters->rulecount].pcre_extra[pcre_count], PCRE_INFO_JIT, &jit);

                                    if (rc != 0 || jit != 1)
                                        {
                                            Sagan_Log(WARN, "[%s, line %d] PCRE JIT does not support regexp in %s at line %d (pcre: \"%s\"). Continuing without PCRE JIT enabled for this rule.", __FILE__, __LINE__, ruleset_fullname, linecount, pcrerule);
                                        }
                                }

#endif

                            if (  rulestruct[counters->rulecount].re_pcre[pcre_count]  == NULL )
                                {
                                    bad_rule = true;
                                    Remove_Lock_File();
                                    Sagan_Log(WARN, "[%s, line %d] PCRE failure in %s at %d [%d: %s], skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount, erroffset, error);
                                    continue;
                                }

                            pcre_count++;
                            rulestruct[counters->rulecount].pcre_count=pcre_count;
                        }


                    /* Snortsam */

                    /* fwsam: src, 24 hours; */

                    if (!strcmp(rulesplit, "fwsam" ))
                        {

                            /* Set some defaults - needs better error checking! */

                            rulestruct[counters->rulecount].fwsam_src_or_dst=1;	/* by src */
                            rulestruct[counters->rulecount].fwsam_seconds = 86400;   /* 1 day */

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule2);

                            if (Sagan_strstr(tmptoken, "src"))
                                {
                                    rulestruct[counters->rulecount].fwsam_src_or_dst=1;
                                }

                            if (Sagan_strstr(tmptoken, "dst"))
                                {
                                    rulestruct[counters->rulecount].fwsam_src_or_dst=2;
                                }

                            /* DEBUG: Error checking?!!? */

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);

                            fwsam_time_tmp=atol(tmptok_tmp);	/* Digit/time */
                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3); /* Type - hour/minute */

                            rulestruct[counters->rulecount].fwsam_seconds = Value_To_Seconds(tmptok_tmp, fwsam_time_tmp);

                        }


                    /* Time based alerting */

                    if (!strcmp(rulesplit, "alert_time"))
                        {

                            rulestruct[counters->rulecount].alert_time_flag = 1;

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                            Var_To_Value(tok_tmp, tmp1, sizeof(tmp1));

                            tmptoken = strtok_r(tmp1, ",", &saveptrrule2);

                            while( tmptoken != NULL )
                                {

                                    if (Sagan_strstr(tmptoken, "days"))
                                        {
                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                                            Remove_Spaces(tmptok_tmp);

                                            if (strlen(tmptok_tmp) > 7 )
                                                {
                                                    Sagan_Log(WARN, "[%s, line %d] To many days (%s) in 'alert_time' in %s at line %d, skipping rule.", __FILE__, __LINE__, tmptok_tmp, ruleset_fullname, linecount);
                                                    bad_rule = true;
                                                    continue;
                                                }

                                            strlcpy(alert_time_tmp, tmptok_tmp, sizeof(alert_time_tmp));

                                            for (i=0; i<strlen(alert_time_tmp); i++)
                                                {
                                                    snprintf(tmp, sizeof(tmp), "%c", alert_time_tmp[i]);

                                                    if (!Is_Numeric(tmp))
                                                        {
                                                            bad_rule = true;
                                                            Sagan_Log(WARN, "[%s, line %d] The day '%c' 'alert_time / days' is invalid in %s at line %d, skipping rule.", __FILE__, __LINE__,  alert_time_tmp[i], ruleset_fullname, linecount);
                                                            continue;
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

                                    if (Sagan_strstr(tmptoken, "hours"))
                                        {

                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                                            Remove_Spaces(tmptok_tmp);

                                            if ( strlen(tmptok_tmp) > 9 || strlen(tmptok_tmp) < 9 )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] Improper 'alert_time' format in %s at line %d, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                    continue;
                                                }

                                            snprintf(alert_time_tmp, sizeof(alert_time_tmp), "%s", tmptok_tmp);

                                            /* Start hour */

                                            snprintf(alert_tmp_hour, sizeof(alert_tmp_hour), "%c%c", alert_time_tmp[0], alert_time_tmp[1]);

                                            if ( atoi(alert_tmp_hour) > 23 )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] Starting 'alert_time' hour cannot be over 23 in %s at line %d, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                    continue;
                                                }

                                            snprintf(alert_tmp_minute, sizeof(alert_tmp_minute), "%c%c", alert_time_tmp[2], alert_time_tmp[3]);

                                            if ( atoi(alert_tmp_minute) > 59 )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] Starting 'alert_time' minute cannot be over 59 in %s at line %d, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                    continue;
                                                }

                                            snprintf(alert_time_all, sizeof(alert_time_all), "%s%s", alert_tmp_hour, alert_tmp_minute);
                                            rulestruct[counters->rulecount].aetas_start = atoi(alert_time_all);

                                            /* End hour */

                                            snprintf(alert_tmp_hour, sizeof(alert_tmp_hour), "%c%c", alert_time_tmp[5], alert_time_tmp[6]);

                                            if ( atoi(alert_tmp_hour) > 23 )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] Ending 'alert_time' hour cannot be over 23 in %s at line %d, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                    continue;
                                                }

                                            snprintf(alert_tmp_minute, sizeof(alert_tmp_minute), "%c%c", alert_time_tmp[7], alert_time_tmp[8]);

                                            if ( atoi(alert_tmp_minute) > 59 )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] Ending 'alert_time' minute cannot be over 59 in %s at line %d, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                    continue;
                                                }

                                            snprintf(alert_time_all, sizeof(alert_time_all), "%s%s", alert_tmp_hour, alert_tmp_minute);

                                            rulestruct[counters->rulecount].aetas_end = atoi(alert_time_all);

                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                                }

                        }


                    /* Threshold */

                    if (!strcmp(rulesplit, "threshold" ))
                        {

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);
                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule2);

                            while( tmptoken != NULL )
                                {

                                    if (Sagan_strstr(tmptoken, "type"))
                                        {

                                            if (Sagan_strstr(tmptoken, "limit"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_type = 1;
                                                }

                                            if (Sagan_strstr(tmptoken, "threshold"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_type = 2;
                                                }
                                        }

                                    if (Sagan_strstr(tmptoken, "track"))
                                        {

                                            if (Sagan_strstr(tmptoken, "by_src"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_src = true;
                                                }

                                            if (Sagan_strstr(tmptoken, "by_dst"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_dst = true;
                                                }

                                            if (Sagan_strstr(tmptoken, "by_username") || Sagan_strstr(tmptoken, "by_string"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_username = true;
                                                }

                                            if (Sagan_strstr(tmptoken, "by_srcport"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_srcport = true;
                                                }

                                            if (Sagan_strstr(tmptoken, "by_dstport"))
                                                {
                                                    rulestruct[counters->rulecount].threshold2_method_dstport = true;
                                                }
                                        }

                                    if (Sagan_strstr(tmptoken, "count"))
                                        {
                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                                            rulestruct[counters->rulecount].threshold2_count = atoi(tmptok_tmp);
                                        }

                                    if (Sagan_strstr(tmptoken, "seconds"))
                                        {
                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3 );
                                            rulestruct[counters->rulecount].threshold2_seconds = atoi(tmptok_tmp);
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);
                                }
                        }

                    /* "after"; similar to thresholding,  but the opposite direction */

                    if (!strcmp(rulesplit, "after" ))
                        {

                            rulestruct[counters->rulecount].after2 = true;

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.  \"after\" options appear incomplete. Abort!", __FILE__, __LINE__, ruleset_fullname, linecount);
                                }


                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule2);

                            while( tmptoken != NULL )
                                {

                                    if (Sagan_strstr(tmptoken, "track"))
                                        {

                                            strtok_r(tmptoken, " ", &after_value1);

                                            if ( after_value1 == NULL )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d]  %s on line %d appears to be incorrect.  \"after\" options appear incomplete. Abort!", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                }

                                            Remove_Return(after_value1);

                                            after_value2 = strtok_r(after_value1, "&", &after_value3);

                                            while ( after_value2 != NULL )
                                                {

                                                    if (!strcmp(after_value2, "by_src"))
                                                        {
                                                            rulestruct[counters->rulecount].after2_method_src = true;
                                                        }

                                                    if (!strcmp(after_value2, "by_dst"))
                                                        {
                                                            rulestruct[counters->rulecount].after2_method_dst = true;
                                                        }

                                                    if (!strcmp(after_value2, "by_username"))
                                                        {
                                                            rulestruct[counters->rulecount].after2_method_username = true;
                                                        }

                                                    if(!strcmp(after_value2, "by_srcport"))
                                                        {
                                                            rulestruct[counters->rulecount].after2_method_srcport  = true;
                                                        }

                                                    if(!strcmp(after_value2, "by_dstport"))
                                                        {
                                                            rulestruct[counters->rulecount].after2_method_dstport  = true;
                                                        }

                                                    after_value2 = strtok_r(NULL, "&", &after_value3);
                                                }
                                        }

                                    if (Sagan_strstr(tmptoken, "count"))
                                        {
                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3);
                                            rulestruct[counters->rulecount].after2_count = atoi(tmptok_tmp);
                                        }

                                    if (Sagan_strstr(tmptoken, "seconds"))
                                        {
                                            tmptok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);
                                            tmptok_tmp = strtok_r(NULL, " ", &saveptrrule3 );
                                            rulestruct[counters->rulecount].after2_seconds = atoi(tmptok_tmp);
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                }
                        }

                    /* Blacklist */

                    if (!strcmp(rulesplit, "blacklist"))
                        {
                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d]  %s on line %d appears to be incorrect.  \"blacklist:\" options appear incomplete, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                    continue;
                                }

                            Remove_Spaces(tok_tmp);

                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule3);

                            while( tmptoken != NULL )
                                {

                                    found = 0;

                                    if (!strcmp(tmptoken, "by_src"))
                                        {
                                            rulestruct[counters->rulecount].blacklist_ipaddr_src = 1;
                                            rulestruct[counters->rulecount].blacklist_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "by_dst"))
                                        {
                                            rulestruct[counters->rulecount].blacklist_ipaddr_dst = 1;
                                            rulestruct[counters->rulecount].blacklist_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "both"))
                                        {
                                            rulestruct[counters->rulecount].blacklist_ipaddr_both = 1;
                                            rulestruct[counters->rulecount].blacklist_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "all"))
                                        {
                                            rulestruct[counters->rulecount].blacklist_ipaddr_all = 1;
                                            rulestruct[counters->rulecount].blacklist_flag = 1;
                                            found = 1;
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule3);
                                }

                        }

                    /* Bro Intel */

                    if (!strcmp(rulesplit, "bro-intel"))
                        {
                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d]  %s on line %d appears to be incorrect.  \"bro-intel:\" options appear incomplete, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                    continue;
                                }

                            Remove_Spaces(tok_tmp);

                            tmptoken = strtok_r(tok_tmp, ",", &saveptrrule3);

                            while( tmptoken != NULL )
                                {

                                    found = 0;

                                    if (!strcmp(tmptoken, "by_src"))
                                        {
                                            rulestruct[counters->rulecount].brointel_ipaddr_src = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "by_dst"))
                                        {
                                            rulestruct[counters->rulecount].brointel_ipaddr_dst = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "both"))
                                        {
                                            rulestruct[counters->rulecount].brointel_ipaddr_both = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "all"))
                                        {
                                            rulestruct[counters->rulecount].brointel_ipaddr_all = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "domain"))
                                        {
                                            rulestruct[counters->rulecount].brointel_domain = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "file_hash"))
                                        {
                                            rulestruct[counters->rulecount].brointel_file_hash = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "url"))
                                        {
                                            rulestruct[counters->rulecount].brointel_url = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "software"))
                                        {
                                            rulestruct[counters->rulecount].brointel_software = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "email"))
                                        {
                                            rulestruct[counters->rulecount].brointel_email = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "user_name"))
                                        {
                                            rulestruct[counters->rulecount].brointel_user_name = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "file_name"))
                                        {
                                            rulestruct[counters->rulecount].brointel_file_name = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if (!strcmp(tmptoken, "cert_hash"))
                                        {
                                            rulestruct[counters->rulecount].brointel_cert_hash = 1;
                                            rulestruct[counters->rulecount].brointel_flag = 1;
                                            found = 1;
                                        }

                                    if ( found == 0 )
                                        {
                                            bad_rule = true;
                                            Sagan_Log(WARN, "[%s, line %d] %s on line %d has an unknown \"brointel\" option \"%s\", skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount, tmptoken);
                                            continue;
                                        }

                                    tmptoken = strtok_r(NULL, ",", &saveptrrule3);
                                }

                        }

                    if (!strcmp(rulesplit, "external"))
                        {

                            tok_tmp = strtok_r(NULL, ":", &saveptrrule2);

                            if ( tok_tmp == NULL )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has 'external' option  but not external 'program' is specified, skipping rule!", __FILE__, __LINE__, ruleset_fullname, linecount);
                                    continue;
                                }

                            Remove_Spaces(tok_tmp);

                            if (stat(tok_tmp, &filecheck) != 0 )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has 'external' option but external program '%s' does not exist, skipping rule!", __FILE__, __LINE__, ruleset_fullname, linecount, tok_tmp);
                                    continue;
                                }

                            if (access(tok_tmp, X_OK) == -1)
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has 'external' option but external program '%s' is not executable, skipping rule!", __FILE__, __LINE__, ruleset_fullname, linecount, tok_tmp);
                                    continue;
                                }

                            rulestruct[counters->rulecount].external_flag = 1;
                            strlcpy(rulestruct[counters->rulecount].external_program, tok_tmp, sizeof(rulestruct[counters->rulecount].external_program));

                        }

#ifdef WITH_BLUEDOT

                    if (!strcmp(rulesplit, "bluedot"))
                        {

                            if ( config->bluedot_flag == 0 )
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has 'bluedot' option enabled,  but 'processor bluedot' is not configured, skipping rule!", __FILE__, __LINE__, ruleset_fullname, linecount);
                                    continue;
                                }

                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                            if (!Sagan_strstr(tmptoken, "type"))
                                {
                                    bad_rule = true;
                                    Sagan_Log(WARN, "[%s, line %d] No Bluedot 'type' found in %s at line %d, skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                                    continue;
                                }

                            if ( Sagan_strstr(tmptoken, "type" ))
                                {

                                    if ( Sagan_strstr(tmptoken, "ip_reputation" ))
                                        {

                                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                            if ( Sagan_strstr(tmptoken, "track" ))
                                                {

                                                    /* 1 == src,  2 == dst,  3 == both,  4 == all */

                                                    if ( Sagan_strstr(tmptoken, "by_src" ))
                                                        {
                                                            rulestruct[counters->rulecount].bluedot_ipaddr_type  = 1;
                                                        }

                                                    if ( Sagan_strstr(tmptoken, "by_dst" ))
                                                        {
                                                            rulestruct[counters->rulecount].bluedot_ipaddr_type  = 2;
                                                        }

                                                    if ( Sagan_strstr(tmptoken, "both" ))
                                                        {
                                                            rulestruct[counters->rulecount].bluedot_ipaddr_type  = 3;
                                                        }

                                                    if ( Sagan_strstr(tmptoken, "all" ))
                                                        {
                                                            rulestruct[counters->rulecount].bluedot_ipaddr_type  = 4;
                                                        }

                                                    if ( rulestruct[counters->rulecount].bluedot_ipaddr_type == 0 )
                                                        {
                                                            bad_rule = true;
                                                            Sagan_Log(WARN, "[%s, line %d] No Bluedot by_src, by_dst, both or all specified in %s at line %d, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                            continue;
                                                        }

                                                }

                                            tmptoken = strtok_r(NULL, ",", &saveptrrule2);

                                            if (!Sagan_strstr(tmptoken, "mdate_effective_period" ) && !Sagan_strstr(tmptoken, "cdate_effective_period" ) && !Sagan_strstr(tmptoken, "none" ))
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] No Bluedot 'mdate_effective_period', 'cdate_effective_period' or 'none' not specified in %s at line %d, skipping rule", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                    continue;
                                                }

                                            if (!Sagan_strstr(tmptoken, "none"))
                                                {

                                                    tok_tmp = strtok_r(tmptoken, " ", &saveptrrule3);

                                                    if (Sagan_strstr(tmptoken, "mdate_effective_period" ))
                                                        {

                                                            bluedot_time = strtok_r(NULL, " ", &saveptrrule3);

                                                            if ( bluedot_time == NULL )
                                                                {
                                                                    bad_rule = true;
                                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has no Bluedot numeric time value, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                    continue;
                                                                }

                                                            bluedot_type = strtok_r(NULL, " ", &saveptrrule3);

                                                            if ( bluedot_type == NULL )
                                                                {
                                                                    bad_rule = true;
                                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has not Bluedot timeframe type (hour, week, month, year, etc) specified, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                    continue;
                                                                }

                                                            Remove_Spaces(bluedot_time);
                                                            Remove_Spaces(bluedot_type);

                                                            bluedot_time_u32 = atol(bluedot_time);

                                                            if ( bluedot_time_u32 == 0 )
                                                                {
                                                                    bad_rule = true;
                                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has no or invalid Bluedot timeframe, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                    continue;
                                                                }

                                                            rulestruct[counters->rulecount].bluedot_mdate_effective_period = Value_To_Seconds(bluedot_type, bluedot_time_u32);
                                                        }
                                                    else if (Sagan_strstr(tmptoken, "cdate_effective_period" ))
                                                        {
                                                            bluedot_time = strtok_r(NULL, " ", &saveptrrule3);

                                                            if ( bluedot_time == NULL )
                                                                {
                                                                    bad_rule = true;
                                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has no Bluedot numeric time value, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                    continue;
                                                                }

                                                            bluedot_type = strtok_r(NULL, " ", &saveptrrule3);

                                                            if ( bluedot_type == NULL )
                                                                {
                                                                    bad_rule = true;
                                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has not Bluedot timeframe type (hour, week, month, year, etc) specified, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                    continue;
                                                                }

                                                            Remove_Spaces(bluedot_time);
                                                            Remove_Spaces(bluedot_type);

                                                            bluedot_time_u32 = atol(bluedot_time);

                                                            if ( bluedot_time_u32 == 0 )
                                                                {
                                                                    bad_rule = true;
                                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has no or invalid Bluedot timeframe, skipping rule.", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                                    continue;
                                                                }

                                                            rulestruct[counters->rulecount].bluedot_cdate_effective_period = Value_To_Seconds(bluedot_type, bluedot_time_u32);
                                                        }

                                                }
                                            else
                                                {

                                                    rulestruct[counters->rulecount].bluedot_mdate_effective_period = 0;
                                                    rulestruct[counters->rulecount].bluedot_cdate_effective_period = 0;

                                                }

                                            tmptoken = strtok_r(NULL, ";", &saveptrrule2);

                                            if ( tmptoken == NULL )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has no Bluedot categories defined, skipping rule!", __FILE__, __LINE__, ruleset_fullname, linecount);
                                                    continue;
                                                }

                                            Remove_Spaces(tmptoken);

                                            Sagan_Verify_Categories( tmptoken, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_IP);


                                        }

                                    if ( Sagan_strstr(tmptoken, "file_hash" ))
                                        {
                                            rulestruct[counters->rulecount].bluedot_file_hash = 1;

                                            tmptok_tmp = strtok_r(NULL, ";", &saveptrrule2);   /* Support var's */

                                            if ( tmptok_tmp == NULL )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has no Bluedot categories defined, skipping rule!", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                                                    continue;
                                                }

                                            Var_To_Value(tmptok_tmp, tmp1, sizeof(tmp1));

                                            Sagan_Verify_Categories( tmp1, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_HASH);
                                        }

                                    if ( Sagan_strstr(tmptoken, "url" ))

                                        {
                                            rulestruct[counters->rulecount].bluedot_url = 1;

                                            tmptok_tmp = strtok_r(NULL, ";", &saveptrrule2);   /* Support var's */

                                            if ( tmptok_tmp == NULL )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has no Bluedot categories defined, skipping rule!", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                                                    continue;
                                                }

                                            Var_To_Value(tmptok_tmp, tmp1, sizeof(tmp1));

                                            Sagan_Verify_Categories( tmp1, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_URL);
                                        }


                                    if ( Sagan_strstr(tmptoken, "filename" ))
                                        {
                                            rulestruct[counters->rulecount].bluedot_filename = 1;

                                            tmptok_tmp = strtok_r(NULL, ";", &saveptrrule2);   /* Support var's */

                                            if ( tmptok_tmp == NULL )
                                                {
                                                    bad_rule = true;
                                                    Sagan_Log(WARN, "[%s, line %d] %s at line %d has no Bluedot categories defined, skipping rule!", __FILE__, __LINE__, ruleset_fullname, linecount, tmptok_tmp);
                                                    continue;
                                                }

                                            Var_To_Value(tmptok_tmp, tmp1, sizeof(tmp1));

                                            Sagan_Verify_Categories( tmp1, counters->rulecount, ruleset_fullname, linecount, BLUEDOT_LOOKUP_FILENAME);
                                        }

                                    /* Error  check (  set flag? */
                                }
                        }

#endif

#ifndef WITH_BLUEDOT

                    if (!strcmp(rulesplit, "bluedot"))
                        {
                            bad_rule = true;
                            Sagan_Log(WARN, "%s has Bluedot rules,  but support isn't compiled in, skipping rule!", ruleset_fullname);
                            continue;
                        }
#endif


                    /* -< Go to next line >- */

                    tokenrule = strtok_r(NULL, ";", &saveptrrule1);
                }

            if (bad_rule)
                {
                    continue;
                }

            /* Some new stuff (normalization) stuff needs to be added */

            if ( debug->debugload )
                {

                    Sagan_Log(DEBUG, "---[Rule %" PRIu64 "]------------------------------------------------------", rulestruct[counters->rulecount].s_sid);


                    Sagan_Log(DEBUG, "= Position: %d", counters->rulecount);
                    Sagan_Log(DEBUG, "= SID: %" PRIu64 "", rulestruct[counters->rulecount].s_sid);
                    Sagan_Log(DEBUG, "= Rev: %d", rulestruct[counters->rulecount].s_rev);
                    Sagan_Log(DEBUG, "= Msg: %s", rulestruct[counters->rulecount].s_msg);
                    Sagan_Log(DEBUG, "= Pri: %d", rulestruct[counters->rulecount].s_pri);
                    Sagan_Log(DEBUG, "= Classtype: %s", rulestruct[counters->rulecount].s_classtype);
                    Sagan_Log(DEBUG, "= Drop: %d", rulestruct[counters->rulecount].drop);
                    Sagan_Log(DEBUG, "= default_dst_port: %d", rulestruct[counters->rulecount].default_dst_port);

                    if ( rulestruct[counters->rulecount].s_find_src_ip != 0 )
                        {
                            Sagan_Log(DEBUG, "= parse_src_ip");
                        }

                    if ( rulestruct[counters->rulecount].s_find_port != 0 )
                        {
                            Sagan_Log(DEBUG, "= parse_port");
                        }

                    for (i=0; i<content_count; i++)
                        {
                            Sagan_Log(DEBUG, "= [%d] content: \"%s\"", i, rulestruct[counters->rulecount].s_content[i]);
                        }

                    for (i=0; i<ref_count; i++)
                        {
                            Sagan_Log(DEBUG, "= [%d] reference: \"%s\"", i,  rulestruct[counters->rulecount].s_reference[i]);
                        }
                }

            __atomic_add_fetch(&counters->rulecount, 1,  __ATOMIC_SEQ_CST);

        } /* end of while loop */

    fclose(rulesfile);
}
