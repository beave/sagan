/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-engine.c
 *
 * Threaded ngine that looks for events & patterns * based on
 * 'snort like' rule sets.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "sagan.h"
#include "sagan-aetas.h"
#include "sagan-meta-content.h"
#include "sagan-send-alert.h"
#include "sagan-flowbit.h"
#include "sagan-rules.h"
#include "sagan-config.h"

#include "parsers/parsers.h"

#include "processors/sagan-engine.h"
#include "processors/sagan-bro-intel.h"
#include "processors/sagan-blacklist.h"

#ifdef WITH_WEBSENSE
#include "processors/sagan-websense.h"
#endif

#ifdef WITH_BLUEDOT
#include "processors/sagan-bluedot.h"
#endif

#ifdef HAVE_LIBLOGNORM
#include "sagan-liblognorm.h"
struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm;
pthread_mutex_t Lognorm_Mutex;
#endif

#ifdef HAVE_LIBMAXMINDDB
#include <sagan-geoip2.h>
#endif

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;
struct _Sagan_Flowbits *flowbits;

pthread_mutex_t AfterMutexSrc=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t AfterMutexDst=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t ThreshMutexSrc=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ThreshMutexDst=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t CounterMutex=PTHREAD_MUTEX_INITIALIZER;

/* Global? Was local */

struct after_by_src *afterbysrc = NULL;
struct after_by_dst *afterbydst = NULL;

int  after_count_by_src=0;
int  after_count_by_dst=0;

struct thresh_by_src *threshbysrc = NULL;
struct thresh_by_dst *threshbydst = NULL;

int  thresh_count_by_src=0;
int  thresh_count_by_dst=0;

sbool flowbit_return = 0;
sbool geoip2_isset = 0;

int   alert_time_return = 0;
int   alert_time_trigger = 0;

#ifdef HAVE_LIBMAXMINDDB
int   geoip2_return = 0;
#endif

void Sagan_Engine_Init ( void )
{

#ifdef HAVE_LIBLOGNORM
    SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));
    memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));
#endif

}

int Sagan_Engine ( _SaganProcSyslog *SaganProcSyslog_LOCAL )
{

    struct _Sagan_Processor_Info *processor_info_engine = NULL;
    processor_info_engine = malloc(sizeof(struct _Sagan_Processor_Info));
    memset(processor_info_engine, 0, sizeof(_Sagan_Processor_Info));

    int processor_info_engine_src_port = 0;
    int processor_info_engine_dst_port = 0;
    int processor_info_engine_proto = 0;
    int processor_info_engine_alertid = 0;

    sbool after_log_flag=0;
    sbool after_flag=0;

    int   threadid=0;
    int i=0;
    int b=0;
    int z=0;
    int match=0;
    int sagan_match=0;				/* Used to determine if all has "matched" (content, pcre, meta_content, etc) */
    int rc=0;
    int ovector[PCRE_OVECCOUNT];
    int  src_port;
    int  dst_port;
    int  alter_num;

    char *ptmp;
    char *tok2;
    char *username = NULL;
    char *filehash = NULL;
    char *url = NULL;
    char *filename = NULL;
//  char *uid = NULL;

    char ip_src[MAXIP] = { 0 };
    sbool ip_src_flag = 0;
    uint32_t ip_src_u32;

    char ip_dst[MAXIP] = { 0 };
    sbool ip_dst_flag = 0;
    uint32_t ip_dst_u32;

    char tmpbuf[128];
    char s_msg[1024];
    char alter_content[MAX_SYSLOGMSG];

    time_t t;
    struct tm *now;
    char  timet[20];

    uint64_t thresh_oldtime_src;
    uint64_t after_oldtime_src;

    sbool thresh_flag=0;
    sbool thresh_log_flag=0;

    int proto = config->sagan_proto;		/* Set proto to default */

    sbool brointel_results = 0;
    sbool blacklist_results = 0;

#ifdef WITH_WEBSENSE
    int websense_results;
    sbool websense_flag;
#endif

#ifdef WITH_BLUEDOT
    int bluedot_results;
    sbool bluedot_ip_flag;
    sbool bluedot_hash_flag;
    sbool bluedot_url_flag;
    sbool bluedot_filename_flag;
#endif


    /* This needs to be included,  even if liblognorm isn't in use */

    sbool liblognorm_status = 0;

    /* Search for matches */

    /* First we search for 'program' and such.   This way,  we don't waste CPU
     * time with pcre/content.  */

    for(b=0; b < counters->rulecount; b++)
        {

            match = 0;

            if ( strcmp(rulestruct[b].s_program, "" ))
                {
                    strlcpy(tmpbuf, rulestruct[b].s_program, sizeof(tmpbuf));
                    ptmp = strtok_r(tmpbuf, "|", &tok2);
                    match=1;
                    while ( ptmp != NULL )
                        {
                            if ( Sagan_Wildcard(ptmp, SaganProcSyslog_LOCAL->syslog_program) == 1 )
                                {
                                    match = 0;
                                }

                            ptmp = strtok_r(NULL, "|", &tok2);
                        }
                }

            if ( strcmp(rulestruct[b].s_facility, "" ))
                {
                    strlcpy(tmpbuf, rulestruct[b].s_facility, sizeof(tmpbuf));
                    ptmp = strtok_r(tmpbuf, "|", &tok2);
                    match=1;
                    while ( ptmp != NULL )
                        {
                            if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_facility))
                                {
                                    match=0;
                                }

                            ptmp = strtok_r(NULL, "|", &tok2);
                        }
                }

            if ( strcmp(rulestruct[b].s_syspri, "" ))
                {
                    strlcpy(tmpbuf, rulestruct[b].s_syspri, sizeof(tmpbuf));
                    ptmp = strtok_r(tmpbuf, "|", &tok2);
                    match=1;
                    while ( ptmp != NULL )
                        {
                            if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_priority))
                                {
                                    match=0;
                                }

                            ptmp = strtok_r(NULL, "|", &tok2);
                        }
                }

            if ( strcmp(rulestruct[b].s_level, "" ))
                {
                    strlcpy(tmpbuf, rulestruct[b].s_level, sizeof(tmpbuf));
                    ptmp = strtok_r(tmpbuf, "|", &tok2);
                    match=1;
                    while ( ptmp != NULL )
                        {
                            if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_level))
                                {
                                    match=0;
                                }

                            ptmp = strtok_r(NULL, "|", &tok2);
                        }
                }

            if ( strcmp(rulestruct[b].s_tag, "" ))
                {
                    strlcpy(tmpbuf, rulestruct[b].s_tag, sizeof(tmpbuf));
                    ptmp = strtok_r(tmpbuf, "|", &tok2);
                    match=1;
                    while ( ptmp != NULL )
                        {
                            if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_tag))
                                {
                                    match=0;
                                }

                            ptmp = strtok_r(NULL, "|", &tok2);
                        }
                }

            /* If there has been a match above,  or NULL on all,  then we continue with
             * PCRE/content search */

            /* Search via strstr (content:) */

            if ( match == 0 )
                {

                    if ( rulestruct[b].content_count != 0 )
                        {

                            for(z=0; z<rulestruct[b].content_count; z++)
                                {


                                    /* Content: OFFSET */

                                    alter_num = 0;

                                    if ( rulestruct[b].s_offset[z] != 0 )
                                        {

                                            if ( strlen(SaganProcSyslog_LOCAL->syslog_message) > rulestruct[b].s_offset[z] )
                                                {

                                                    alter_num = strlen(SaganProcSyslog_LOCAL->syslog_message) - rulestruct[b].s_offset[z];
                                                    strlcpy(alter_content, SaganProcSyslog_LOCAL->syslog_message + (strlen(SaganProcSyslog_LOCAL->syslog_message) - alter_num), alter_num + 1);

                                                }
                                            else
                                                {

                                                    alter_content[0] = '\0'; 	/* The offset is larger than the message.  Set content too NULL */

                                                }


                                        }
                                    else
                                        {

                                            strlcpy(alter_content, SaganProcSyslog_LOCAL->syslog_message, sizeof(alter_content));

                                        }

                                    /* Content: DEPTH */

                                    if ( rulestruct[b].s_depth[z] != 0 )
                                        {

                                            /* We do +2 to account for alter_count[0] and whitespace at the begin of syslog message */

                                            strlcpy(alter_content, alter_content, rulestruct[b].s_depth[z] + 2);

                                        }

                                    /* Content: DISTANCE */

                                    if ( z > 0 && rulestruct[b].s_distance[z] != 0 && rulestruct[b].s_depth[z-1] != 0 )
                                        {

                                            alter_num = strlen(SaganProcSyslog_LOCAL->syslog_message) - ( rulestruct[b].s_depth[z-1] + rulestruct[b].s_distance[z] + 1);
                                            strlcpy(alter_content, SaganProcSyslog_LOCAL->syslog_message + (strlen(SaganProcSyslog_LOCAL->syslog_message) - alter_num), alter_num + 1);

                                            /* Content: WITHIN */

                                            if ( rulestruct[b].s_within[z] != 0 )
                                                {
                                                    strlcpy(alter_content, alter_content, rulestruct[b].s_within[z] + 1);

                                                }

                                        }

                                    /* If case insensitive */
                                    if ( rulestruct[b].s_nocase[z] == 1 )
                                        {

                                            if (rulestruct[b].content_not[z] != 1 && Sagan_stristr(alter_content, rulestruct[b].s_content[z], false))

                                                {
                                                    sagan_match++;
                                                }
                                            else
                                                {
                                                    /* for content: ! */
                                                    if ( rulestruct[b].content_not[z] == 1 && !Sagan_stristr(alter_content, rulestruct[b].s_content[z], false)) sagan_match++;

                                                }
                                        }
                                    else
                                        {

                                            /* If case sensitive */
                                            if ( rulestruct[b].content_not[z] != 1 && Sagan_strstr(alter_content, rulestruct[b].s_content[z] ))
                                                {
                                                    sagan_match++;
                                                }
                                            else
                                                {
                                                    /* for content: ! */
                                                    if ( rulestruct[b].content_not[z] == 1 && !Sagan_strstr(alter_content, rulestruct[b].s_content[z])) sagan_match++;

                                                }
                                        }
                                }
                        }

                    /* Search via PCRE */

                    /* Note:  We verify each "step" has succeeded before function execution.  For example,
                     * if there is a "content",  but that has failed,  there is no point in doing the
                     * pcre or meta_content. */

                    if ( rulestruct[b].pcre_count != 0 && sagan_match == rulestruct[b].content_count )
                        {

                            for(z=0; z<rulestruct[b].pcre_count; z++)
                                {

                                    rc = pcre_exec( rulestruct[b].re_pcre[z], rulestruct[b].pcre_extra[z], SaganProcSyslog_LOCAL->syslog_message, (int)strlen(SaganProcSyslog_LOCAL->syslog_message), 0, 0, ovector, PCRE_OVECCOUNT);

                                    if ( rc == 1 ) sagan_match++;

                                }  /* End of pcre if */
                        }

                    /* Search via meta_content */

                    if ( rulestruct[b].meta_content_count != 0 && sagan_match == rulestruct[b].content_count + rulestruct[b].pcre_count )
                        {

                            for (z=0; z<rulestruct[b].meta_content_count; z++)
                                {

                                    rc = Sagan_Meta_Content_Search(SaganProcSyslog_LOCAL->syslog_message, b);

                                    if ( rc == 1 ) sagan_match++;

                                }
                        }



                } /* End of content: & pcre */

            /* if you got match */

            if ( sagan_match == rulestruct[b].pcre_count + rulestruct[b].content_count + rulestruct[b].meta_content_count )
                {

                    if ( match == 0 )
                        {

                            ip_src_flag = 0;
                            ip_dst_flag = 0;

                            dst_port=0;
                            src_port=0;

                            filehash = NULL;
                            url = NULL;
                            username = NULL;
                            filename = NULL;
//		   uid=NULL;

#ifdef HAVE_LIBLOGNORM
                            if ( rulestruct[b].normalize == 1 && counters->liblognormtoload_count != 0 )
                                {

                                    pthread_mutex_lock(&Lognorm_Mutex);

                                    liblognorm_status = 0;

                                    Sagan_Normalize_Liblognorm(SaganProcSyslog_LOCAL->syslog_message);

                                    if (SaganNormalizeLiblognorm->ip_src[0] != '0')
                                        {
                                            strlcpy(ip_src, SaganNormalizeLiblognorm->ip_src, sizeof(ip_src));
                                            ip_src_flag = 1;
                                            liblognorm_status = 1;
                                        }


                                    if (SaganNormalizeLiblognorm->ip_dst[0] != '0' )
                                        {
                                            strlcpy(ip_dst, SaganNormalizeLiblognorm->ip_dst, sizeof(ip_dst));
                                            ip_dst_flag = 1;
                                            liblognorm_status = 1;
                                        }

                                    if ( SaganNormalizeLiblognorm->src_port != 0 )
                                        {
                                            src_port = SaganNormalizeLiblognorm->src_port;
                                            liblognorm_status = 1;
                                        }

                                    if ( SaganNormalizeLiblognorm->dst_port != 0 )
                                        {
                                            dst_port = SaganNormalizeLiblognorm->dst_port;
                                            liblognorm_status = 1;
                                        }

                                    if ( SaganNormalizeLiblognorm->username[0] != '\0' )
                                        {
                                            username = SaganNormalizeLiblognorm->username;
                                            liblognorm_status = 1;
                                        }

                                    if ( SaganNormalizeLiblognorm->url[0] != '\0' )
                                        {
                                            url = SaganNormalizeLiblognorm->url;
                                            liblognorm_status = 1;
                                        }

                                    if ( SaganNormalizeLiblognorm->filename[0] != '\0' )
                                        {
                                            filename = SaganNormalizeLiblognorm->filename;
                                            liblognorm_status = 1;
                                        }

                                    /* We want SHA256 over anthing else. */

                                    if ( SaganNormalizeLiblognorm->filehash_sha256[0] != '\0' )
                                        {
                                            filehash = SaganNormalizeLiblognorm->filehash_sha256;
                                            liblognorm_status = 1;
                                        }

                                    else if ( SaganNormalizeLiblognorm->filehash_sha1[0] != '\0' )
                                        {

                                            filehash = SaganNormalizeLiblognorm->filehash_sha1;
                                            liblognorm_status = 1;

                                        }

                                    else if ( SaganNormalizeLiblognorm->filehash_md5[0] != '\0' )
                                        {

                                            filehash = SaganNormalizeLiblognorm->filehash_md5;
                                            liblognorm_status = 1;

                                        }

//		  			 uid = SaganNormalizeLiblognorm->uid;

                                    pthread_mutex_unlock(&Lognorm_Mutex);

                                }

#endif

                            /* Normalization should always over ride parse_src_ip/parse_dst_ip/parse_port,
                             * _unless_ liblognorm fails and both are in a rule */

                            if ( rulestruct[b].normalize == 0 || (rulestruct[b].normalize == 1 && liblognorm_status == 0 ) )
                                {

                                    /* parse_src_ip: {position} */

                                    if ( rulestruct[b].s_find_src_ip == 1 )
                                        {
                                            strlcpy(ip_src, Sagan_Parse_IP(SaganProcSyslog_LOCAL->syslog_message, rulestruct[b].s_find_src_pos), sizeof(ip_src));
                                            ip_src_flag = 1;
                                        }

                                    /* parse_dst_ip: {postion} */

                                    if ( rulestruct[b].s_find_dst_ip == 1 )
                                        {
                                            strlcpy(ip_dst, Sagan_Parse_IP(SaganProcSyslog_LOCAL->syslog_message, rulestruct[b].s_find_dst_pos), sizeof(ip_dst));
                                            ip_dst_flag = 1;
                                        }

                                    /* parse_port */

                                    if ( rulestruct[b].s_find_port == 1 )
                                        {
                                            src_port = Sagan_Parse_Port(SaganProcSyslog_LOCAL->syslog_message);
                                        }
                                    else
                                        {
                                            src_port = config->sagan_port;
                                        }
                                }


                            /* If the rule calls for proto searching,  we do it now */

                            proto = 0;

                            if ( rulestruct[b].s_find_proto_program == 1 )
                                {
                                    proto = Sagan_Parse_Proto_Program(SaganProcSyslog_LOCAL->syslog_program);
                                }

                            if ( rulestruct[b].s_find_proto == 1 && proto == 0 )
                                {
                                    proto = Sagan_Parse_Proto(SaganProcSyslog_LOCAL->syslog_message);
                                }

                            /* If proto is not searched or has failed,  default to whatever the rule told us to
                               use */

                            if ( proto == 0 )
                                {
                                    proto = rulestruct[b].ip_proto;
                                }

                            if ( ip_src_flag == 0 || ip_src[0] == '0' )
                                {
                                    strlcpy(ip_src, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_src));
                                }

                            if ( ip_dst_flag == 0 || ip_dst[0] == '0' )
                                {
                                    strlcpy(ip_dst, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_dst));
                                }

                            if ( src_port == 0 ) src_port=config->sagan_port;
                            if ( dst_port == 0 ) dst_port=rulestruct[b].dst_port;
                            if ( proto == 0 ) proto = config->sagan_proto;		/* Rule didn't specify proto,  use sagan default! */

                            /* If the "source" is 127.0.0.1 that is not useful.  Replace with config->sagan_host
                             * (defined by user in sagan.conf */

                            if ( !strcmp(ip_src, "127.0.0.1") || !strcmp(ip_dst, "::1") )
                                {
                                    strlcpy(ip_src, config->sagan_host, sizeof(ip_src));
                                }

                            if ( !strcmp(ip_dst, "127.0.0.1") || !strcmp(ip_dst, "::1" ) )
                                {
                                    strlcpy(ip_dst, config->sagan_host, sizeof(ip_dst));
                                }

                            ip_src_u32 = IP2Bit(ip_src);
                            ip_dst_u32 = IP2Bit(ip_dst);

                            strlcpy(s_msg, rulestruct[b].s_msg, sizeof(s_msg));


                            /****************************************************************************
                             * Flowbit
                             ****************************************************************************/

                            if ( rulestruct[b].flowbit_flag && rulestruct[b].flowbit_condition_count )
                                {
                                    flowbit_return = Sagan_Flowbit_Condition(b, ip_src, ip_dst);
                                }

                            /****************************************************************************
                             * Country code
                             ****************************************************************************/

#ifdef HAVE_LIBMAXMINDDB

                            if ( rulestruct[b].geoip2_flag )
                                {

                                    geoip2_isset = 0; 		/* Reset,  so we dont use previous value */

                                    if ( rulestruct[b].geoip2_src_or_dst == 1 )
                                        {
                                            geoip2_return = Sagan_GeoIP2_Lookup_Country(ip_src, b);
                                        }
                                    else
                                        {
                                            geoip2_return = Sagan_GeoIP2_Lookup_Country(ip_dst, b);
                                        }

                                    if ( geoip2_return != 2 )
                                        {

                                            /* If country IS NOT {my value} return 1 */

                                            if ( rulestruct[b].geoip2_type == 1 )    		/* isnot */
                                                {

                                                    if ( geoip2_return == 1 )
                                                        {
                                                            geoip2_isset = 0;
                                                        }
                                                    else
                                                        {
                                                            geoip2_isset = 1;
                                                            counters->geoip2_hit++;
                                                        }
                                                }

                                            /* If country IS {my value} return 1 */

                                            if ( rulestruct[b].geoip2_type == 2 )             /* is */
                                                {

                                                    if ( geoip2_return == 1 )
                                                        {
                                                            geoip2_isset = 1;
                                                            counters->geoip2_hit++;
                                                        }
                                                    else
                                                        {
                                                            geoip2_isset = 0;
                                                        }
                                                }
                                        }
                                }

#endif

                            /****************************************************************************
                             * Time based alerting
                             ****************************************************************************/

                            if ( rulestruct[b].alert_time_flag )
                                {

                                    alert_time_trigger = 0;

                                    if (  Sagan_Check_Time(b) )
                                        {
                                            alert_time_trigger = 1;
                                        }
                                }

                            /****************************************************************************
                             * Blacklist
                             ****************************************************************************/

                            if ( rulestruct[b].blacklist_flag )
                                {

                                    blacklist_results = 0;

                                    if ( rulestruct[b].blacklist_ipaddr_src )
                                        {
                                            blacklist_results = Sagan_Blacklist_IPADDR( ip_src_u32 );
                                        }

                                    if ( blacklist_results == 0 && rulestruct[b].blacklist_ipaddr_dst )
                                        {
                                            blacklist_results = Sagan_Blacklist_IPADDR( ip_dst_u32 );
                                        }

                                    if ( blacklist_results == 0 && rulestruct[b].blacklist_ipaddr_all )
                                        {
                                            blacklist_results = Sagan_Blacklist_IPADDR_All(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( blacklist_results == 0 && rulestruct[b].blacklist_ipaddr_both )
                                        {
                                            if ( Sagan_Blacklist_IPADDR( ip_src_u32 ) || Sagan_Blacklist_IPADDR( ip_dst_u32 ) )
                                                {
                                                    blacklist_results = 1;
                                                }
                                        }
                                }


#ifdef WITH_WEBSENSE

                            if ( config->websense_flag && rulestruct[b].websense_ipaddr_type )
                                {

                                    websense_results = 0;

                                    /* 1 == src,  2 == dst,  3 == both,  4 == all */

                                    if ( rulestruct[b].websense_ipaddr_type == 1 )
                                        {
                                            websense_results = Sagan_Websense_Lookup(ip_src);
                                            websense_flag = Sagan_Websense_Cat_Compare( websense_results, b);
                                        }

                                    if ( rulestruct[b].websense_ipaddr_type == 2 )
                                        {
                                            websense_results = Sagan_Websense_Lookup(ip_dst);
                                            websense_flag = Sagan_Websense_Cat_Compare( websense_results, b);
                                        }

                                    if ( rulestruct[b].websense_ipaddr_type == 3 )
                                        {

                                            websense_results = Sagan_Websense_Lookup(ip_src);
                                            websense_flag = Sagan_Websense_Cat_Compare( websense_results, b);

                                            /* If the source isn't found,  then check the dst */

                                            if ( websense_flag != 0 )
                                                {
                                                    websense_results = Sagan_Websense_Lookup(ip_dst);
                                                    websense_flag = Sagan_Websense_Cat_Compare( websense_results, b);
                                                }

                                        }

                                    if ( rulestruct[b].websense_ipaddr_type == 4 )
                                        {

                                            websense_flag = Sagan_Websense_Lookup_All(SaganProcSyslog_LOCAL->syslog_message, b);

                                        }

                                    /* Do cleanup at the end in case any "hits" above refresh the cache.  This why we don't
                                     * "delete" an entry only to re-add it! */

                                    Sagan_Websene_Check_Cache_Time();

                                }

                            if ( debug->debugwebsense )
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] Websense flag: %d", __FILE__, __LINE__, websense_flag);
                                }

#endif

#ifdef WITH_BLUEDOT

                            if ( config->bluedot_flag )
                                {
                                    if ( rulestruct[b].bluedot_ipaddr_type )
                                        {

                                            bluedot_results = 0;

                                            /* 1 == src,  2 == dst,  3 == both,  4 == all */

                                            if ( rulestruct[b].bluedot_ipaddr_type == 1 )
                                                {
                                                    bluedot_results = Sagan_Bluedot_Lookup(ip_src, BLUEDOT_LOOKUP_IP);
                                                    bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                }

                                            if ( rulestruct[b].bluedot_ipaddr_type == 2 )
                                                {
                                                    bluedot_results = Sagan_Bluedot_Lookup(ip_dst, BLUEDOT_LOOKUP_IP);
                                                    bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                }

                                            if ( rulestruct[b].bluedot_ipaddr_type == 3 )
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup(ip_src, BLUEDOT_LOOKUP_IP);
                                                    bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);

                                                    /* If the source isn't found,  then check the dst */

                                                    if ( bluedot_ip_flag != 0 )
                                                        {
                                                            bluedot_results = Sagan_Bluedot_Lookup(ip_dst, BLUEDOT_LOOKUP_IP);
                                                            bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                        }

                                                }

                                            if ( rulestruct[b].bluedot_ipaddr_type == 4 )
                                                {

                                                    bluedot_ip_flag = Sagan_Bluedot_IP_Lookup_All(SaganProcSyslog_LOCAL->syslog_message, b);

                                                }

                                        }


                                    if ( rulestruct[b].bluedot_file_hash && filehash != NULL )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( filehash, BLUEDOT_LOOKUP_HASH);
                                            bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH);

                                        }

                                    if ( rulestruct[b].bluedot_url && url != NULL )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( url, BLUEDOT_LOOKUP_URL);
                                            bluedot_url_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_URL);

                                        }

                                    if ( rulestruct[b].bluedot_filename && filename != NULL )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( url, BLUEDOT_LOOKUP_FILENAME);
                                            bluedot_filename_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_FILENAME);

                                        }

                                    /* Do cleanup at the end in case any "hits" above refresh the cache.  This why we don't
                                     * "delete" an entry only to re-add it! */

                                    Sagan_Bluedot_Check_Cache_Time();


                                }
#endif


                            /****************************************************************************
                            * Bro Intel
                            ****************************************************************************/

                            if ( rulestruct[b].brointel_flag )
                                {

                                    brointel_results = 0;

                                    if ( rulestruct[b].brointel_ipaddr_src )
                                        {
                                            brointel_results = Sagan_BroIntel_IPADDR( ip_src_u32 );
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_ipaddr_dst )
                                        {
                                            brointel_results = Sagan_BroIntel_IPADDR( ip_dst_u32 );
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_ipaddr_all )
                                        {
                                            brointel_results = Sagan_BroIntel_IPADDR_All ( SaganProcSyslog_LOCAL->syslog_message );
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_ipaddr_both )
                                        {
                                            if ( Sagan_BroIntel_IPADDR( ip_src_u32 ) || Sagan_BroIntel_IPADDR( ip_dst_u32 ) )
                                                {
                                                    brointel_results = 1;
                                                }
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_domain )
                                        {
                                            brointel_results = Sagan_BroIntel_DOMAIN(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_file_hash )
                                        {
                                            brointel_results = Sagan_BroIntel_FILE_HASH(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_url )
                                        {
                                            brointel_results = Sagan_BroIntel_URL(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_software )
                                        {
                                            brointel_results = Sagan_BroIntel_SOFTWARE(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_user_name )
                                        {
                                            brointel_results = Sagan_BroIntel_USER_NAME(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_file_name )
                                        {
                                            brointel_results = Sagan_BroIntel_FILE_NAME(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( brointel_results == 0 && rulestruct[b].brointel_cert_hash )
                                        {
                                            brointel_results = Sagan_BroIntel_CERT_HASH(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                }

                            /****************************************************************************/
                            /* Populate the SaganEvent array with the information needed.  This info    */
                            /* will be passed to the threads.  No need to populate it _if_ we're in a   */
                            /* threshold state.                                                         */
                            /****************************************************************************/

                            if ( rulestruct[b].flowbit_flag == 0 ||
                                    ( rulestruct[b].flowbit_flag && rulestruct[b].flowbit_set_count && rulestruct[b].flowbit_condition_count == 0 ) ||
                                    ( rulestruct[b].flowbit_flag && rulestruct[b].flowbit_set_count && rulestruct[b].flowbit_condition_count && flowbit_return ) ||
                                    ( rulestruct[b].flowbit_flag && rulestruct[b].flowbit_set_count == 0 && rulestruct[b].flowbit_condition_count && flowbit_return ))
                                {

                                    if ( rulestruct[b].alert_time_flag == 0 || alert_time_trigger == 1 )
                                        {

#ifdef HAVE_LIBMAXMINDDB
                                            if ( rulestruct[b].geoip2_flag == 0 || geoip2_isset == 1 )
                                                {
#endif
                                                    if ( rulestruct[b].blacklist_flag == 0 || blacklist_results == 1 )
                                                        {

                                                            if ( rulestruct[b].brointel_flag == 0 || brointel_results == 1)
                                                                {
#ifdef WITH_WEBSENSE
                                                                    if ( ( config->websense_flag == 0 || rulestruct[b].websense_ipaddr_type == 0 ) ||  websense_flag == 1 )
                                                                        {
#endif

#ifdef WITH_BLUEDOT


                                                                            if ( config->bluedot_flag == 0 || rulestruct[b].bluedot_file_hash == 0 || ( rulestruct[b].bluedot_file_hash == 1 && bluedot_hash_flag == 1 ))
                                                                                {

                                                                                    if ( config->bluedot_flag == 0 || rulestruct[b].bluedot_filename == 0 || ( rulestruct[b].bluedot_filename == 1 && bluedot_filename_flag == 1 ))
                                                                                        {

                                                                                            if ( config->bluedot_flag == 0 || rulestruct[b].bluedot_url == 0 || ( rulestruct[b].bluedot_url == 1 && bluedot_url_flag == 1 ))
                                                                                                {

                                                                                                    if ( config->bluedot_flag == 0 || rulestruct[b].bluedot_ipaddr_type == 0 || ( rulestruct[b].bluedot_ipaddr_type != 0 && bluedot_ip_flag == 1 ))
                                                                                                        {



#endif


                                                                                                            after_log_flag=0;

                                                                                                            /*********************************************************/
                                                                                                            /* After - Similar to thresholding,  but the opposite    */
                                                                                                            /* direction - ie - alert _after_ X number of events     */
                                                                                                            /*********************************************************/

                                                                                                            if ( rulestruct[b].after_src_or_dst != 0 )
                                                                                                                {

                                                                                                                    after_log_flag=1;

                                                                                                                    t = time(NULL);
                                                                                                                    now=localtime(&t);
                                                                                                                    strftime(timet, sizeof(timet), "%s",  now);

                                                                                                                    /* After by source IP address */

                                                                                                                    if ( rulestruct[b].after_src_or_dst == 1 )
                                                                                                                        {
                                                                                                                            after_flag = 0;

                                                                                                                            for (i = 0; i < after_count_by_src; i++ )
                                                                                                                                {
                                                                                                                                    if ( afterbysrc[i].ipsrc == ip_src_u32  && !strcmp(afterbysrc[i].sid, rulestruct[b].s_sid ))
                                                                                                                                        {

                                                                                                                                            after_flag=1;

                                                                                                                                            pthread_mutex_lock(&AfterMutexSrc);

                                                                                                                                            afterbysrc[i].count++;
                                                                                                                                            after_oldtime_src = atol(timet) - afterbysrc[i].utime;
                                                                                                                                            afterbysrc[i].utime = atol(timet);

                                                                                                                                            if ( after_oldtime_src > rulestruct[b].after_seconds )
                                                                                                                                                {
                                                                                                                                                    afterbysrc[i].count=1;
                                                                                                                                                    afterbysrc[i].utime = atol(timet);
                                                                                                                                                    after_log_flag=1;
                                                                                                                                                }

                                                                                                                                            pthread_mutex_unlock(&AfterMutexSrc);

                                                                                                                                            if ( rulestruct[b].after_count < afterbysrc[i].count )
                                                                                                                                                {
                                                                                                                                                    after_log_flag = 0;

                                                                                                                                                    if ( debug->debuglimits )
                                                                                                                                                        {
                                                                                                                                                            Sagan_Log(S_NORMAL, "After SID %s by source IP address. [%s]", afterbysrc[i].sid, ip_src);
                                                                                                                                                        }


                                                                                                                                                    pthread_mutex_lock(&CounterMutex);
                                                                                                                                                    counters->after_total++;
                                                                                                                                                    pthread_mutex_unlock(&CounterMutex);
                                                                                                                                                }

                                                                                                                                        }
                                                                                                                                }
                                                                                                                        }


                                                                                                                    /* If not found,  add it to the array */

                                                                                                                    if ( after_flag == 0 )
                                                                                                                        {

                                                                                                                            pthread_mutex_lock(&AfterMutexSrc);

                                                                                                                            afterbysrc = (after_by_src *) realloc(afterbysrc, (after_count_by_src+1) * sizeof(after_by_src));
                                                                                                                            afterbysrc[after_count_by_src].ipsrc = ip_src_u32;
                                                                                                                            strlcpy(afterbysrc[after_count_by_src].sid, rulestruct[b].s_sid, sizeof(afterbysrc[after_count_by_src].sid));
                                                                                                                            afterbysrc[after_count_by_src].count = 1;
                                                                                                                            afterbysrc[after_count_by_src].utime = atol(timet);
                                                                                                                            after_count_by_src++;

                                                                                                                            pthread_mutex_unlock(&AfterMutexSrc);
                                                                                                                        }

                                                                                                                    /* After by destination IP address */

                                                                                                                    if ( rulestruct[b].after_src_or_dst == 2 )
                                                                                                                        {

                                                                                                                            after_flag = 0;

                                                                                                                            /* Check array for matching src / sid */

                                                                                                                            for (i = 0; i < after_count_by_dst; i++ )
                                                                                                                                {
                                                                                                                                    if ( afterbydst[i].ipdst == ip_dst_u32 && !strcmp(afterbydst[i].sid, rulestruct[b].s_sid ))
                                                                                                                                        {
                                                                                                                                            after_flag=1;

                                                                                                                                            pthread_mutex_lock(&AfterMutexDst);

                                                                                                                                            afterbydst[i].count++;
                                                                                                                                            after_oldtime_src = atol(timet) - afterbydst[i].utime;
                                                                                                                                            afterbydst[i].utime = atol(timet);
                                                                                                                                            if ( after_oldtime_src > rulestruct[b].after_seconds )
                                                                                                                                                {
                                                                                                                                                    afterbydst[i].count=1;
                                                                                                                                                    afterbydst[i].utime = atol(timet);
                                                                                                                                                    after_log_flag=1;
                                                                                                                                                }

                                                                                                                                            pthread_mutex_unlock(&AfterMutexDst);

                                                                                                                                            if ( rulestruct[b].after_count < afterbydst[i].count )
                                                                                                                                                {
                                                                                                                                                    after_log_flag = 0;

                                                                                                                                                    if ( debug->debuglimits )
                                                                                                                                                        {
                                                                                                                                                            Sagan_Log(S_NORMAL, "After SID %s by destination IP address. [%s]", afterbydst[i].sid, ip_dst);
                                                                                                                                                        }


                                                                                                                                                    pthread_mutex_lock(&CounterMutex);
                                                                                                                                                    counters->after_total++;
                                                                                                                                                    pthread_mutex_unlock(&CounterMutex);
                                                                                                                                                }
                                                                                                                                        }
                                                                                                                                }

                                                                                                                            /* If not found,  add it to the array */

                                                                                                                            if ( after_flag == 0 )
                                                                                                                                {

                                                                                                                                    pthread_mutex_lock(&AfterMutexDst);

                                                                                                                                    afterbydst = (after_by_dst *) realloc(afterbydst, (after_count_by_dst+1) * sizeof(after_by_dst));
                                                                                                                                    afterbydst[after_count_by_dst].ipdst = ip_dst_u32;
                                                                                                                                    strlcpy(afterbydst[after_count_by_dst].sid, rulestruct[b].s_sid, sizeof(afterbydst[after_count_by_dst].sid));
                                                                                                                                    afterbydst[after_count_by_dst].count = 1;
                                                                                                                                    afterbydst[after_count_by_dst].utime = atol(timet);
                                                                                                                                    after_count_by_dst++;

                                                                                                                                    pthread_mutex_unlock(&AfterMutexDst);
                                                                                                                                }
                                                                                                                        }

                                                                                                                } /* End of After */

                                                                                                            thresh_log_flag = 0;

                                                                                                            /*********************************************************/
                                                                                                            /* Thresh holding                                        */
                                                                                                            /*********************************************************/

                                                                                                            if ( rulestruct[b].threshold_type != 0 && after_log_flag == 0)
                                                                                                                {

                                                                                                                    t = time(NULL);
                                                                                                                    now=localtime(&t);
                                                                                                                    strftime(timet, sizeof(timet), "%s",  now);

                                                                                                                    /* Thresholding by source IP address */

                                                                                                                    if ( rulestruct[b].threshold_src_or_dst == 1 )
                                                                                                                        {
                                                                                                                            thresh_flag = 0;

                                                                                                                            /* Check array for matching src / sid */

                                                                                                                            for (i = 0; i < thresh_count_by_src; i++ )
                                                                                                                                {
                                                                                                                                    if ( threshbysrc[i].ipsrc == ip_src_u32 && !strcmp(threshbysrc[i].sid, rulestruct[b].s_sid ))
                                                                                                                                        {

                                                                                                                                            thresh_flag=1;

                                                                                                                                            pthread_mutex_lock(&ThreshMutexSrc);

                                                                                                                                            threshbysrc[i].count++;
                                                                                                                                            thresh_oldtime_src = atol(timet) - threshbysrc[i].utime;

                                                                                                                                            threshbysrc[i].utime = atol(timet);

                                                                                                                                            if ( thresh_oldtime_src > rulestruct[b].threshold_seconds )
                                                                                                                                                {
                                                                                                                                                    threshbysrc[i].count=1;
                                                                                                                                                    threshbysrc[i].utime = atol(timet);
                                                                                                                                                    thresh_log_flag=0;
                                                                                                                                                }

                                                                                                                                            pthread_mutex_unlock(&ThreshMutexSrc);

                                                                                                                                            if ( rulestruct[b].threshold_count < threshbysrc[i].count )
                                                                                                                                                {
                                                                                                                                                    thresh_log_flag = 1;

                                                                                                                                                    if ( debug->debuglimits )
                                                                                                                                                        {
                                                                                                                                                            Sagan_Log(S_NORMAL, "Threshold SID %s by source IP address. [%s]", threshbysrc[i].sid, ip_src);
                                                                                                                                                        }

                                                                                                                                                    pthread_mutex_lock(&CounterMutex);
                                                                                                                                                    counters->threshold_total++;
                                                                                                                                                    pthread_mutex_unlock(&CounterMutex);
                                                                                                                                                }

                                                                                                                                        }
                                                                                                                                }

                                                                                                                            /* If not found,  add it to the array */

                                                                                                                            if ( thresh_flag == 0 )
                                                                                                                                {

                                                                                                                                    pthread_mutex_lock(&ThreshMutexSrc);

                                                                                                                                    threshbysrc = (thresh_by_src *) realloc(threshbysrc, (thresh_count_by_src+1) * sizeof(thresh_by_src));
                                                                                                                                    threshbysrc[thresh_count_by_src].ipsrc = ip_src_u32;
                                                                                                                                    strlcpy(threshbysrc[thresh_count_by_src].sid, rulestruct[b].s_sid, sizeof(threshbysrc[thresh_count_by_src].sid));
                                                                                                                                    threshbysrc[thresh_count_by_src].count = 1;
                                                                                                                                    threshbysrc[thresh_count_by_src].utime = atol(timet);
                                                                                                                                    thresh_count_by_src++;

                                                                                                                                    pthread_mutex_unlock(&ThreshMutexSrc);

                                                                                                                                }
                                                                                                                        }

                                                                                                                    /* Thresholding by destination IP address */

                                                                                                                    if ( rulestruct[b].threshold_src_or_dst == 2 )
                                                                                                                        {
                                                                                                                            thresh_flag = 0;

                                                                                                                            /* Check array for matching src / sid */

                                                                                                                            for (i = 0; i < thresh_count_by_dst; i++ )
                                                                                                                                {
                                                                                                                                    if ( threshbydst[i].ipdst == ip_dst_u32 && !strcmp(threshbydst[i].sid, rulestruct[b].s_sid ))
                                                                                                                                        {

                                                                                                                                            thresh_flag=1;

                                                                                                                                            pthread_mutex_lock(&ThreshMutexDst);

                                                                                                                                            threshbydst[i].count++;
                                                                                                                                            thresh_oldtime_src = atol(timet) - threshbydst[i].utime;
                                                                                                                                            threshbydst[i].utime = atol(timet);
                                                                                                                                            if ( thresh_oldtime_src > rulestruct[b].threshold_seconds )
                                                                                                                                                {
                                                                                                                                                    threshbydst[i].count=1;
                                                                                                                                                    threshbydst[i].utime = atol(timet);
                                                                                                                                                    thresh_log_flag=0;
                                                                                                                                                }

                                                                                                                                            pthread_mutex_unlock(&ThreshMutexDst);

                                                                                                                                            if ( rulestruct[b].threshold_count < threshbydst[i].count )
                                                                                                                                                {
                                                                                                                                                    thresh_log_flag = 1;

                                                                                                                                                    if ( debug->debuglimits )
                                                                                                                                                        {
                                                                                                                                                            Sagan_Log(S_NORMAL, "Threshold SID %s by destination IP address. [%s]", threshbydst[i].sid, ip_dst);
                                                                                                                                                        }

                                                                                                                                                    pthread_mutex_lock(&CounterMutex);
                                                                                                                                                    counters->threshold_total++;
                                                                                                                                                    pthread_mutex_unlock(&CounterMutex);
                                                                                                                                                }
                                                                                                                                        }
                                                                                                                                }

                                                                                                                            /* If not found,  add it to the array */

                                                                                                                            if ( thresh_flag == 0 )
                                                                                                                                {

                                                                                                                                    pthread_mutex_lock(&ThreshMutexDst);

                                                                                                                                    threshbydst = (thresh_by_dst *) realloc(threshbydst, (thresh_count_by_dst+1) * sizeof(thresh_by_dst));
                                                                                                                                    threshbydst[thresh_count_by_dst].ipdst = ip_dst_u32;
                                                                                                                                    strlcpy(threshbydst[thresh_count_by_dst].sid, rulestruct[b].s_sid, sizeof(threshbydst[thresh_count_by_dst].sid));
                                                                                                                                    threshbydst[thresh_count_by_dst].count = 1;
                                                                                                                                    threshbydst[thresh_count_by_dst].utime = atol(timet);
                                                                                                                                    thresh_count_by_dst++;

                                                                                                                                    pthread_mutex_unlock(&ThreshMutexDst);
                                                                                                                                }
                                                                                                                        }
                                                                                                                }  /* End of thresholding */


                                                                                                            pthread_mutex_lock(&CounterMutex);
                                                                                                            counters->saganfound++;
                                                                                                            pthread_mutex_unlock(&CounterMutex);

                                                                                                            /* Check for thesholding & "after" */

                                                                                                            if ( thresh_log_flag == 0 && after_log_flag == 0 )
                                                                                                                {

                                                                                                                    if ( debug->debugengine )
                                                                                                                        {

                                                                                                                            Sagan_Log(S_DEBUG, "[%s, line %d] **[Trigger]*********************************", __FILE__, __LINE__);
                                                                                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->syslog_tag);
                                                                                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Threshold flag: %d | After flag: %d | Flowbit Flag: %d | Flowbit status: %d", __FILE__, __LINE__, thresh_log_flag, after_log_flag, rulestruct[b].flowbit_flag, flowbit_return);
                                                                                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Triggering Message: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);

                                                                                                                        }

                                                                                                                    if ( rulestruct[b].flowbit_flag && rulestruct[b].flowbit_set_count )
                                                                                                                        Sagan_Flowbit_Set(b, ip_src, ip_dst);

                                                                                                                    threadid++;
                                                                                                                    if ( threadid >= MAX_THREADS ) threadid=0;

                                                                                                                    /* We can't use the pointers from our syslog data.  If two (or more) event's
                                                                                                                     * fire at the same time,  the two alerts will have corrupted information
                                                                                                                     * (due to threading).   So we populate the SaganEvent[threadid] with the
                                                                                                                     * var[msgslot] information. - Champ Clark 02/02/2011
                                                                                                                     */

                                                                                                                    processor_info_engine->processor_name          =       s_msg;
                                                                                                                    processor_info_engine->processor_generator_id  =       SAGAN_PROCESSOR_GENERATOR_ID;
                                                                                                                    processor_info_engine->processor_facility      =       SaganProcSyslog_LOCAL->syslog_facility;
                                                                                                                    processor_info_engine->processor_priority      =       SaganProcSyslog_LOCAL->syslog_level;
                                                                                                                    processor_info_engine->processor_pri           =       rulestruct[b].s_pri;
                                                                                                                    processor_info_engine->processor_class         =       rulestruct[b].s_classtype;
                                                                                                                    processor_info_engine->processor_tag           =       SaganProcSyslog_LOCAL->syslog_tag;
                                                                                                                    processor_info_engine->processor_rev           =       rulestruct[b].s_rev;

                                                                                                                    processor_info_engine_dst_port                 =       dst_port;
                                                                                                                    processor_info_engine_src_port                 =       src_port;
                                                                                                                    processor_info_engine_proto                    =       proto;
                                                                                                                    processor_info_engine_alertid                  =       atoi(rulestruct[b].s_sid);

                                                                                                                    if ( rulestruct[b].flowbit_flag == 0 || rulestruct[b].flowbit_noalert == 0 )
                                                                                                                        {
                                                                                                                            Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info_engine, ip_src, ip_dst, processor_info_engine_proto, processor_info_engine_alertid, processor_info_engine_src_port, processor_info_engine_dst_port, b );
                                                                                                                        }


                                                                                                                } /* Threshold / After */
#ifdef WITH_WEBSENSE
                                                                                                        } /* Websense */
#endif

#ifdef WITH_BLUEDOT
                                                                                                } /* Bluedot */
                                                                                        }
                                                                                }
                                                                        }
#endif

                                                                } /* Bro Intel */

                                                        } /* Blacklist */
#ifdef HAVE_LIBMAXMINDDB
                                                } /* GeoIP2 */
#endif
                                        } /* Time based alerts */

                                } /* Flowbit */

                        } /* End of match */

                } /* End of pcre match */

            match=0;  		/* Reset match! */
            sagan_match=0;	/* Reset pcre/meta_content/content match! */
            rc=0;		/* Return code */
            flowbit_return=0;	/* Flowbit reset */


        } /* End for for loop */

    free(processor_info_engine);

    return(0);
}

