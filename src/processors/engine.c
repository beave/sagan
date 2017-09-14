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

/* engine.c
 *
 * Threaded negine that looks for events & patterns based on 'Snort like'
 * rules.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "aetas.h"
#include "meta-content.h"
#include "send-alert.h"
#include "xbit.h"
#include "xbit-mmap.h"
#include "rules.h"
#include "sagan-config.h"
#include "ipc.h"
#include "check-flow.h"
#include "after.h"
#include "threshold.h"

#include "parsers/parsers.h"

#include "processors/engine.h"
#include "processors/bro-intel.h"
#include "processors/blacklist.h"
#include "processors/dynamic-rules.h"

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
#endif

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm;
pthread_mutex_t Lognorm_Mutex;
#endif

#ifdef HAVE_LIBMAXMINDDB
#include "geoip2.h"
#endif

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct _Sagan_IPC_Counters *counters_ipc;

pthread_mutex_t CounterFollowFlowDrop=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t CountersFlowFlowTotal=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t CountersGeoIPHit=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t CounterSaganFoundMutex=PTHREAD_MUTEX_INITIALIZER;

void Sagan_Engine_Init ( void )
{

#ifdef HAVE_LIBLOGNORM

    SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));

    if ( SaganNormalizeLiblognorm == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganNormalizeLiblognorm. Abort!", __FILE__, __LINE__);
        }

    memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));

#endif

}

int Sagan_Engine ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, sbool dynamic_rule_flag )
{

    struct _Sagan_Processor_Info *processor_info_engine = NULL;
    processor_info_engine = malloc(sizeof(struct _Sagan_Processor_Info));

    if ( processor_info_engine == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for processor_info_engine. Abort!", __FILE__, __LINE__);
        }

    memset(processor_info_engine, 0, sizeof(_Sagan_Processor_Info));

    int processor_info_engine_src_port = 0;
    int processor_info_engine_dst_port = 0;
    int processor_info_engine_proto = 0;
    int processor_info_engine_alertid = 0;

    sbool after_log_flag = false;
    sbool thresh_log_flag = false;

    int threadid = 0;

    int i = 0;
    int b = 0;
    int z = 0;

    sbool match = false;
    int sagan_match = 0;				/* Used to determine if all has "matched" (content, pcre, meta_content, etc) */

    int rc = 0;
    int ovector[PCRE_OVECCOUNT];

    int alter_num = 0;
    int meta_alter_num = 0;

    sbool xbit_return = 0;
    sbool xbit_count_return = 0;

    sbool alert_time_trigger = false;
    sbool check_flow_return = true;  /* 1 = match, 0 = no match */

    char *ptmp;
    char *tok2;

    /* We don't tie these to HAVE_LIBMAXMINDDB because we might have other
     * methods to extract the informaton */

    char normalize_selector[MAXSELECTOR] = { 0 };
    char normalize_username[MAX_USERNAME_SIZE] = { 0 };
    char normalize_md5_hash[MD5_HASH_SIZE+1] = { 0 };
    char normalize_sha1_hash[SHA1_HASH_SIZE+1] = { 0 };
    char normalize_sha256_hash[SHA256_HASH_SIZE+1] = { 0 };

    char normalize_filename[MAX_FILENAME_SIZE] = { 0 };
    char normalize_http_uri[MAX_URL_SIZE] = { 0 };
    char normalize_http_hostname[MAX_HOSTNAME_SIZE] = { 0 };

    char *pnormalize_selector = NULL;

    int  normalize_src_port;
    int  normalize_dst_port;

    int check_pos = 0;
    struct _Sagan_Lookup_Cache_Entry lookup_cache[MAX_PARSE_IP] = { 0 };

    char ip_parse_cache[MAX_PARSE_IP][MAXIP] = {0};
    ptrdiff_t ip_parse_cache_used[MAX_PARSE_IP];

    char ip_src[MAXIP];
    sbool ip_src_flag = 0;

    uint32_t ip_srcport_u32;
    unsigned char ip_src_bits[MAXIPBIT] = { 0 };

    char ip_dst[MAXIP];
    sbool ip_dst_flag = 0;

    uint32_t ip_dstport_u32 = 0;
    unsigned char ip_dst_bits[MAXIPBIT] = { 0 };

    char tmpbuf[128];
    char s_msg[1024];
    char alter_content[MAX_SYSLOGMSG];
    char meta_alter_content[MAX_SYSLOGMSG];

    struct timeval tp;
    int proto = 0;

    sbool brointel_results = 0;
    sbool blacklist_results = 0;

#ifdef HAVE_LIBMAXMINDDB

    unsigned char geoip2_return = 0;
    sbool geoip2_isset = false;

#endif

#ifdef WITH_BLUEDOT

    unsigned char bluedot_results = 0;
    sbool bluedot_ip_flag = 0;
    sbool bluedot_hash_flag = 0;
    sbool bluedot_url_flag = 0;
    sbool bluedot_filename_flag = 0;

#endif

    // Set all to -1 to facilitate easier checking
    memset((char *)ip_parse_cache_used, -1, sizeof(ip_parse_cache_used));

    /* This needs to be included,  even if liblognorm isn't in use */

    sbool liblognorm_status = 0;
    json_object *json_normalize = NULL;

    /* Search for matches */

    /* First we search for 'program' and such.   This way,  we don't waste CPU
     * time with pcre/content.  */

    for(b=0; b < counters->rulecount; b++)
        {
            ip_src[0] = '\0';
            ip_dst[0] = '\0';

            memset(ip_src_bits, 0, sizeof(ip_src_bits));
            memset(ip_dst_bits, 0, sizeof(ip_dst_bits));

            /* Process "normal" rules.  Skip dynamic rules if it's not time to process them */

            if ( rulestruct[b].type == NORMAL_RULE || ( rulestruct[b].type == DYNAMIC_RULE && dynamic_rule_flag == true ) )
                {

                    match = false;

                    if ( strcmp(rulestruct[b].s_program, "" ))
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_program, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            match = true;
                            while ( ptmp != NULL )
                                {
                                    if ( Wildcard(ptmp, SaganProcSyslog_LOCAL->syslog_program) == 1 )
                                        {
                                            match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( strcmp(rulestruct[b].s_facility, "" ))
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_facility, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            match = true;
                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_facility))
                                        {
                                            match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( strcmp(rulestruct[b].s_syspri, "" ))
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_syspri, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            match = true;
                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_priority))
                                        {
                                            match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( strcmp(rulestruct[b].s_level, "" ))
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_level, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            match = true;
                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_level))
                                        {
                                            match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( strcmp(rulestruct[b].s_tag, "" ))
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_tag, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            match = true;
                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_tag))
                                        {
                                            match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    /* If there has been a match above,  or NULL on all,  then we continue with
                     * PCRE/content search */

                    /* Search via strstr (content:) */

                    if ( match == false )
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

                                            if ( rulestruct[b].s_distance[z] != 0 )
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

                                            if ( rc > 0 )
                                                {
                                                    sagan_match++;
                                                }

                                        }  /* End of pcre if */
                                }

                            /* Search via meta_content */

                            if ( rulestruct[b].meta_content_count != 0 && sagan_match == rulestruct[b].content_count + rulestruct[b].pcre_count )
                                {

                                    for (z=0; z<rulestruct[b].meta_content_count; z++)
                                        {

                                            meta_alter_num = 0;

                                            /* Meta_content: OFFSET */

                                            if ( rulestruct[b].meta_offset[z] != 0 )
                                                {

                                                    if ( strlen(SaganProcSyslog_LOCAL->syslog_message) > rulestruct[b].meta_offset[z] )
                                                        {

                                                            meta_alter_num = strlen(SaganProcSyslog_LOCAL->syslog_message) - rulestruct[b].meta_offset[z];
                                                            strlcpy(meta_alter_content, SaganProcSyslog_LOCAL->syslog_message + (strlen(SaganProcSyslog_LOCAL->syslog_message) - meta_alter_num), meta_alter_num + 1);

                                                        }
                                                    else
                                                        {

                                                            meta_alter_content[0] = '\0';    /* The offset is larger than the message.  Set meta_content too NULL */

                                                        }

                                                }
                                            else
                                                {

                                                    strlcpy(meta_alter_content, SaganProcSyslog_LOCAL->syslog_message, sizeof(meta_alter_content));

                                                }


                                            /* Meta_content: DEPTH */

                                            if ( rulestruct[b].meta_depth[z] != 0 )
                                                {

                                                    /* We do +2 to account for alter_count[0] and whitespace at the begin of syslog message */

                                                    strlcpy(meta_alter_content, meta_alter_content, rulestruct[b].meta_depth[z] + 2);

                                                }

                                            /* Meta_content: DISTANCE */

                                            if ( rulestruct[b].meta_distance[z] != 0 )
                                                {

                                                    meta_alter_num = strlen(SaganProcSyslog_LOCAL->syslog_message) - ( rulestruct[b].meta_depth[z-1] + rulestruct[b].meta_distance[z] + 1 );
                                                    strlcpy(meta_alter_content, SaganProcSyslog_LOCAL->syslog_message + (strlen(SaganProcSyslog_LOCAL->syslog_message) - meta_alter_num), meta_alter_num + 1);

                                                    /* Meta_ontent: WITHIN */

                                                    if ( rulestruct[b].meta_within[z] != 0 )
                                                        {
                                                            strlcpy(meta_alter_content, meta_alter_content, rulestruct[b].meta_within[z] + 1);

                                                        }

                                                }

                                            rc = Meta_Content_Search(meta_alter_content, b, z);

                                            if ( rc == 1 )
                                                {
                                                    sagan_match++;
                                                }

                                        }
                                }


                        } /* End of content: & pcre */

                    /* if you got match */

                    if ( sagan_match == rulestruct[b].pcre_count + rulestruct[b].content_count + rulestruct[b].meta_content_count )
                        {

                            gettimeofday(&tp, 0);	/* Store event time as soon as we get a match */

                            if ( match == false )
                                {

                                    ip_src_flag = 0;
                                    ip_dst_flag = 0;

#ifdef HAVE_LIBLOGNORM
                                    if ( 0 == liblognorm_status && rulestruct[b].normalize == 1 )
                                        {
                                            // Set that normalization has been tried work isn't repeated
                                            liblognorm_status = -1;

                                            pthread_mutex_lock(&Lognorm_Mutex);

                                            json_normalize = Normalize_Liblognorm(SaganProcSyslog_LOCAL->syslog_message);

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
                                                    normalize_src_port = SaganNormalizeLiblognorm->src_port;
                                                    liblognorm_status = 1;
                                                }

                                            if ( SaganNormalizeLiblognorm->dst_port != 0 )
                                                {
                                                    normalize_dst_port = SaganNormalizeLiblognorm->dst_port;
                                                    liblognorm_status = 1;
                                                }

                                            if ( SaganNormalizeLiblognorm->username[0] != '\0' )
                                                {
                                                    strlcpy(normalize_username, SaganNormalizeLiblognorm->username, sizeof(normalize_username));
                                                    liblognorm_status = 1;
                                                }

                                            if ( config->selector_flag && SaganNormalizeLiblognorm->selector[0] != '\0' )
                                                {
                                                    strlcpy(normalize_selector, SaganNormalizeLiblognorm->selector, sizeof(normalize_selector));
                                                    liblognorm_status = 1;
                                                    pnormalize_selector = normalize_selector;
                                                }

                                            if ( SaganNormalizeLiblognorm->http_uri[0] != '\0' )
                                                {
                                                    strlcpy(normalize_http_uri, SaganNormalizeLiblognorm->http_uri, sizeof(normalize_http_uri));
                                                    liblognorm_status = 1;
                                                }

                                            if ( SaganNormalizeLiblognorm->filename[0] != '\0' )
                                                {
                                                    strlcpy(normalize_filename, SaganNormalizeLiblognorm->filename, sizeof(normalize_filename));
                                                    liblognorm_status = 1;
                                                }


                                            if ( SaganNormalizeLiblognorm->hash_sha256[0] != '\0' )
                                                {
                                                    strlcpy(normalize_sha256_hash, SaganNormalizeLiblognorm->hash_sha256, sizeof(normalize_sha256_hash));
                                                    liblognorm_status = 1;
                                                }


                                            if ( SaganNormalizeLiblognorm->hash_sha1[0] != '\0' )
                                                {
                                                    strlcpy(normalize_sha1_hash, SaganNormalizeLiblognorm->hash_sha1, sizeof(normalize_sha1_hash));
                                                    liblognorm_status = 1;
                                                }

                                            if ( SaganNormalizeLiblognorm->hash_md5[0] != '\0' )
                                                {

                                                    strlcpy(normalize_md5_hash, SaganNormalizeLiblognorm->hash_md5, sizeof(normalize_md5_hash));
                                                    liblognorm_status = 1;

                                                }

                                            pthread_mutex_unlock(&Lognorm_Mutex);

                                        }
#endif


                                    /* Normalization should always over ride parse_src_ip/parse_dst_ip/parse_port,
                                     * _unless_ liblognorm fails and both are in a rule */

                                    if ( rulestruct[b].normalize == 0 || (rulestruct[b].normalize == 1 && liblognorm_status <= 0 ) )
                                        {

                                            /* parse_src_ip: {position} */

                                            if ( rulestruct[b].s_find_src_ip == 1 )
                                                {
                                                    check_pos = rulestruct[b].s_find_src_pos - 1;
                                                    // Cache the parsing to avoid doing this for every rule
                                                    if (check_pos < MAX_PARSE_IP && lookup_cache[check_pos].searched)
                                                        {
                                                            strlcpy(ip_src, lookup_cache[check_pos].ip, sizeof(ip_src));
                                                            // This case handles if we already found the previous index
                                                        }
                                                    else
                                                        {
                                                            Parse_IP(SaganProcSyslog_LOCAL->syslog_message,
                                                                     check_pos+1,
                                                                     ip_src,
                                                                     sizeof(ip_src),
                                                                     lookup_cache,
                                                                     MAX_PARSE_IP);
                                                        }

                                                    ip_src_flag = 1;
                                                }

                                            /* parse_dst_ip: {postion} */

                                            if ( rulestruct[b].s_find_dst_ip == 1 )
                                                {
                                                    check_pos = rulestruct[b].s_find_dst_pos - 1;
                                                    // Cache the parsing to avoid doing this for every rule
                                                    if (check_pos < MAX_PARSE_IP && lookup_cache[check_pos].searched)
                                                        {
                                                            strlcpy(ip_dst, lookup_cache[check_pos].ip, sizeof(ip_dst));
                                                            // This case handles if we already found the previous index
                                                        }
                                                    else
                                                        {
                                                            Parse_IP(SaganProcSyslog_LOCAL->syslog_message,
                                                                     check_pos+1,
                                                                     ip_dst,
                                                                     sizeof(ip_dst),
                                                                     lookup_cache,
                                                                     MAX_PARSE_IP);
                                                        }

                                                    ip_dst_flag = 1;
                                                }

                                            /* parse_port */

                                            if ( rulestruct[b].s_find_port == 1 )
                                                {
                                                    normalize_src_port = Parse_Src_Port(SaganProcSyslog_LOCAL->syslog_message);
                                                    normalize_dst_port = Parse_Dst_Port(SaganProcSyslog_LOCAL->syslog_message);
                                                }

                                            /* parse_hash: md5 */

                                            if ( rulestruct[b].s_find_hash_type == PARSE_HASH_MD5 )
                                                {
                                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_MD5, normalize_md5_hash, sizeof(normalize_md5_hash));
                                                }

                                            else if ( rulestruct[b].s_find_hash_type == PARSE_HASH_SHA1 )
                                                {
                                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_SHA1, normalize_sha1_hash, sizeof(normalize_sha1_hash));
                                                }

                                            else if ( rulestruct[b].s_find_hash_type == PARSE_HASH_SHA256 )
                                                {
                                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_SHA256, normalize_sha256_hash, sizeof(normalize_sha256_hash));
                                                }

                                            /*  DEBUG
                                            else if ( rulestruct[b].s_find_hash_type == PARSE_HASH_ALL )
                                                {
                                            Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_SHA256, normalize_sha256_hash, sizeof(normalize_sha256_hash));
                                                              }
                                                              */


                                        }


                                    /* If the rule calls for proto searching,  we do it now */

                                    proto = 0;

                                    if ( rulestruct[b].s_find_proto_program == 1 )
                                        {
                                            proto = Parse_Proto_Program(SaganProcSyslog_LOCAL->syslog_program);
                                        }

                                    if ( rulestruct[b].s_find_proto == 1 && proto == 0 )
                                        {
                                            proto = Parse_Proto(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    /* If proto is not searched or has failed,  default to whatever the rule told us to
                                       use */

                                    if ( ip_src_flag == 0 || ip_src[0] == '0' )
                                        {
                                            strlcpy(ip_src, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_src));
                                        }

                                    if ( ip_dst_flag == 0 || ip_dst[0] == '0' )
                                        {
                                            strlcpy(ip_dst, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_dst));
                                        }

                                    /* No source port was normalized, Use the rules default */

                                    if ( normalize_src_port == 0 )
                                        {
                                            normalize_src_port=rulestruct[b].default_src_port;
                                        }

                                    /* No destination port was normalzied. Use the rules default */

                                    if ( normalize_dst_port == 0 )
                                        {
                                            normalize_dst_port=rulestruct[b].default_dst_port;
                                        }


                                    /* No protocol was normalized.  Use the rules default */

                                    if ( proto == 0 )
                                        {
                                            proto = rulestruct[b].default_proto;
                                        }

                                    /* If the "source" is 127.0.0.1 that is not useful.  Replace with config->sagan_host
                                     * (defined by user in sagan.conf. For now keep ::1 as there needs to be another option for that value  */

                                    if ( !strcmp(ip_src, "127.0.0.1") )
                                        {
                                            strlcpy(ip_src, config->sagan_host, sizeof(ip_src));
                                        }

                                    if ( !strcmp(ip_dst, "127.0.0.1") )
                                        {
                                            strlcpy(ip_dst, config->sagan_host, sizeof(ip_dst));
                                        }

                                    ip_src_flag = ip_src[0] != '\0' && IP2Bit(ip_src, ip_src_bits);
                                    ip_dst_flag = ip_dst[0] != '\0' && IP2Bit(ip_dst, ip_dst_bits);

                                    ip_dstport_u32 = normalize_dst_port;
                                    ip_srcport_u32 = normalize_src_port;

                                    strlcpy(s_msg, rulestruct[b].s_msg, sizeof(s_msg));


                                    /* Check for flow of rule - has_flow is set as rule loading.  It 1, then
                                    the rule has some sort of flow.  It 0,  rule is set any:any/any:any */

                                    if ( rulestruct[b].has_flow == 1 )
                                        {

                                            check_flow_return = Check_Flow( b, proto, ip_src_bits, normalize_src_port, ip_dst_bits, normalize_dst_port);

                                            if(check_flow_return == false)
                                                {

                                                    pthread_mutex_lock(&CounterFollowFlowDrop);
                                                    counters->follow_flow_drop++;
                                                    pthread_mutex_unlock(&CounterFollowFlowDrop);

                                                }

                                            pthread_mutex_lock(&CountersFlowFlowTotal);
                                            counters->follow_flow_total++;
                                            pthread_mutex_unlock(&CountersFlowFlowTotal);

                                        }

                                    /****************************************************************************
                                     * Xbit - ISSET || ISNOTSET
                                     ****************************************************************************/

                                    if ( rulestruct[b].xbit_flag )
                                        {

                                            if ( rulestruct[b].xbit_condition_count )
                                                {
                                                    xbit_return = Xbit_Condition(b, ip_src, ip_dst, normalize_src_port, normalize_dst_port, pnormalize_selector);
                                                }

                                            if ( rulestruct[b].xbit_count_flag )
                                                {
                                                    xbit_count_return = Xbit_Count(b, ip_src, ip_dst, pnormalize_selector);
                                                }

                                        }


                                    /****************************************************************************
                                     * Country code
                                     ****************************************************************************/

#ifdef HAVE_LIBMAXMINDDB

                                    if ( rulestruct[b].geoip2_flag )
                                        {

                                            if ( rulestruct[b].geoip2_src_or_dst == 1 )
                                                {
                                                    geoip2_return = GeoIP2_Lookup_Country(ip_src, b);
                                                }
                                            else
                                                {
                                                    geoip2_return = GeoIP2_Lookup_Country(ip_dst, b);
                                                }

                                            if ( geoip2_return != 2 )
                                                {

                                                    /* If country IS NOT {my value} return 1 */

                                                    if ( rulestruct[b].geoip2_type == 1 )    		/* isnot */
                                                        {

                                                            if ( geoip2_return == 1 )
                                                                {
                                                                    geoip2_isset = false;
                                                                }
                                                            else
                                                                {
                                                                    geoip2_isset = true;

                                                                    pthread_mutex_lock(&CountersGeoIPHit);
                                                                    counters->geoip2_hit++;
                                                                    pthread_mutex_unlock(&CountersGeoIPHit);
                                                                }
                                                        }

                                                    /* If country IS {my value} return 1 */

                                                    if ( rulestruct[b].geoip2_type == 2 )             /* is */
                                                        {

                                                            if ( geoip2_return == 1 )
                                                                {

                                                                    geoip2_isset = true;

                                                                    pthread_mutex_lock(&CountersGeoIPHit);
                                                                    counters->geoip2_hit++;
                                                                    pthread_mutex_unlock(&CountersGeoIPHit);

                                                                }
                                                            else
                                                                {

                                                                    geoip2_isset = false;
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

                                            alert_time_trigger = false;

                                            if ( Check_Time(b) )
                                                {
                                                    alert_time_trigger = true;
                                                }
                                        }

                                    /****************************************************************************
                                     * Blacklist
                                     ****************************************************************************/

                                    if ( rulestruct[b].blacklist_flag )
                                        {

                                            blacklist_results = 0;

                                            if ( rulestruct[b].blacklist_ipaddr_src && ip_src_flag )
                                                {
                                                    blacklist_results = Sagan_Blacklist_IPADDR( ip_src_bits );
                                                }

                                            if ( blacklist_results == 0 && rulestruct[b].blacklist_ipaddr_dst && ip_dst_flag )
                                                {
                                                    blacklist_results = Sagan_Blacklist_IPADDR( ip_dst_bits );
                                                }

                                            if ( blacklist_results == 0 && rulestruct[b].blacklist_ipaddr_all )
                                                {
                                                    blacklist_results = Sagan_Blacklist_IPADDR_All(SaganProcSyslog_LOCAL->syslog_message, lookup_cache, MAX_PARSE_IP);
                                                }

                                            if ( blacklist_results == 0 && rulestruct[b].blacklist_ipaddr_both && ip_src_flag && ip_dst_flag )
                                                {
                                                    if ( Sagan_Blacklist_IPADDR( ip_src_bits ) || Sagan_Blacklist_IPADDR( ip_dst_bits ) )
                                                        {
                                                            blacklist_results = 1;
                                                        }
                                                }
                                        }

#ifdef WITH_BLUEDOT

                                    if ( config->bluedot_flag )
                                        {
                                            if ( rulestruct[b].bluedot_ipaddr_type )
                                                {

                                                    bluedot_results = 0;

                                                    /* 1 == src,  2 == dst,  3 == both,  4 == all */

                                                    if ( rulestruct[b].bluedot_ipaddr_type == 1 && ip_src_flag )
                                                        {
                                                            bluedot_results = Sagan_Bluedot_Lookup(ip_src, BLUEDOT_LOOKUP_IP, b);
                                                            bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                        }

                                                    if ( rulestruct[b].bluedot_ipaddr_type == 2 && ip_dst_flag )
                                                        {
                                                            bluedot_results = Sagan_Bluedot_Lookup(ip_dst, BLUEDOT_LOOKUP_IP, b);
                                                            bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                        }

                                                    if ( rulestruct[b].bluedot_ipaddr_type == 3 && ip_src_flag && ip_dst_flag )
                                                        {

                                                            bluedot_results = Sagan_Bluedot_Lookup(ip_src, BLUEDOT_LOOKUP_IP, b);
                                                            bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);

                                                            /* If the source isn't found,  then check the dst */

                                                            if ( bluedot_ip_flag != 0 )
                                                                {
                                                                    bluedot_results = Sagan_Bluedot_Lookup(ip_dst, BLUEDOT_LOOKUP_IP, b);
                                                                    bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                                }

                                                        }

                                                    if ( rulestruct[b].bluedot_ipaddr_type == 4 )
                                                        {

                                                            bluedot_ip_flag = Sagan_Bluedot_IP_Lookup_All(SaganProcSyslog_LOCAL->syslog_message, b, lookup_cache, MAX_PARSE_IP);

                                                        }

                                                }


                                            if ( rulestruct[b].bluedot_file_hash && ( normalize_md5_hash[0] != '\0' ||
                                                    normalize_sha1_hash[0] != '\0' || normalize_sha256_hash[0] != '\0') )
                                                {

                                                    if ( normalize_md5_hash[0] != '\0')
                                                        {

                                                            bluedot_results = Sagan_Bluedot_Lookup( normalize_md5_hash, BLUEDOT_LOOKUP_HASH, b);
                                                            bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH);

                                                        }

                                                    if ( normalize_sha1_hash[0] != '\0' )
                                                        {

                                                            bluedot_results = Sagan_Bluedot_Lookup( normalize_sha1_hash, BLUEDOT_LOOKUP_HASH, b);
                                                            bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH);

                                                        }

                                                    if ( normalize_sha256_hash[0] != '\0')
                                                        {

                                                            bluedot_results = Sagan_Bluedot_Lookup( normalize_sha256_hash, BLUEDOT_LOOKUP_HASH, b);
                                                            bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH);

                                                        }

                                                }

                                            if ( rulestruct[b].bluedot_url && normalize_http_uri != '\0' )
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup( normalize_http_uri, BLUEDOT_LOOKUP_URL, b);
                                                    bluedot_url_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_URL);

                                                }

                                            if ( rulestruct[b].bluedot_filename && normalize_filename[0] != '\0' )
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup( normalize_filename, BLUEDOT_LOOKUP_FILENAME, b);
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

                                            if ( rulestruct[b].brointel_ipaddr_src && ip_src_flag )
                                                {
                                                    brointel_results = Sagan_BroIntel_IPADDR( ip_src_bits );
                                                }

                                            if ( brointel_results == 0 && rulestruct[b].brointel_ipaddr_dst && ip_dst_flag )
                                                {
                                                    brointel_results = Sagan_BroIntel_IPADDR( ip_dst_bits );
                                                }

                                            if ( brointel_results == 0 && rulestruct[b].brointel_ipaddr_all )
                                                {
                                                    brointel_results = Sagan_BroIntel_IPADDR_All ( SaganProcSyslog_LOCAL->syslog_message, lookup_cache, MAX_PARSE_IP);
                                                }

                                            if ( brointel_results == 0 && rulestruct[b].brointel_ipaddr_both && ip_src_flag && ip_dst_flag )
                                                {
                                                    if ( Sagan_BroIntel_IPADDR( ip_src_bits ) || Sagan_BroIntel_IPADDR( ip_dst_bits ) )
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

                                    if ( check_flow_return == true )
                                        {

                                            /* DEBUG: Had rulestruct[b].xbit_flag */

                                            if ( rulestruct[b].xbit_flag == false ||
                                                    ( rulestruct[b].xbit_set_count && rulestruct[b].xbit_condition_count == 0 ) ||
                                                    ( rulestruct[b].xbit_set_count && rulestruct[b].xbit_condition_count && xbit_return ) ||
                                                    ( rulestruct[b].xbit_set_count == false && rulestruct[b].xbit_condition_count && xbit_return ))
                                                {

                                                    if ( rulestruct[b].xbit_count_flag == false ||
                                                            xbit_count_return == true )
                                                        {

                                                            if ( rulestruct[b].alert_time_flag == false || alert_time_trigger == true )
                                                                {

#ifdef HAVE_LIBMAXMINDDB
                                                                    if ( rulestruct[b].geoip2_flag == false || geoip2_isset == true )
                                                                        {
#endif
                                                                            if ( rulestruct[b].blacklist_flag == false || blacklist_results == true )
                                                                                {

                                                                                    if ( rulestruct[b].brointel_flag == false || brointel_results == true )
                                                                                        {
#ifdef WITH_BLUEDOT


                                                                                            if ( config->bluedot_flag == false || rulestruct[b].bluedot_file_hash == false || ( rulestruct[b].bluedot_file_hash == true && bluedot_hash_flag == true ))
                                                                                                {

                                                                                                    if ( config->bluedot_flag == false || rulestruct[b].bluedot_filename == false || ( rulestruct[b].bluedot_filename == true && bluedot_filename_flag == true ))
                                                                                                        {

                                                                                                            if ( config->bluedot_flag == false || rulestruct[b].bluedot_url == false || ( rulestruct[b].bluedot_url == true && bluedot_url_flag == true ))
                                                                                                                {

                                                                                                                    if ( config->bluedot_flag == false || rulestruct[b].bluedot_ipaddr_type == false || ( rulestruct[b].bluedot_ipaddr_type != 0 && bluedot_ip_flag == true ))
                                                                                                                        {



#endif

                                                                                                                            /* After */

                                                                                                                            after_log_flag = false;

                                                                                                                            if ( rulestruct[b].after_method != 0 )
                                                                                                                                {

                                                                                                                                    switch(rulestruct[b].after_method)
                                                                                                                                        {

                                                                                                                                        case(AFTER_BY_SRC):
                                                                                                                                            after_log_flag = After_By_Src(b, ip_src, ip_src_bits, pnormalize_selector);
                                                                                                                                            break;

                                                                                                                                        case(AFTER_BY_DST):
                                                                                                                                            after_log_flag = After_By_Dst(b, ip_dst, ip_dst_bits, pnormalize_selector);
                                                                                                                                            break;

                                                                                                                                        case(AFTER_BY_SRCPORT):
                                                                                                                                            after_log_flag = After_By_SrcPort(b, ip_srcport_u32, pnormalize_selector);
                                                                                                                                            break;

                                                                                                                                        case(AFTER_BY_DSTPORT):
                                                                                                                                            after_log_flag = After_By_DstPort(b, ip_dstport_u32, pnormalize_selector);
                                                                                                                                            break;

                                                                                                                                        case(AFTER_BY_USERNAME):

                                                                                                                                            if ( normalize_username[0] != '\0' )
                                                                                                                                                {

                                                                                                                                                    after_log_flag = After_By_Username(b, normalize_username, pnormalize_selector );
                                                                                                                                                }


                                                                                                                                        } /*switch */

                                                                                                                                } /* rulestruct[b].after_method != 0 */

                                                                                                                            thresh_log_flag = false;

                                                                                                                            if ( rulestruct[b].threshold_type != 0 &&
                                                                                                                                    after_log_flag == false )
                                                                                                                                {

                                                                                                                                    switch( rulestruct[b].threshold_method )
                                                                                                                                        {

                                                                                                                                        case(THRESH_BY_SRC):
                                                                                                                                            thresh_log_flag = Thresh_By_Src(b, ip_src, ip_src_bits, pnormalize_selector);
                                                                                                                                            break;

                                                                                                                                        case(THRESH_BY_DST):
                                                                                                                                            thresh_log_flag = Thresh_By_Dst(b, ip_dst, ip_dst_bits, pnormalize_selector);
                                                                                                                                            break;

                                                                                                                                        case(THRESH_BY_USERNAME):
                                                                                                                                            if ( normalize_username[0] != '\0' )
                                                                                                                                                {
                                                                                                                                                    thresh_log_flag = Thresh_By_Username(b, normalize_username, pnormalize_selector);
                                                                                                                                                }
                                                                                                                                            break;

                                                                                                                                        case(THRESH_BY_SRCPORT):
                                                                                                                                            thresh_log_flag = Thresh_By_SrcPort(b, ip_srcport_u32, pnormalize_selector);

                                                                                                                                        case(THRESH_BY_DSTPORT):
                                                                                                                                            thresh_log_flag = Thresh_By_DstPort(b, ip_dstport_u32, pnormalize_selector);
                                                                                                                                            break;

                                                                                                                                        } /* switch */

                                                                                                                                } /* if */

                                                                                                                            pthread_mutex_lock(&CounterSaganFoundMutex);
                                                                                                                            counters->saganfound++;
                                                                                                                            pthread_mutex_unlock(&CounterSaganFoundMutex);

                                                                                                                            /* Check for thesholding & "after" */

                                                                                                                            if ( thresh_log_flag == false && after_log_flag == false )
                                                                                                                                {

                                                                                                                                    if ( debug->debugengine )
                                                                                                                                        {

                                                                                                                                            Sagan_Log(S_DEBUG, "[%s, line %d] **[Trigger]*********************************", __FILE__, __LINE__);
                                                                                                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->syslog_tag);
                                                                                                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Threshold flag: %d | After flag: %d | Xbit Flag: %d | Xbit status: %d", __FILE__, __LINE__, thresh_log_flag, after_log_flag, rulestruct[b].xbit_flag, xbit_return);
                                                                                                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Triggering Message: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);

                                                                                                                                        }

                                                                                                                                    if ( rulestruct[b].xbit_flag && rulestruct[b].xbit_set_count )
                                                                                                                                        {
                                                                                                                                            Xbit_Set(b, ip_src, ip_dst, normalize_src_port, normalize_dst_port, pnormalize_selector);
                                                                                                                                        }

                                                                                                                                    threadid++;

                                                                                                                                    if ( threadid >= MAX_THREADS )
                                                                                                                                        {
                                                                                                                                            threadid=0;
                                                                                                                                        }


                                                                                                                                    processor_info_engine->processor_name          =       s_msg;
                                                                                                                                    processor_info_engine->processor_generator_id  =       SAGAN_PROCESSOR_GENERATOR_ID;
                                                                                                                                    processor_info_engine->processor_facility      =       SaganProcSyslog_LOCAL->syslog_facility;
                                                                                                                                    processor_info_engine->processor_priority      =       SaganProcSyslog_LOCAL->syslog_level;
                                                                                                                                    processor_info_engine->processor_pri           =       rulestruct[b].s_pri;
                                                                                                                                    processor_info_engine->processor_class         =       rulestruct[b].s_classtype;
                                                                                                                                    processor_info_engine->processor_tag           =       SaganProcSyslog_LOCAL->syslog_tag;
                                                                                                                                    processor_info_engine->processor_rev           =       rulestruct[b].s_rev;
                                                                                                                                    processor_info_engine_dst_port                 =       normalize_dst_port;
                                                                                                                                    processor_info_engine_src_port                 =       normalize_src_port;
                                                                                                                                    processor_info_engine_proto                    =       proto;
                                                                                                                                    processor_info_engine_alertid                  =       atoi(rulestruct[b].s_sid);

                                                                                                                                    if ( rulestruct[b].xbit_flag == false || rulestruct[b].xbit_noalert == 0 )
                                                                                                                                        {

                                                                                                                                            if ( rulestruct[b].type == NORMAL_RULE )
                                                                                                                                                {

                                                                                                                                                    Send_Alert(SaganProcSyslog_LOCAL,
                                                                                                                                                               json_normalize,
                                                                                                                                                               processor_info_engine,
                                                                                                                                                               ip_src,
                                                                                                                                                               ip_dst,
                                                                                                                                                               normalize_http_uri,
                                                                                                                                                               normalize_http_hostname,
                                                                                                                                                               processor_info_engine_proto,
                                                                                                                                                               processor_info_engine_alertid,
                                                                                                                                                               processor_info_engine_src_port,
                                                                                                                                                               processor_info_engine_dst_port,
                                                                                                                                                               b, tp );

                                                                                                                                                }
                                                                                                                                            else
                                                                                                                                                {

                                                                                                                                                    Sagan_Dynamic_Rules(SaganProcSyslog_LOCAL, b, processor_info_engine,
                                                                                                                                                                        ip_src, ip_dst);

                                                                                                                                                }

                                                                                                                                        }


                                                                                                                                } /* Threshold / After */
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

                                                        } /* Xbit count */

                                                } /* Xbit */

                                        } /* Check Rule Flow */

                                } /* End of match */

                        } /* End of pcre match */

#ifdef HAVE_LIBMAXMINDDB
                    geoip2_isset = false;
#endif

                    match = false;  		      /* Reset match! */
                    sagan_match=0;	      /* Reset pcre/meta_content/content match! */
                    rc=0;		      /* Return code */
                    xbit_return=0;	      /* Xbit reset */
                    check_flow_return = true;      /* Rule flow direction reset */

                } /* If normal or dynamic rule */

        } /* End for for loop */

    free(processor_info_engine);

#ifdef HAVE_LIBLOGNORM
    if (NULL != json_normalize)
        {
            json_object_put(json_normalize);
            json_normalize = NULL;
        }
#endif

    return(0);
}
