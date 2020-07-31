/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
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
#include <unistd.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "aetas.h"
#include "meta-content.h"
#include "send-alert.h"
#include "flexbit.h"
#include "flexbit-mmap.h"
#include "rules.h"
#include "sagan-config.h"
#include "ipc.h"
#include "flow.h"
#include "after.h"
#include "threshold.h"
#include "xbit.h"
#include "event-id.h"
#include "routing.h"
#include "content.h"
#include "pcre-s.h"
#include "json-pcre.h"
#include "json-content.h"
#include "json-meta-content.h"

#include "parsers/parsers.h"

#include "processors/engine.h"
#include "processors/zeek-intel.h"
#include "processors/blacklist.h"
#include "processors/dynamic-rules.h"

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"
#endif

#ifdef HAVE_LIBLOGNORM
#include "liblognormalize.h"
#endif

#ifdef HAVE_LIBMAXMINDDB
#include "geoip.h"
#endif

#ifdef HAVE_LIBFASTJSON
#include "message-json-map.h"
#endif

#include "output-plugins/eve.h"

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _Sagan_Ruleset_Track *Ruleset_Track;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct _Sagan_IPC_Counters *counters_ipc;

void Sagan_Engine_Init ( void )
{
    /* Nothing to do yet */
}

int Sagan_Engine ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, bool dynamic_rule_flag )
{

    struct _Sagan_Routing *SaganRouting = NULL;
    SaganRouting = malloc(sizeof(struct _Sagan_Routing));

    if ( SaganRouting == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Sagan_Routing, Abort!", __FILE__, __LINE__);
        }

    memset(SaganRouting, 0, sizeof(_Sagan_Routing));

    SaganRouting->check_flow_return = true;
    SaganRouting->flexbit_count_return = false;
    SaganRouting->flexbit_return = false;
    SaganRouting->xbit_return = false;
    SaganRouting->alert_time_trigger = false;
    SaganRouting->blacklist_results = false;
    SaganRouting->brointel_results = false;

#ifdef HAVE_LIBMAXMINDDB
    SaganRouting->geoip2_isset = false;
#endif

#ifdef WITH_BLUEDOT

    SaganRouting->bluedot_ip_flag = false;
    SaganRouting->bluedot_hash_flag = false;
    SaganRouting->bluedot_url_flag = false;
    SaganRouting->bluedot_filename_flag = false;
    SaganRouting->bluedot_ja3_flag = false;

#endif

    struct _Sagan_Processor_Info *processor_info_engine = NULL;
    processor_info_engine = malloc(sizeof(struct _Sagan_Processor_Info));

    if ( processor_info_engine == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for processor_info_engine. Abort!", __FILE__, __LINE__);
        }

    memset(processor_info_engine, 0, sizeof(_Sagan_Processor_Info));

    struct _Sagan_Lookup_Cache_Entry *lookup_cache = NULL;
    lookup_cache = malloc(sizeof(struct _Sagan_Lookup_Cache_Entry) * MAX_PARSE_IP);

    if ( lookup_cache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for lookup_cache. Abort!", __FILE__, __LINE__);
        }

    memset(lookup_cache, 0, sizeof(_Sagan_Lookup_Cache_Entry) * MAX_PARSE_IP);

    bool after_log_flag = false;
    bool thresh_log_flag = false;

    int threadid = 0;

    int b = 0;

    bool pre_match = false;

    char *ptmp = NULL;
    char *tok2 = NULL;

    char parse_ip_src[MAXIP] = { 0 };
    char parse_ip_dst[MAXIP] = { 0 };
    char parse_md5_hash[MD5_HASH_SIZE+1] = { 0 };
    char parse_sha1_hash[SHA1_HASH_SIZE+1] = { 0 };
    char parse_sha256_hash[SHA256_HASH_SIZE+1] = { 0 };

    bool ip_src_flag = false;

    uint32_t ip_srcport_u32;
    unsigned char ip_src_bits[MAXIPBIT] = { 0 };

    bool ip_dst_flag = false;

    uint32_t ip_dstport_u32 = 0;
    unsigned char ip_dst_bits[MAXIPBIT] = { 0 };

    char tmpbuf[256] = { 0 };
    char s_msg[1024] = { 0 };

    char syslog_append_program[MAX_SYSLOGMSG] = { 0 };

    struct timeval tp;
    unsigned char proto = 0;
    int lookup_cache_size = 0;

    char *ip_src = NULL;
    char *ip_dst = NULL;

    char *md5_hash = NULL;
    char *sha1_hash = NULL;
    char *sha256_hash = NULL;

    char json_normalize[JSON_MAX_SIZE] = { 0 };

    /* These do not need to be reset each time as they are _only_
     * set through normalize */

#ifdef HAVE_LIBFASTJSON

    char *normalize_username = NULL;
    char *normalize_filename = NULL;
    char *normalize_http_uri = NULL;
    char *normalize_http_hostname = NULL;
    char *normalize_ja3 = NULL;

#endif

#ifdef HAVE_LIBMAXMINDDB

    unsigned char geoip2_return = GEOIP_MISS;

#endif

    /* Needs to be outside ifdef */

    unsigned char bluedot_results = 0;

    /* Outside the WITH_BLUEDOT because we use it in passing to Send_Alert() */

    char bluedot_json[BLUEDOT_JSON_SIZE] = { 0 };

    /* Set a default for liblognorm JSON.  In case it's not used */

    json_normalize[0] = '\0';

#ifdef HAVE_LIBLOGNORM

    static __thread struct _SaganNormalizeLiblognorm SaganNormalizeLiblognorm = { 0 };
    memset((char *)&SaganNormalizeLiblognorm, 0, sizeof(struct _SaganNormalizeLiblognorm));

#endif

    /* This needs to be included,  even if liblognorm isn't in use */

    bool liblognorm_status = 0;

    /* Get time we received the event */

    gettimeofday(&tp, 0);       /* Store event time as soon as we get it */

#ifdef HAVE_LIBFASTJSON

    /* If "parse-json-program" is enabled, we'll look for signs in the program
       field for JSON.  If we find it,  we'll append the program and message
       field */


    if ( config->parse_json_program == true || config->parse_json_message == true )
        {
            SaganProcSyslog_LOCAL->src_ip[0] = '\0';
            SaganProcSyslog_LOCAL->dst_ip[0] = '\0';
            SaganProcSyslog_LOCAL->src_port = 0;
            SaganProcSyslog_LOCAL->dst_port = 0;
            SaganProcSyslog_LOCAL->proto = 0;
        }

    if ( config->parse_json_program == true &&
            ( SaganProcSyslog_LOCAL->syslog_program[0] == '{' ||
              SaganProcSyslog_LOCAL->syslog_program[1] == '{' ) )
        {

            char tmp_json[MAX_SYSLOGMSG] = { 0 };

            if ( debug->debugjson )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Found possible JSON within program \"%s\"", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_program );
                }

            /* Merge program+message */

            snprintf(tmp_json, sizeof(tmp_json), "%s%s", SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_message );

            /* Zero out program (might get set by JSON) */

            SaganProcSyslog_LOCAL->syslog_program[0] = '\0';
            strlcpy(SaganProcSyslog_LOCAL->syslog_message, tmp_json, sizeof(SaganProcSyslog_LOCAL->syslog_message));

            /* Parse JSON */

            Parse_JSON_Message( SaganProcSyslog_LOCAL );

        }

    /* If "parse-json-message" is enabled, we'll look for signs in the message for
           JSON */

    if ( config->parse_json_message == true &&
            ( SaganProcSyslog_LOCAL->syslog_message[1] == '{' ||
              SaganProcSyslog_LOCAL->syslog_message[2] == '{'  ) )
        {

            if ( debug->debugjson )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Found possible JSON within message \"%s\".", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);
                }

            Parse_JSON_Message( SaganProcSyslog_LOCAL );

        }

#endif

    /* Search for matches */

    /* First we search for 'program' and such.   This way,  we don't waste CPU
     * time with pcre/content.  */


    for(b=0; b < counters->rulecount; b++)
        {

            ip_src_flag = false;
            ip_dst_flag = false;

            parse_ip_src[0] = '\0';
            parse_ip_dst[0] = '\0';
            parse_md5_hash[0] = '\0';
            parse_sha1_hash[0] = '\0';
            parse_sha256_hash[0] = '\0';

            ip_src = parse_ip_src;
            ip_dst = parse_ip_dst;

            md5_hash = parse_md5_hash;
            sha1_hash = parse_sha1_hash;
            sha256_hash = parse_sha256_hash;

            ip_dstport_u32 = 0;
            ip_srcport_u32 = 0;

            memset(ip_src_bits, 0, sizeof(ip_src_bits));
            memset(ip_dst_bits, 0, sizeof(ip_dst_bits));

#ifdef HAVE_LIBFASTJSON

            /* If we've already located the source/destination IP address in JSON,  we can
               set it here.  "normalize" and "parse_*_ip can still over ride */


            if ( SaganProcSyslog_LOCAL->src_ip[0] != '\0' )
                {
                    ip_src = SaganProcSyslog_LOCAL->src_ip;
                    IP2Bit(ip_src, ip_src_bits);
                    ip_src_flag = true;
                }

            if ( SaganProcSyslog_LOCAL->dst_ip[0] != '\0' )
                {

                    ip_dst = SaganProcSyslog_LOCAL->dst_ip;
                    IP2Bit(ip_dst, ip_dst_bits);
                    ip_dst_flag = true;
                }

            if ( SaganProcSyslog_LOCAL->src_port != 0 )
                {
                    ip_srcport_u32 = SaganProcSyslog_LOCAL->src_port;
                }

            if ( SaganProcSyslog_LOCAL->dst_port != 0 )
                {
                    ip_dstport_u32 = SaganProcSyslog_LOCAL->dst_port;
                }

            if ( SaganProcSyslog_LOCAL->proto != 0 )
                {
                    proto = SaganProcSyslog_LOCAL->proto;
                }

            if ( SaganProcSyslog_LOCAL->md5[0] != '\0' )
                {
                    md5_hash = SaganProcSyslog_LOCAL->md5;
                }

            if ( SaganProcSyslog_LOCAL->sha1[0] != '\0' )
                {
                    sha1_hash = SaganProcSyslog_LOCAL->sha1;
                }

            if ( SaganProcSyslog_LOCAL->sha256[0] != '\0' )
                {
                    sha256_hash = SaganProcSyslog_LOCAL->sha256;
                }

            if ( SaganProcSyslog_LOCAL->filename[0] != '\0' )
                {
                    normalize_filename = SaganProcSyslog_LOCAL->filename;
                }

            if ( SaganProcSyslog_LOCAL->hostname[0] != '\0' )
                {
                    char tmp_normalize_http_uri[MAX_HOSTNAME_SIZE + MAX_URL_SIZE] = { 0 };
                    snprintf(tmp_normalize_http_uri, sizeof(tmp_normalize_http_uri), "%s%s", SaganProcSyslog_LOCAL->hostname, SaganProcSyslog_LOCAL->url);
                    normalize_http_uri = tmp_normalize_http_uri;
                }

            if ( SaganProcSyslog_LOCAL->ja3[0] != '\0' )
                {
                    normalize_ja3 = SaganProcSyslog_LOCAL->ja3;
                }


#endif

            /* Process "normal" rules.  Skip dynamic rules if it's not time to process them */

            if ( rulestruct[b].type == NORMAL_RULE || ( rulestruct[b].type == DYNAMIC_RULE && dynamic_rule_flag == true ) )
                {

                    pre_match = false;

                    if ( rulestruct[b].s_program[0] != '\0' )
                        {

                            strlcpy(tmpbuf, rulestruct[b].s_program, sizeof(tmpbuf));

                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if ( Wildcard(ptmp, SaganProcSyslog_LOCAL->syslog_program) == 1 )
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( rulestruct[b].s_facility[0] != '\0' && pre_match == false )
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_facility, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_facility))
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( rulestruct[b].s_level[0] != '\0' && pre_match == false )
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_level, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_level))
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( rulestruct[b].s_tag[0] != '\0' && pre_match == false )
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_tag, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_tag))
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    if ( rulestruct[b].s_syspri[0] != '\0' && pre_match == false )
                        {
                            strlcpy(tmpbuf, rulestruct[b].s_syspri, sizeof(tmpbuf));
                            ptmp = strtok_r(tmpbuf, "|", &tok2);
                            pre_match = true;

                            while ( ptmp != NULL )
                                {
                                    if (!strcmp(ptmp, SaganProcSyslog_LOCAL->syslog_priority))
                                        {
                                            pre_match = false;
                                        }

                                    ptmp = strtok_r(NULL, "|", &tok2);
                                }
                        }

                    /* If there has been a pre_match above,  or NULL on all,  then we continue with
                     * PCRE/content search */

                    /* Search via strstr (content:) */

                    bool flag = false;

                    if ( pre_match == false )
                        {

                            /* If the "append_program" rule option is used,  we append the program here */

                            if ( rulestruct[b].append_program == true )
                                {
                                    snprintf(syslog_append_program, sizeof(syslog_append_program), "%s | %s", SaganProcSyslog_LOCAL->syslog_message, SaganProcSyslog_LOCAL->syslog_program);
                                    syslog_append_program[ sizeof(syslog_append_program) - 1 ] = '\0';
                                    strlcpy(SaganProcSyslog_LOCAL->syslog_message, syslog_append_program, sizeof(SaganProcSyslog_LOCAL->syslog_message));
                                }

                            /* Start processing searches from rule optison */

                            flag = true;

                            if ( rulestruct[b].content_count > 0 )
                                {
                                    flag = Content(b, SaganProcSyslog_LOCAL->syslog_message );
                                }

                            if ( flag == true && rulestruct[b].pcre_count > 0 )
                                {
                                    flag = PcreS(b, SaganProcSyslog_LOCAL->syslog_message );
                                }

                            if ( flag == true && rulestruct[b].meta_content_count > 0 )
                                {
                                    flag = Meta_Content(b, SaganProcSyslog_LOCAL->syslog_message);
                                }

                            if ( flag == true && rulestruct[b].json_pcre_count > 0 )
                                {
                                    flag = JSON_Pcre(b, SaganProcSyslog_LOCAL );
                                }

                            if ( flag == true && rulestruct[b].json_content_count > 0 )
                                {
                                    flag = JSON_Content(b, SaganProcSyslog_LOCAL );
                                }

                            if ( flag == true && rulestruct[b].json_meta_content_count > 0 )
                                {
                                    flag = JSON_Meta_Content(b, SaganProcSyslog_LOCAL );
                                }

                            if ( flag == true && rulestruct[b].event_id_count > 0 )
                                {
                                    flag = Event_ID( b, SaganProcSyslog_LOCAL );
                                }

                        }

                    /* Check for match from content, pcre, etc... */

                    if ( pre_match == false && flag == true )
                        {


#ifdef HAVE_LIBLOGNORM
                            if ( liblognorm_status == false && rulestruct[b].normalize == true )
                                {
                                    /* Set that normalization has been tried work isn't repeated */

                                    liblognorm_status = -1;

                                    Normalize_Liblognorm(SaganProcSyslog_LOCAL->syslog_message, &SaganNormalizeLiblognorm);

                                    strlcpy(json_normalize, SaganNormalizeLiblognorm.json_normalize, sizeof(json_normalize));

                                    if ( SaganNormalizeLiblognorm.ip_src[0] != '0'  ||
                                            SaganNormalizeLiblognorm.ip_dst[0] != '0'  ||
                                            SaganNormalizeLiblognorm.src_port != 0  ||
                                            SaganNormalizeLiblognorm.dst_port != 0  ||
                                            SaganNormalizeLiblognorm.hash_sha1[0] != '\0'  ||
                                            SaganNormalizeLiblognorm.hash_sha256[0] != '\0'  ||
                                            SaganNormalizeLiblognorm.hash_md5[0] != '\0' )

                                        {
                                            liblognorm_status = true;
                                        }

                                    /* These are _only_ set here */

                                    if ( SaganNormalizeLiblognorm.username[0] != '\0' )
                                        {

                                            liblognorm_status = true;
                                            normalize_username = SaganNormalizeLiblognorm.username;
                                        }

                                    if ( SaganNormalizeLiblognorm.http_uri[0] != '\0' )
                                        {
                                            liblognorm_status = true;
                                            normalize_http_uri = SaganNormalizeLiblognorm.http_uri;
                                        }

                                    if ( SaganNormalizeLiblognorm.filename[0] != '\0' )
                                        {
                                            liblognorm_status = true;
                                            normalize_filename = SaganNormalizeLiblognorm.filename;
                                        }

                                    if ( SaganNormalizeLiblognorm.ja3[0] != '\0' )
                                        {
                                            liblognorm_status = true;
                                            normalize_ja3 = SaganNormalizeLiblognorm.ja3;
                                        }

                                    if ( SaganNormalizeLiblognorm.event_id[0] != '\0' )
                                        {
                                            liblognorm_status = true;
                                            strlcpy(SaganProcSyslog_LOCAL->event_id, SaganNormalizeLiblognorm.event_id, sizeof(SaganProcSyslog_LOCAL->event_id));
                                        }

                                }

                            if ( liblognorm_status == true && rulestruct[b].normalize == true )
                                {
                                    if ( SaganNormalizeLiblognorm.ip_src[0] != '0')
                                        {
                                            ip_src_flag = true;
                                            ip_src = SaganNormalizeLiblognorm.ip_src;

                                            if ( !strcmp(ip_src, "127.0.0.1") ||
                                                    !strcmp(ip_src, "::1" ) ||
                                                    !strcmp(ip_src, "::ffff:127.0.0.1" ) )
                                                {

                                                    ip_src = SaganProcSyslog_LOCAL->syslog_host;
                                                    ip_src_flag = false;
                                                }

                                            else
                                                {

                                                    IP2Bit(ip_src, ip_src_bits);
                                                }


                                        }


                                    if ( SaganNormalizeLiblognorm.ip_dst[0] != '0' )
                                        {
                                            ip_dst_flag = true;
                                            ip_dst = SaganNormalizeLiblognorm.ip_dst;

                                            if ( !strcmp(ip_dst, "127.0.0.1") ||
                                                    !strcmp(ip_dst, "::1" ) ||
                                                    !strcmp(ip_dst, "::ffff:127.0.0.1" ) )

                                                {
                                                    ip_dst = SaganProcSyslog_LOCAL->syslog_host;
                                                    ip_dst_flag = false;
                                                }

                                            else
                                                {
                                                    IP2Bit(ip_dst, ip_dst_bits);
                                                }


                                        }

                                    if ( SaganNormalizeLiblognorm.src_port != 0 )
                                        {
                                            ip_srcport_u32 = SaganNormalizeLiblognorm.src_port;
                                        }


                                    if ( SaganNormalizeLiblognorm.dst_port != 0 )
                                        {
                                            ip_dstport_u32 = SaganNormalizeLiblognorm.dst_port;
                                        }

                                    if ( SaganNormalizeLiblognorm.hash_md5[0] != '\0' )
                                        {
                                            md5_hash = SaganNormalizeLiblognorm.hash_md5;
                                        }

                                    if ( SaganNormalizeLiblognorm.hash_sha1[0] != '\0' )
                                        {
                                            sha1_hash = SaganNormalizeLiblognorm.hash_sha1;
                                        }

                                    if ( SaganNormalizeLiblognorm.hash_sha256[0] != '\0' )
                                        {
                                            sha256_hash = SaganNormalizeLiblognorm.hash_sha256;
                                        }

                                }
#endif


                            /* Normalization should always over ride parse_src_ip/parse_dst_ip/parse_port,
                             * _unless_ liblognorm fails and both are in a rule or liblognorm failed to get src or dst */

                            /* parse_src_ip: {position} - Parse_IP build a cache table for IPs, ports, etc.  This way,
                            we only parse the syslog string one time regardless of the rule options! */

                            if ( rulestruct[b].s_find_src_ip == true ||
                                    rulestruct[b].s_find_src_ip == true ||
                                    rulestruct[b].blacklist_ipaddr_all == true ||
                                    rulestruct[b].s_find_proto == true ||
#ifdef WITH_BLUEDOT
                                    rulestruct[b].bluedot_ipaddr_type == 4 ||
#endif
                                    rulestruct[b].brointel_ipaddr_all == true )
                                {

                                    lookup_cache_size = Parse_IP(SaganProcSyslog_LOCAL->syslog_message, lookup_cache );

                                }

                            if ( ip_src_flag == false && rulestruct[b].s_find_src_ip == true )
                                {


                                    if ( lookup_cache[rulestruct[b].s_find_src_pos-1].status == true )
                                        {


                                            memcpy(parse_ip_src, lookup_cache[rulestruct[b].s_find_src_pos-1].ip, MAXIP );
                                            memcpy(ip_src_bits, lookup_cache[rulestruct[b].s_find_src_pos-1].ip_bits, MAXIPBIT);

                                            ip_src = parse_ip_src;

                                            if ( !strcmp(ip_src, "127.0.0.1") ||
                                                    !strcmp(ip_src, "::1" ) ||
                                                    !strcmp(ip_src, "::ffff:127.0.0.1" ) )
                                                {

                                                    ip_src = SaganProcSyslog_LOCAL->syslog_host;
                                                    ip_src_flag = false;
                                                }

                                            ip_srcport_u32 = lookup_cache[rulestruct[b].s_find_src_pos-1].port;
                                            proto = lookup_cache[0].proto;
                                            ip_src_flag = true;

                                        }

                                }


                            /* parse_dst_ip: {position} */

                            if ( ip_dst_flag == false && rulestruct[b].s_find_dst_ip == true )
                                {

                                    if ( lookup_cache[rulestruct[b].s_find_dst_pos-1].status == true )
                                        {

                                            memcpy(parse_ip_dst, lookup_cache[rulestruct[b].s_find_dst_pos-1].ip, MAXIP );
                                            memcpy(ip_dst_bits, lookup_cache[rulestruct[b].s_find_dst_pos-1].ip_bits, MAXIPBIT);
                                            ip_dst = parse_ip_dst;

                                            if ( !strcmp(ip_dst, "127.0.0.1") ||
                                                    !strcmp(ip_dst, "::1" ) ||
                                                    !strcmp(ip_dst, "::ffff:127.0.0.1" ))
                                                {

                                                    ip_dst = SaganProcSyslog_LOCAL->syslog_host;
                                                    ip_dst_flag = false;

                                                }

                                            ip_dstport_u32 = lookup_cache[rulestruct[b].s_find_dst_pos-1].port;
                                            proto = lookup_cache[0].proto;
                                            ip_dst_flag = true;

                                        }

                                }

                            /* parse_hash: md5 */

                            if ( parse_md5_hash[0] == '\0' && rulestruct[b].s_find_hash_type == PARSE_HASH_MD5 )
                                {
                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_MD5, parse_md5_hash, sizeof(parse_md5_hash));
                                    md5_hash = parse_md5_hash;
                                }

                            else if ( parse_sha1_hash[0] == '\0' && rulestruct[b].s_find_hash_type == PARSE_HASH_SHA1 )
                                {
                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_SHA1, parse_sha256_hash, sizeof(parse_sha1_hash));
                                    sha1_hash = parse_sha1_hash;
                                }

                            else if ( parse_sha256_hash[0] == '\0' && rulestruct[b].s_find_hash_type == PARSE_HASH_SHA256 )
                                {
                                    Parse_Hash(SaganProcSyslog_LOCAL->syslog_message, PARSE_HASH_SHA256, parse_sha256_hash, sizeof(parse_sha256_hash));
                                    sha256_hash = parse_sha256_hash;
                                }

                            /* If the rule calls for proto searching,  we do it now */

                            if ( rulestruct[b].s_find_proto_program == true )
                                {
                                    proto = Parse_Proto_Program(SaganProcSyslog_LOCAL->syslog_program);
                                }


                            /* If proto is not searched or has failed,  default to whatever the rule told us to use */

                            if ( ip_src_flag == false )
                                {

                                    /* We don't want 127.0.0.1,  so if the source is that, we change it to config->sagan_host */

                                    if (!strcmp(SaganProcSyslog_LOCAL->syslog_host, "127.0.0.1") ||
                                            !strcmp(SaganProcSyslog_LOCAL->syslog_host, "::1" ) ||
                                            !strcmp(SaganProcSyslog_LOCAL->syslog_host, "::ffff:127.0.0.1" ) )

                                        {
                                            ip_src = config->sagan_host;
                                        }
                                    else
                                        {

                                            ip_src = SaganProcSyslog_LOCAL->syslog_host;
                                        }

                                    IP2Bit(ip_src, ip_src_bits);

                                }

                            if ( ip_dst_flag == false )
                                {

                                    /* We don't want 127.0.0.1,  so if the source is that, we
                                    change it to config->sagan_host */

                                    if (!strcmp(SaganProcSyslog_LOCAL->syslog_host, "127.0.0.1") ||
                                            !strcmp(SaganProcSyslog_LOCAL->syslog_host, "::1" ) ||
                                            !strcmp(SaganProcSyslog_LOCAL->syslog_host, "::ffff:127.0.0.1" ) )
                                        {
                                            ip_dst = config->sagan_host;
                                        }
                                    else
                                        {

                                            ip_dst = SaganProcSyslog_LOCAL->syslog_host;

                                        }

                                    IP2Bit(ip_dst, ip_dst_bits);
                                }

                            /* No source port was normalized, Use the rules default */

                            if ( ip_srcport_u32 == 0 )
                                {
                                    ip_srcport_u32=rulestruct[b].default_src_port;
                                }

                            /* No destination port was normalzied. Use the rules default */

                            if ( ip_dstport_u32 == 0 )
                                {
                                    ip_dstport_u32=rulestruct[b].default_dst_port;
                                }

                            /* No protocol was normalized.  Use the rules default */

                            if ( proto == 0 )
                                {
                                    proto = rulestruct[b].default_proto;
                                }

                            strlcpy(s_msg, rulestruct[b].s_msg, sizeof(s_msg));

                            /* Check for flow of rule - has_flow is set as rule loading.  It 1, then
                            the rule has some sort of flow.  It 0,  rule is set any:any/any:any */

                            if ( rulestruct[b].has_flow == true )
                                {

                                    SaganRouting->check_flow_return = Check_Flow( b, proto, ip_src_bits, ip_srcport_u32, ip_dst_bits, ip_dstport_u32);

                                    if( SaganRouting->check_flow_return == false)
                                        {

                                            __atomic_add_fetch(&counters->follow_flow_drop, 1, __ATOMIC_SEQ_CST);

                                        }

                                    __atomic_add_fetch(&counters->follow_flow_total, 1, __ATOMIC_SEQ_CST);

                                }


                            /****************************************************************************
                                             * flexbit/xbit "upause".  This lets flexbits/xbit settle in "tight" timing situations.
                              ****************************************************************************/


                            /* pause (seconds) */

                            if ( rulestruct[b].flexbit_pause_time != 0 )
                                {

                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] flexbit_pause for %d seconds", __FILE__, __LINE__, rulestruct[b].flexbit_pause_time);
                                        }


                                    sleep( rulestruct[b].flexbit_pause_time );
                                }

                            /* upause (millisecond) */

                            if ( rulestruct[b].flexbit_upause_time != 0 )
                                {
                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] flexbit_pause for %d microseconds", __FILE__, __LINE__, rulestruct[b].flexbit_upause_time);
                                        }

                                    usleep( rulestruct[b].flexbit_upause_time );
                                }

                            /* pause (second) */

                            if ( rulestruct[b].xbit_pause_time != 0 )
                                {

                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] xbit_pause for %d seconds", __FILE__, __LINE__, rulestruct[b].xbit_pause_time);
                                        }

                                    sleep( rulestruct[b].xbit_pause_time );
                                }

                            if ( rulestruct[b].xbit_upause_time != 0 )
                                {
                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(DEBUG, "[%s, line %d] xbit_upause for %d microseconds", __FILE__, __LINE__, rulestruct[b].xbit_upause_time);
                                        }


                                    sleep( rulestruct[b].xbit_upause_time );
                                }

                            /****************************************************************************
                             * xbit - ISSET || ISNOTSET
                             ****************************************************************************/

                            if ( rulestruct[b].xbit_flag && ( rulestruct[b].xbit_isset_count || rulestruct[b].xbit_isnotset_count ) )
                                {
                                    SaganRouting->xbit_return = Xbit_Condition(b, ip_src, ip_dst);
                                }

                            /****************************************************************************
                             * flexbit - ISSET || ISNOTSET
                             ****************************************************************************/

                            if ( rulestruct[b].flexbit_flag )
                                {

                                    if ( rulestruct[b].flexbit_condition_count )
                                        {
                                            SaganRouting->flexbit_return = Flexbit_Condition(b, ip_src, ip_dst, ip_srcport_u32, ip_dstport_u32);
                                        }

                                    if ( rulestruct[b].flexbit_count_flag )
                                        {
                                            SaganRouting->flexbit_count_return = Flexbit_Count(b, ip_src, ip_dst);
                                        }

                                }


                            /****************************************************************************
                             * Country code
                             ****************************************************************************/

#ifdef HAVE_LIBMAXMINDDB

                            if ( rulestruct[b].geoip2_flag )
                                {

                                    /* Set geoip2_return to GEOIP_SKIP in case ip_src_flag
                                       or ip_dst_flag is false! This way it will short
                                       circuit past the rest of the GeoIP logic. */

                                    geoip2_return = GEOIP_SKIP;
                                    SaganRouting->geoip2_isset = false;

                                    if ( ip_src_flag == true && rulestruct[b].geoip2_src_or_dst == 1 )
                                        {
                                            geoip2_return = GeoIP2_Lookup_Country(ip_src, b );
                                        }

                                    else if ( ip_dst_flag == true && rulestruct[b].geoip2_src_or_dst == 2 )
                                        {
                                            geoip2_return = GeoIP2_Lookup_Country(ip_dst, b );
                                        }

                                    if ( geoip2_return != GEOIP_SKIP )
                                        {

                                            /* If country IS NOT {my value} return 1 */

                                            if ( rulestruct[b].geoip2_type == 1 )    		/* isnot */
                                                {

                                                    if ( geoip2_return == GEOIP_HIT )
                                                        {
                                                            SaganRouting->geoip2_isset = false;
                                                        }
                                                    else
                                                        {
                                                            SaganRouting->geoip2_isset = true;

                                                            __atomic_add_fetch(&counters->geoip2_hit, 1, __ATOMIC_SEQ_CST);

                                                        }
                                                }

                                            /* If country IS {my value} return 1 */

                                            else if ( rulestruct[b].geoip2_type == 2 )             /* is */
                                                {

                                                    if ( geoip2_return == GEOIP_HIT )
                                                        {
                                                            SaganRouting->geoip2_isset = true;

                                                            __atomic_add_fetch(&counters->geoip2_hit, 1, __ATOMIC_SEQ_CST);

                                                        }
                                                    else
                                                        {

                                                            SaganRouting->geoip2_isset = false;
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

                                    SaganRouting->alert_time_trigger = false;

                                    if ( Check_Time(b) )
                                        {
                                            SaganRouting->alert_time_trigger = true;
                                        }
                                }

                            /****************************************************************************
                             * Blacklist
                             ****************************************************************************/

                            if ( rulestruct[b].blacklist_flag )
                                {

                                    SaganRouting->blacklist_results = false;

                                    if ( rulestruct[b].blacklist_ipaddr_src && ip_src_flag )
                                        {
                                            SaganRouting->blacklist_results = Sagan_Blacklist_IPADDR( ip_src_bits );
                                        }

                                    if ( SaganRouting->blacklist_results == false && rulestruct[b].blacklist_ipaddr_dst && ip_dst_flag )
                                        {
                                            SaganRouting->blacklist_results = Sagan_Blacklist_IPADDR( ip_dst_bits );
                                        }

                                    if ( SaganRouting->blacklist_results == false && rulestruct[b].blacklist_ipaddr_all )
                                        {
                                            SaganRouting->blacklist_results = Sagan_Blacklist_IPADDR_All(SaganProcSyslog_LOCAL->syslog_message, lookup_cache, lookup_cache_size);
                                        }

                                    if ( SaganRouting->blacklist_results == false && rulestruct[b].blacklist_ipaddr_both && ip_src_flag && ip_dst_flag )
                                        {
                                            if ( Sagan_Blacklist_IPADDR( ip_src_bits ) || Sagan_Blacklist_IPADDR( ip_dst_bits ) )
                                                {
                                                    SaganRouting->blacklist_results = true;
                                                }
                                        }
                                }

#ifdef WITH_BLUEDOT

                            if ( config->bluedot_flag )
                                {

                                    bluedot_results = 0;
                                    bluedot_json[0] = '\0';

                                    if ( rulestruct[b].bluedot_ipaddr_type )
                                        {

                                            /* 1 == src,  2 == dst,  3 == both,  4 == all */

                                            if ( rulestruct[b].bluedot_ipaddr_type == 1 && ip_src_flag )
                                                {
                                                    bluedot_results = Sagan_Bluedot_Lookup(ip_src, BLUEDOT_LOOKUP_IP, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                }

                                            if ( rulestruct[b].bluedot_ipaddr_type == 2 && ip_dst_flag )
                                                {
                                                    bluedot_results = Sagan_Bluedot_Lookup(ip_dst, BLUEDOT_LOOKUP_IP, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                }

                                            if ( rulestruct[b].bluedot_ipaddr_type == 3 && ip_src_flag && ip_dst_flag )
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup(ip_src, BLUEDOT_LOOKUP_IP, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                    /* If the source isn't found,  then check the dst */

                                                    if ( SaganRouting->bluedot_ip_flag == 0 )
                                                        {
                                                            bluedot_results = Sagan_Bluedot_Lookup(ip_dst, BLUEDOT_LOOKUP_IP, b, bluedot_json, sizeof(bluedot_json));
                                                            SaganRouting->bluedot_ip_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_IP);
                                                        }

                                                }

                                            if ( lookup_cache_size > 0 && rulestruct[b].bluedot_ipaddr_type == 4 )
                                                {

                                                    SaganRouting->bluedot_ip_flag = Sagan_Bluedot_IP_Lookup_All(SaganProcSyslog_LOCAL->syslog_message, b, lookup_cache, lookup_cache_size );

                                                }


                                        }



                                    if ( rulestruct[b].bluedot_file_hash )
                                        {


                                            if ( md5_hash[0] != '\0')
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup( md5_hash, BLUEDOT_LOOKUP_HASH, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH);

                                                }

                                            if ( sha256_hash[0] != '\0' )
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup( sha256_hash, BLUEDOT_LOOKUP_HASH, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH );

                                                }

                                            if ( sha256_hash[0] != '\0')
                                                {

                                                    bluedot_results = Sagan_Bluedot_Lookup( sha256_hash, BLUEDOT_LOOKUP_HASH, b, bluedot_json, sizeof(bluedot_json));
                                                    SaganRouting->bluedot_hash_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_HASH);

                                                }

                                        }

                                    if ( rulestruct[b].bluedot_url && normalize_http_uri != NULL )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( normalize_http_uri, BLUEDOT_LOOKUP_URL, b, bluedot_json, sizeof(bluedot_json));
                                            SaganRouting->bluedot_url_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_URL);

                                        }

                                    if ( rulestruct[b].bluedot_filename && normalize_filename != NULL )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( normalize_filename, BLUEDOT_LOOKUP_FILENAME, b, bluedot_json, sizeof(bluedot_json));
                                            SaganRouting->bluedot_filename_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_FILENAME);

                                        }

                                    if ( rulestruct[b].bluedot_ja3 && normalize_ja3 != NULL )
                                        {

                                            bluedot_results = Sagan_Bluedot_Lookup( normalize_ja3, BLUEDOT_LOOKUP_JA3, b, bluedot_json, sizeof(bluedot_json));
                                            SaganRouting->bluedot_ja3_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, b, BLUEDOT_LOOKUP_JA3);

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

                                    SaganRouting->brointel_results = false;

                                    if ( rulestruct[b].brointel_ipaddr_src && ip_src_flag )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_IPADDR( ip_src_bits, ip_src );
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_ipaddr_dst && ip_dst_flag )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_IPADDR( ip_dst_bits, ip_dst );
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_ipaddr_all )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_IPADDR_All ( SaganProcSyslog_LOCAL->syslog_message, lookup_cache, MAX_PARSE_IP);
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_ipaddr_both && ip_src_flag && ip_dst_flag )
                                        {
                                            if ( Sagan_BroIntel_IPADDR( ip_src_bits, ip_src ) || Sagan_BroIntel_IPADDR( ip_dst_bits, ip_dst ) )
                                                {
                                                    SaganRouting->brointel_results = true;
                                                }
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_domain )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_DOMAIN(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_file_hash )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_FILE_HASH(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_url )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_URL(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_software )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_SOFTWARE(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_user_name )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_USER_NAME(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_file_name )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_FILE_NAME(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                    if ( SaganRouting->brointel_results == false && rulestruct[b].brointel_cert_hash )
                                        {
                                            SaganRouting->brointel_results = Sagan_BroIntel_CERT_HASH(SaganProcSyslog_LOCAL->syslog_message);
                                        }

                                }

                            /****************************************************************************/
                            /* Populate the Sagan Event array with the information needed.  This info    */
                            /* will be passed to the threads.  No need to populate it _if_ we're in a   */
                            /* threshold state.                                                         */
                            /****************************************************************************/

                            SaganRouting->position = b;

                            if ( Sagan_Check_Routing( SaganRouting ) == true )
                                {

                                    /* After */

                                    after_log_flag = false;

                                    if ( rulestruct[b].after2 == true )
                                        {
                                            after_log_flag = After2 (b, ip_src, ip_srcport_u32, ip_dst, ip_dstport_u32, normalize_username, SaganProcSyslog_LOCAL->syslog_message );
                                        }

                                    /* Threshold */

                                    thresh_log_flag = false;

                                    if ( rulestruct[b].threshold2_type != 0 && after_log_flag == false )
                                        {
                                            thresh_log_flag = Threshold2 (b, ip_src, ip_srcport_u32, ip_dst, ip_dstport_u32, normalize_username, SaganProcSyslog_LOCAL->syslog_message );
                                        }


                                    if ( config->rule_tracking_flag == true )
                                        {
                                            Ruleset_Track[rulestruct[b].ruleset_id].trigger = true;
                                        }


                                    __atomic_add_fetch(&counters->saganfound, 1, __ATOMIC_SEQ_CST);

                                    /* Check for thesholding & "after" */

                                    if ( thresh_log_flag == false && after_log_flag == false )
                                        {

                                            if ( debug->debugengine )
                                                {

                                                    Sagan_Log(DEBUG, "[%s, line %d] **[Trigger]*********************************", __FILE__, __LINE__);
                                                    Sagan_Log(DEBUG, "[%s, line %d] Program: %s | Facility: %s | Priority: %s | Level: %s | Tag: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_program, SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->syslog_tag);
                                                    Sagan_Log(DEBUG, "[%s, line %d] Threshold flag: %d | After flag: %d | Flexbit Flag: %d | Flexbit status: %d", __FILE__, __LINE__, thresh_log_flag, after_log_flag, rulestruct[b].flexbit_flag, SaganRouting->flexbit_return);
                                                    Sagan_Log(DEBUG, "[%s, line %d] Triggering Message: %s", __FILE__, __LINE__, SaganProcSyslog_LOCAL->syslog_message);

                                                }

                                            /* Do we need to "set" an xbit? */

                                            if ( rulestruct[b].xbit_flag && ( rulestruct[b].xbit_set_count || rulestruct[b].xbit_unset_count ) )
                                                {
                                                    Xbit_Set(b, ip_src, ip_dst, SaganProcSyslog_LOCAL);
                                                }

                                            /* Check to "set" a flexbit */

                                            if ( rulestruct[b].flexbit_flag && rulestruct[b].flexbit_set_count )
                                                {
                                                    Flexbit_Set(b, ip_src, ip_dst, ip_srcport_u32, ip_dstport_u32, SaganProcSyslog_LOCAL);
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

                                            if ( rulestruct[b].flexbit_flag == false || rulestruct[b].flexbit_noalert == 0 )
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
                                                                       proto,
                                                                       rulestruct[b].s_sid,
                                                                       ip_srcport_u32,
                                                                       ip_dstport_u32,
                                                                       b, tp, bluedot_json, bluedot_results );


                                                        }
                                                    else
                                                        {

                                                            Sagan_Dynamic_Rules(SaganProcSyslog_LOCAL, b, processor_info_engine,
                                                                                ip_src, ip_dst);

                                                        }

                                                }


                                        } /* Threshold / After */

                                } /* End of routing */

                        } /* End of pcre/content/etc match */

                    pre_match = false;  		      /* Reset match! */
                    SaganRouting->flexbit_return=false;	      /* Flexbit reset */
                    SaganRouting->xbit_return=false;            /* xbit reset */
                    SaganRouting->check_flow_return = true;      /* Rule flow direction reset */

                } /* If normal or dynamic rule */

        } /* End for for loop */


#ifdef HAVE_LIBFASTJSON

    if ( config->eve_flag && config->eve_logs )
        {
            Log_JSON(SaganProcSyslog_LOCAL, tp);
        }

#endif

    free(processor_info_engine);
    free(lookup_cache);
    free(SaganRouting);

    return(0);
}
