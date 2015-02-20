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

/* sagan-search.c
*
* This processor takes a list of terms and searchs for them in log lines.
* For example,  a list of known malware domain names
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-search.h"
#include "sagan-send-alert.h"
#include "sagan-liblognorm.h"
#include "sagan-config.h"

#include "parsers/parsers.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;

struct _Sagan_Nocase_Searchlist *SaganNocaseSearchlist;
struct _Sagan_Case_Searchlist *SaganCaseSearchlist;

struct _Sagan_Processor_Info *processor_info_search = NULL;

#ifdef HAVE_LIBLOGNORM
struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm;
pthread_mutex_t Lognorm_Mutex;
#endif

/****************************************************************************
 * Init memory for usage
 ****************************************************************************/

void Sagan_Search_Init ( void )
{

    SaganNocaseSearchlist = malloc(sizeof(_Sagan_Nocase_Searchlist));
    SaganCaseSearchlist = malloc(sizeof(_Sagan_Case_Searchlist));

}


/****************************************************************************
 * Sagan_Search_Load - Initializes processor info and loads the search
 * file into memory
 ****************************************************************************/


int Sagan_Search_Load ( int type )
{

    FILE *search;
    char searchbuf[1024] = { 0 };
    char tmpfile[MAXPATH];

    processor_info_search = malloc(sizeof(struct _Sagan_Processor_Info));
    memset(processor_info_search, 0, sizeof(_Sagan_Processor_Info));

    processor_info_search->processor_name          =       SEARCH_PROCESSOR_NAME;
    processor_info_search->processor_generator_id  =       SEARCH_PROCESSOR_GENERATOR_ID;
    processor_info_search->processor_name          =       SEARCH_PROCESSOR_NAME;
    processor_info_search->processor_facility      =       SEARCH_PROCESSOR_FACILITY;
    processor_info_search->processor_priority      =       SEARCH_PROCESSOR_PRIORITY;
    processor_info_search->processor_pri           =       SEARCH_PROCESSOR_PRI;
    processor_info_search->processor_class         =       SEARCH_PROCESSOR_CLASS;
    processor_info_search->processor_tag           =       SEARCH_PROCESSOR_TAG;
    processor_info_search->processor_rev           =       SEARCH_PROCESSOR_REV;

    if ( type == 1 )
        {
            strlcpy(tmpfile, config->search_nocase_file, sizeof(tmpfile));
        }
    else
        {
            strlcpy(tmpfile, config->search_case_file,  sizeof(tmpfile));
        }

    if (( search = fopen(tmpfile, "r" )) == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] No search list to load (%s)", __FILE__, __LINE__, config->search_nocase_file);
        }

    while(fgets(searchbuf, 1024, search) != NULL)
        {

            /* Skip comments and blank linkes */

            if (searchbuf[0] == '#' || searchbuf[0] == 10 || searchbuf[0] == ';' || searchbuf[0] == 32)
                {
                    continue;

                }
            else
                {

                    if ( type == 1)
                        {
                            SaganNocaseSearchlist = (_Sagan_Nocase_Searchlist *) realloc(SaganNocaseSearchlist, (counters->search_nocase_count+1) * sizeof(_Sagan_Nocase_Searchlist));
                            strlcpy(SaganNocaseSearchlist[counters->search_nocase_count].search, Remove_Return(searchbuf), sizeof(SaganNocaseSearchlist[counters->search_nocase_count].search));
                            counters->search_nocase_count++;
                        }
                    else
                        {
                            SaganCaseSearchlist = (_Sagan_Case_Searchlist *) realloc(SaganCaseSearchlist, (counters->search_case_count+1) * sizeof(_Sagan_Case_Searchlist));
                            strlcpy(SaganCaseSearchlist[counters->search_case_count].search, Remove_Return(searchbuf),  sizeof(SaganCaseSearchlist[counters->search_case_count].search));
                            counters->search_case_count++;
                        }

                }
        }

    return(0);
}

/*****************************************************************************
 * Sagan_Search - Searches a syslog_message for words, phrases, etc.  from
 * the Sagan_Search_Load
 *****************************************************************************/

void Sagan_Search (_SaganProcSyslog *SaganProcSyslog_LOCAL, int type )
{

    int i;

    char ip_src[MAXIP] = { 0 };
    char ip_dst[MAXIP] = { 0 };

    int   src_port = 0;
    int   dst_port = 0;
    int   proto = 0;

    if ( type == 1 )
        {

            for (i=0; i<counters->search_nocase_count; i++)
                {

                    ip_src[0] = '0';
                    ip_src[1] = '\0';

                    ip_dst[0] = '0';
                    ip_dst[1] = '\0';

                    if (Sagan_stristr(SaganProcSyslog_LOCAL->syslog_message, SaganNocaseSearchlist[i].search, TRUE))
                        {

                            counters->search_nocase_hit_count++;

#ifdef HAVE_LIBLOGNORM
                            if ( config->search_nocase_lognorm)
                                {

                                    pthread_mutex_lock(&Lognorm_Mutex);

                                    Sagan_Normalize_Liblognorm(SaganProcSyslog_LOCAL->syslog_message);

                                    if (SaganNormalizeLiblognorm->ip_src[0] != '0')
                                        strlcpy(ip_src, SaganNormalizeLiblognorm->ip_src, sizeof(ip_src));


                                    if (SaganNormalizeLiblognorm->ip_dst[0] != '0')
                                        strlcpy(ip_dst, SaganNormalizeLiblognorm->ip_dst, sizeof(ip_dst));


                                    src_port = SaganNormalizeLiblognorm->src_port;
                                    dst_port = SaganNormalizeLiblognorm->dst_port;
                                    pthread_mutex_unlock(&Lognorm_Mutex);

                                    if ( ip_src[0] == '0' ) strlcpy(ip_src, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_src));
                                    if ( ip_dst[0] == '0' ) strlcpy(ip_dst, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_dst));
                                }
#endif

                            if ( src_port == 0 ) src_port = config->sagan_port;
                            if ( dst_port == 0 ) dst_port = config->sagan_port;

                            if ( config->search_nocase_parse_src && ip_src[0] == '0' )
                                {

                                    strlcpy(ip_src, parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->search_nocase_parse_src), sizeof(ip_src));
                                    if ( ip_src[0] == '0' ) strlcpy(ip_src, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_src));
                                }

                            if ( config->search_nocase_parse_dst && ip_dst[0] == '0' )
                                {

                                    strlcpy(ip_dst, parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->search_nocase_parse_dst), sizeof(ip_dst));
                                    if ( ip_dst[0] == '0' ) strlcpy(ip_dst, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_dst));
                                }

                            if ( config->search_nocase_parse_proto ) proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);
                            if ( config->search_nocase_parse_proto_program ) proto = parse_proto_program(SaganProcSyslog_LOCAL->syslog_program);
                            if ( proto == 0 ) proto = config->sagan_proto;

                            Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info_search, ip_src, ip_dst, proto, 1, src_port, dst_port, 0);

                        }
                }
        }
    else
        {

            for (i=0; i<counters->search_case_count; i++)
                {

                    ip_src[0] = '0';
                    ip_src[1] = '\0';

                    ip_dst[0] = '0';
                    ip_dst[1] = '\0';

                    if (Sagan_strstr(SaganProcSyslog_LOCAL->syslog_message, SaganCaseSearchlist[i].search ))
                        {

                            counters->search_case_hit_count++;

#ifdef HAVE_LIBLOGNORM
                            if ( config->search_case_lognorm)
                                {

                                    pthread_mutex_lock(&Lognorm_Mutex);

                                    Sagan_Normalize_Liblognorm(SaganProcSyslog_LOCAL->syslog_message);

                                    if (SaganNormalizeLiblognorm->ip_src[0] != '0')
                                        strlcpy(ip_src, SaganNormalizeLiblognorm->ip_src, sizeof(ip_src));

                                    if (SaganNormalizeLiblognorm->ip_dst[0] != '0')
                                        strlcpy(ip_dst, SaganNormalizeLiblognorm->ip_dst, sizeof(ip_dst));

                                    src_port = SaganNormalizeLiblognorm->src_port;
                                    dst_port = SaganNormalizeLiblognorm->dst_port;

                                    pthread_mutex_unlock(&Lognorm_Mutex);
                                }

#endif

                            if ( src_port == 0 ) src_port = config->sagan_port;
                            if ( dst_port == 0 ) dst_port = config->sagan_port;

                            if ( config->search_case_parse_src && ip_src[0] == '0')
                                {

                                    strlcpy(ip_src, parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->search_nocase_parse_src), sizeof(ip_src));
                                    if ( ip_src[0] =='0' ) strlcpy(ip_src, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_src));
                                }

                            if ( config->search_case_parse_dst && ip_dst[0] == '0' )
                                {

                                    strlcpy(ip_dst, parse_ip(SaganProcSyslog_LOCAL->syslog_message, config->search_nocase_parse_dst), sizeof(ip_dst));
                                    if ( ip_dst[0] == '0' ) strlcpy(ip_dst, SaganProcSyslog_LOCAL->syslog_host, sizeof(ip_dst));
                                }

                            if ( config->search_nocase_parse_proto ) proto = parse_proto(SaganProcSyslog_LOCAL->syslog_message);
                            if ( config->search_case_parse_proto_program ) proto = parse_proto_program(SaganProcSyslog_LOCAL->syslog_program);
                            if ( proto == 0 ) proto = config->sagan_proto;

                            Sagan_Send_Alert(SaganProcSyslog_LOCAL, processor_info_search, ip_src, ip_dst, config->sagan_proto, 2, src_port, dst_port, 0);
                        }
                }
        }
}

