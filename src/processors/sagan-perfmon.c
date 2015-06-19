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

/* sagan-perfmon.c
*
* This write out statistics to a CSV type file so often (user defined).  If
* enabled,  this thread never exits
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "sagan-lockfile.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;

/*****************************************************************************
 * Sagan_Perfmonitor_Handler - This becomes the thread to write out
 * preformance monitoring data.
 *****************************************************************************/

void Sagan_Perfmonitor_Handler( void )
{

    unsigned long total=0;
    unsigned long seconds=0;

    char curtime_utime[64] = { 0 };
    time_t t;
    struct tm *now;

    t = time(NULL);
    now=localtime(&t);
    strftime(curtime_utime, sizeof(curtime_utime), "%s",  now);

    uint64_t last_sagantotal = 0;
    uint64_t last_saganfound = 0;
    uint64_t last_alert_total = 0;
    uint64_t last_after_total = 0;
    uint64_t last_threshold_total = 0;
    uint64_t last_sagan_processor_drop = 0;
    uint64_t last_ignore_count = 0;

#ifdef HAVE_LIBMAXMINDDB
    uint64_t last_geoip2_lookup = 0;
    uint64_t last_geoip2_hit = 0;
    uint64_t last_geoip2_miss = 0;
#endif

#ifdef WITH_WEBSENSE
    uint64_t last_websense_cache_hit = 0;
    uint64_t last_websense_error_count = 0;
    uint64_t last_websense_positive_hit = 0;
#endif

#ifdef HAVE_LIBESMTP
    uint64_t last_esmtp_count_success = 0;
    uint64_t last_esmtp_count_failed = 0;
#endif

    uint64_t last_blacklist_hit_count = 0;
    uint64_t last_sagan_output_drop = 0;

    uint64_t last_dns_miss_count = 0;

    while (1)
        {

            sleep(config->perfmonitor_time);

            if ( config->perfmonitor_flag )
                {

                    fprintf(config->perfmonitor_file_stream, "%s,", curtime_utime),

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->sagantotal - last_sagantotal);
                    last_sagantotal = counters->sagantotal;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->saganfound - last_saganfound);
                    last_saganfound = counters->saganfound;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->alert_total - last_alert_total);
                    last_alert_total = counters->alert_total;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->after_total - last_after_total);
                    last_after_total = counters->after_total;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->threshold_total - last_threshold_total);
                    last_threshold_total = counters->threshold_total;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->sagan_processor_drop - last_sagan_processor_drop);
                    last_sagan_processor_drop = counters->sagan_processor_drop;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->ignore_count - last_ignore_count);
                    last_ignore_count = counters->ignore_count;

                    t = time(NULL);
                    now=localtime(&t);
                    strftime(curtime_utime, sizeof(curtime_utime), "%s",  now);
                    seconds = atol(curtime_utime) - atol(config->sagan_startutime);
                    total = counters->sagantotal / seconds;

                    fprintf(config->perfmonitor_file_stream, "%lu,", total);

#ifdef HAVE_LIBMAXMINDDB

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->geoip2_lookup - last_geoip2_lookup);
                    last_geoip2_lookup = counters->geoip2_lookup;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->geoip2_hit - last_geoip2_hit);
                    last_geoip2_hit = counters->geoip2_hit;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->geoip2_miss - last_geoip2_miss);
                    last_geoip2_miss = counters->geoip2_miss;

#endif

#ifndef HAVE_LIBMAXMINDDB

                    fprintf(config->perfmonitor_file_stream, "0,0,0,");

#endif

                    /* DEBUG: IS THE BELOW RIGHT?  TWO counters->sagan_processor_drop REFERENCES */

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->sagan_processor_drop - last_sagan_processor_drop);
                    last_sagan_processor_drop = counters->sagan_processor_drop;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->blacklist_hit_count - last_blacklist_hit_count);
                    last_blacklist_hit_count = counters->blacklist_hit_count;

                    /* DEBUG: CONSTANT? */

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->track_clients_client_count);
                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->track_clients_down);

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->sagan_output_drop - last_sagan_output_drop);
                    last_sagan_output_drop = counters->sagan_output_drop;

#ifdef HAVE_LIBESMTP
                    if ( config->sagan_esmtp_flag )
                        {

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->esmtp_count_success - last_esmtp_count_success);
                            last_esmtp_count_success = counters->esmtp_count_success;

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->esmtp_count_failed - last_esmtp_count_failed);
                            last_esmtp_count_failed = counters->esmtp_count_failed;
                        }
                    else
                        {
                            fprintf(config->perfmonitor_file_stream, "0,0,");
                        }
#endif

#ifndef HAVE_LIBESMTP
                    fprintf(config->perfmonitor_file_stream, "0,0,");
#endif

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->dns_cache_count);

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->dns_miss_count - last_dns_miss_count);
                    last_dns_miss_count = counters->dns_miss_count;

#ifdef WITH_WEBSENSE

                    if (config->websense_flag)
                        {

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->websense_cache_count);

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->websense_cache_hit - last_websense_cache_hit);
                            last_websense_cache_hit = counters->websense_cache_hit;

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->websense_error_count - last_websense_error_count);
                            last_websense_error_count = counters->websense_error_count;

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 "", counters->websense_postive_hit - last_websense_positive_hit); 	/* Don't need , here */
                            last_websense_positive_hit = counters->websense_postive_hit;

                        }
                    else
                        {

                            fprintf(config->perfmonitor_file_stream, "0,0,0,0,0");
                        }

#endif

#ifndef WITH_WEBSENSE
                    fprintf(config->perfmonitor_file_stream, "0,0,0,0,0");
#endif

                    fprintf(config->perfmonitor_file_stream, "\n");
                    fflush(config->perfmonitor_file_stream);
                }
        }
}

/*****************************************************************************
 * Sagan_Perfmonitor_Close - Closes performance monitoring file.
 *****************************************************************************/

void Sagan_Perfmonitor_Close(void)
{

    char curtime[64] = { 0 };

    time_t t;
    struct tm *now;

    t = time(NULL);
    now=localtime(&t);
    strftime(curtime, sizeof(curtime), "%m/%d/%Y %H:%M:%S",  now);

    fprintf(config->perfmonitor_file_stream, "################################ Perfmon end: pid=%d at=%s ###################################\n", getpid(), curtime);

    fflush(config->perfmonitor_file_stream);
    fclose(config->perfmonitor_file_stream);

}

/*****************************************************************************
 * Sagan_Perfmonitor_Open - Open's performance monitoring file.
 *****************************************************************************/

void Sagan_Perfmonitor_Open(void)
{

    char curtime[64] = { 0 };
    time_t t;
    struct tm *now;

    t = time(NULL);
    now=localtime(&t);
    strftime(curtime, sizeof(curtime), "%m/%d/%Y %H:%M:%S",  now);

    if (( config->perfmonitor_file_stream = fopen(config->perfmonitor_file_name, "a" )) == NULL )
        {
            Remove_Lock_File();
            Sagan_Log(S_ERROR, "[%s, line %d] Can't open %s - %s!", __FILE__, __LINE__, config->perfmonitor_file_name, strerror(errno));
        }

    fprintf(config->perfmonitor_file_stream, "################################ Perfmon start: pid=%d at=%s ###################################\n", getpid(), curtime);
    fprintf(config->perfmonitor_file_stream, "# engine.utime,engine.total,engine.sig_match.total,engine.alerts.total,engine.after.total,engine.threshold.total, engine.drop.total,engine.ignored.total,engine.eps,geoip2.lookup.total,geoip2.hits,geoip2.misses,processor.drop.total,processor.blacklist.hits,processor.tracker.total,processor.tracker.down,output.drop.total,processor.esmtp.success,processor.esmtp.failed,dns.total,dns.miss,processor.websense.cache_count,processor.websense.hits,processor.websense.errors,processor.websense.found\n");
    fflush(config->perfmonitor_file_stream);

}
