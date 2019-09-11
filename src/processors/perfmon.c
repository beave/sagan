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

/* perfmon.c
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

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "lockfile.h"

#include "processors/perfmon.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _Sagan_IPC_Counters *counters_ipc;


/*****************************************************************************
 * Sagan_Perfmonitor_Handler - This becomes the thread to write out
 * preformance monitoring data.
 *****************************************************************************/

void Sagan_Perfmonitor_Handler( void )
{

    (void)SetThreadName("SaganPerfmon");

    unsigned long total=0;
    unsigned long seconds=0;

    char curtime_utime[64] = { 0 };
    time_t t;
    struct tm *now;

    t = time(NULL);
    now=localtime(&t);
    strftime(curtime_utime, sizeof(curtime_utime), "%s",  now);

    uint64_t last_events_received = 0;
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

#ifdef WITH_BLUEDOT
    uint64_t last_bluedot_ip_cache_hit = 0;
    uint64_t last_bluedot_ip_positive_hit = 0;
    uint64_t last_bluedot_hash_cache_hit = 0;
    uint64_t last_bluedot_hash_positive_hit = 0;
    uint64_t last_bluedot_url_cache_hit = 0;
    uint64_t last_bluedot_url_positive_hit = 0;
    uint64_t last_bluedot_filename_cache_hit = 0;
    uint64_t last_bluedot_filename_positive_hit = 0;
    uint64_t last_bluedot_error_count = 0;

    unsigned long bluedot_ip_total;
    unsigned long bluedot_url_total;
    unsigned long bluedot_hash_total;
    unsigned long bluedot_filename_total;
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

            t = time(NULL);
            now=localtime(&t);
            strftime(curtime_utime, sizeof(curtime_utime), "%s",  now);
            seconds = atol(curtime_utime) - atol(config->sagan_startutime);


            if ( config->perfmonitor_flag )
                {

                    fprintf(config->perfmonitor_file_stream, "%s,", curtime_utime),

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->events_received - last_events_received);
                    last_events_received = counters->events_received;

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

                    total = counters->events_received / seconds;
                    fprintf(config->perfmonitor_file_stream, "%lu,", total);

#ifdef HAVE_LIBMAXMINDDB

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->geoip2_lookup - last_geoip2_lookup);
                    last_geoip2_lookup = counters->geoip2_lookup;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->geoip2_hit - last_geoip2_hit);
                    last_geoip2_hit = counters->geoip2_hit;

                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", 0);
                    //last_geoip2_miss = counters->geoip2_miss;

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

//                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters_ipc->track_clients_client_count);
//                    fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters_ipc->track_clients_down);

                    fprintf(config->perfmonitor_file_stream, "%d,", counters_ipc->track_clients_client_count);
                    fprintf(config->perfmonitor_file_stream, "%d,", counters_ipc->track_clients_down);

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



#ifdef WITH_BLUEDOT

                    if ( config->bluedot_flag )
                        {

                            /* IP Reputation */

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_ip_cache_count);

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_ip_cache_hit - last_bluedot_ip_cache_hit);
                            last_bluedot_ip_cache_hit = counters->bluedot_ip_cache_count;

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_ip_positive_hit - last_bluedot_ip_positive_hit);
                            last_bluedot_ip_positive_hit = counters->bluedot_ip_positive_hit;

                            bluedot_ip_total = counters->bluedot_ip_total / seconds;
                            fprintf(config->perfmonitor_file_stream, "%lu,", bluedot_ip_total);

                            /* Hash */

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_hash_cache_count);

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_hash_cache_hit - last_bluedot_hash_cache_hit);
                            last_bluedot_ip_cache_hit = counters->bluedot_ip_cache_count;

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_hash_positive_hit - last_bluedot_hash_positive_hit);
                            last_bluedot_hash_positive_hit = counters->bluedot_hash_positive_hit;

                            bluedot_hash_total = counters->bluedot_hash_total / seconds;
                            fprintf(config->perfmonitor_file_stream, "%lu,", total);

                            /* URL */

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_url_cache_count);

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_url_cache_hit - last_bluedot_url_cache_hit);
                            last_bluedot_ip_cache_hit = counters->bluedot_ip_cache_count;

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_url_positive_hit - last_bluedot_url_positive_hit);
                            last_bluedot_url_positive_hit = counters->bluedot_url_positive_hit;

                            bluedot_url_total = counters->bluedot_url_total / seconds;
                            fprintf(config->perfmonitor_file_stream, "%lu,", bluedot_url_total);

                            /* Filename */

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_filename_cache_count);

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_filename_cache_hit - last_bluedot_filename_cache_hit);
                            last_bluedot_ip_cache_hit = counters->bluedot_ip_cache_count;

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_filename_positive_hit - last_bluedot_filename_positive_hit);
                            last_bluedot_filename_positive_hit = counters->bluedot_filename_positive_hit;

                            bluedot_filename_total = counters->bluedot_filename_total / seconds;
                            fprintf(config->perfmonitor_file_stream, "%lu,", bluedot_filename_total);		/* Last comma here! */

                            /* Error count */

                            fprintf(config->perfmonitor_file_stream, "%" PRIu64 ",", counters->bluedot_error_count - last_bluedot_error_count);
                            last_bluedot_error_count = counters->bluedot_error_count;

                            fprintf(config->perfmonitor_file_stream, "%lu", bluedot_ip_total + bluedot_hash_total + bluedot_url_total + bluedot_filename_total);


                        }
                    else
                        {

                            fprintf(config->perfmonitor_file_stream, "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
                        }

#endif

#ifndef WITH_BLUEDOT

                    fprintf(config->perfmonitor_file_stream, "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
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
            Sagan_Log(ERROR, "[%s, line %d] Can't open %s - %s!", __FILE__, __LINE__, config->perfmonitor_file_name, strerror(errno));
        }

    config->perfmonitor_file_stream_status = true;

    fprintf(config->perfmonitor_file_stream, "################################ Perfmon start: pid=%d at=%s ###################################\n", getpid(), curtime);
    fprintf(config->perfmonitor_file_stream, "# engine.utime,engine.total,engine.sig_match.total,engine.alerts.total,engine.after.total,engine.threshold.total, engine.drop.total,engine.ignored.total,engine.eps,geoip2.lookup.total,geoip2.hits,geoip2.misses,processor.drop.total,processor.blacklist.hits,processor.tracker.total,processor.tracker.down,output.drop.total,processor.esmtp.success,processor.esmtp.failed,dns.total,dns.miss,processor.bluedot_ip_cache_count,processor.bluedot_ip_cache_hit,processor.bluedot_ip_positive_hit,processor.bluedot_ip_qps,processor.bluedot_hash_cache_count,processor.bluedot_hash_cache_hit,processor.bluedot_hash_positive_hit,processor.bluedot_hash_qps,processor.bluedot_url_cache_count,processor.bluedot_url_cache_hit,processor.bluedot_url_positive_hit,processor.bluedot_url_qps,processor.bluedot_filename_cache_count,processor.bluedot_filename_cache_hit,processor.bluedot_filename_positive_hit,processor.bluedot_filename_qps,processor.bluedot_error_count,processor.bluedot_total_qps\n");
    fflush(config->perfmonitor_file_stream);

}
