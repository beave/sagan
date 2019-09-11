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

/* stats.c
 *
 * Simply dumps statistics of Sagan to the user or via sagan.log
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "stats.h"
#include "rules.h"
#include "sagan-config.h"

struct _SaganCounters *counters;
struct _Sagan_IPC_Counters *counters_ipc;
struct _Sagan_Ruleset_Track *Ruleset_Track;
struct _SaganConfig *config;

int proc_running; 	/* Count of executing threads */

void Statistics( void )
{

    char timet[20];

    time_t t;
    struct tm *now;
    int seconds = 0;
    unsigned long total=0;
    int i;
    bool flag;

    int uptime_days;
    int uptime_abovedays;
    int uptime_hours;
    int uptime_abovehours;
    int uptime_minutes;
    int uptime_seconds;

#ifdef WITH_BLUEDOT
    unsigned long bluedot_ip_total=0;
    unsigned long bluedot_hash_total=0;
    unsigned long bluedot_url_total=0;
    unsigned long bluedot_filename_total=0;
    unsigned long bluedot_ja3_total=0;
#endif


    /* This is used to calulate the events per/second */
    /* Champ Clark III - 11/17/2011 */

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);
    seconds = atol(timet) - atol(config->sagan_startutime);

    /* if statement prevents floating point exception */

    if ( seconds != 0 )
        {
            total = counters->events_received / seconds;

#ifdef WITH_BLUEDOT
            bluedot_ip_total = counters->bluedot_ip_total / seconds;
            bluedot_hash_total = counters->bluedot_hash_total / seconds;
            bluedot_url_total = counters->bluedot_url_total / seconds;
            bluedot_filename_total = counters->bluedot_filename_total / seconds;
#endif

        }


    if ((isatty(1)))
        {


            Sagan_Log(NORMAL, " ,-._,-.  -[ Sagan Version %s - Engine Statistics ]-", VERSION);
            Sagan_Log(NORMAL, " \\/)\"(\\/");
            Sagan_Log(NORMAL, "  (_o_)    Received/Processed/Ignored : %" PRIu64 "/%" PRIu64 "/%" PRIu64 " (%.3f%%/%.3f%%)", counters->events_received, counters->events_processed, counters->ignore_count, CalcPct(counters->events_processed, counters->events_received), CalcPct(counters->ignore_count, counters->events_received));
            Sagan_Log(NORMAL, "  /   \\/)  Signatures matched         : %" PRIu64 " (%.3f%%)", counters->saganfound, CalcPct(counters->saganfound, counters->events_received ) );
            Sagan_Log(NORMAL, " (|| ||)   Alerts                     : %" PRIu64 " (%.3f%%)",  counters->alert_total, CalcPct( counters->alert_total, counters->events_received) );
            Sagan_Log(NORMAL, "  oo-oo    After                      : %" PRIu64 " (%.3f%%)",  counters->after_total, CalcPct( counters->after_total, counters->events_received) );
            Sagan_Log(NORMAL, "           Threshold                  : %" PRIu64 " (%.3f%%)", counters->threshold_total, CalcPct( counters->threshold_total, counters->events_received) );
            Sagan_Log(NORMAL, "           Dropped                    : %" PRIu64 " (%.3f%%)", counters->sagan_processor_drop + counters->sagan_output_drop + counters->sagan_log_drop, CalcPct(counters->sagan_processor_drop + counters->sagan_output_drop + counters->sagan_log_drop, counters->events_received) );

//        Sagan_Log(NORMAL, "           Malformed                : h:%" PRIu64 "|f:%" PRIu64 "|p:%" PRIu64 "|l:%" PRIu64 "|T:%" PRIu64 "|d:%" PRIu64 "|T:%" PRIu64 "|P:%" PRIu64 "|M:%" PRIu64 "", counters->malformed_host, counters->malformed_facility, counters->malformed_priority, counters->malformed_level, counters->malformed_tag, counters->malformed_date, counters->malformed_time, counters->malformed_program, counters->malformed_message);

            Sagan_Log(NORMAL, "           Thread Exhaustion          : %" PRIu64 " (%.3f%%)", counters->worker_thread_exhaustion,  CalcPct( counters->worker_thread_exhaustion, counters->events_received) );

            Sagan_Log(NORMAL, "           Thread Usage               : %d/%d (%.3f%%)", proc_running, config->max_processor_threads, CalcPct( proc_running, config->max_processor_threads ));

            /*
                        if (config->sagan_droplist_flag)
                            {
                                Sagan_Log(NORMAL, "           Ignored Input            : %" PRIu64 " (%.3f%%)", counters->ignore_count, CalcPct(counters->ignore_count, counters->events_received) );
                            }*/

#ifdef HAVE_LIBFASTJSON
            if ( config->parse_json_program == true || config->parse_json_message == true )
                {
                    Sagan_Log(NORMAL, "           JSON Input                 : %" PRIu64 " (%.3f%%)", counters->json_input_count, CalcPct( counters->json_input_count, counters->events_received) );
                    Sagan_Log(NORMAL, "           JSON Program/Message       : %" PRIu64 " (%.3f%%)", counters->json_mp_count, CalcPct( counters->json_mp_count, counters->events_received) );

                }

#endif

#ifdef HAVE_LIBMAXMINDDB
            Sagan_Log(NORMAL, "           GeoIP Hits:                : %" PRIu64 " (%.3f%%)", counters->geoip2_hit, CalcPct( counters->geoip2_hit, counters->events_received) );
            Sagan_Log(NORMAL, "           GeoIP Lookups:             : %" PRIu64 "", counters->geoip2_lookup);
            Sagan_Log(NORMAL, "           GeoIP Errors               : %" PRIu64 "", counters->geoip2_error);
#

#endif

            uptime_days = seconds / 86400;
            uptime_abovedays = seconds % 86400;
            uptime_hours = uptime_abovedays / 3600;
            uptime_abovehours = uptime_abovedays % 3600;
            uptime_minutes = uptime_abovehours / 60;
            uptime_seconds = uptime_abovehours % 60;

            Sagan_Log(NORMAL, "           Uptime                     : %d days, %d hours, %d minutes, %d seconds.", uptime_days, uptime_hours, uptime_minutes, uptime_seconds);

            /* If processing from a file,  don't display events per/second */

            if ( config->sagan_is_file == 0 )
                {

                    if ( seconds < 60 || seconds == 0 )
                        {
                            Sagan_Log(NORMAL, "           Avg. events per/second     : %lu [%lu of 60 seconds. Calculating...]", total, seconds);
                        }
                    else
                        {
                            Sagan_Log(NORMAL, "           Avg. events per/second     : %lu", total);
                        }
                }
            else
                {

                    Sagan_Log(NORMAL, "           Avg. events per/second     : %lu", total);

                }

            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "          -[ Sagan Malformed Data Statistics ]-");
            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "           Host                       : %" PRIu64 " (%.3f%%)", counters->malformed_host, CalcPct(counters->malformed_host, counters->events_received) );
            Sagan_Log(NORMAL, "           Facility                   : %" PRIu64 " (%.3f%%)", counters->malformed_facility, CalcPct(counters->malformed_facility, counters->events_received) );
            Sagan_Log(NORMAL, "           Priority                   : %" PRIu64 " (%.3f%%)", counters->malformed_priority, CalcPct(counters->malformed_priority, counters->events_received) );
            Sagan_Log(NORMAL, "           Level                      : %" PRIu64 " (%.3f%%)", counters->malformed_level, CalcPct(counters->malformed_level, counters->events_received) );
            Sagan_Log(NORMAL, "           Tag                        : %" PRIu64 " (%.3f%%)", counters->malformed_tag, CalcPct(counters->malformed_tag, counters->events_received) );
            Sagan_Log(NORMAL, "           Date                       : %" PRIu64 " (%.3f%%)", counters->malformed_date, CalcPct(counters->malformed_date, counters->events_received) );
            Sagan_Log(NORMAL, "           Time                       : %" PRIu64 " (%.3f%%)", counters->malformed_time, CalcPct(counters->malformed_time, counters->events_received) );
            Sagan_Log(NORMAL, "           Program                    : %" PRIu64 " (%.3f%%)", counters->malformed_program, CalcPct(counters->malformed_program, counters->events_received) );
            Sagan_Log(NORMAL, "           Message                    : %" PRIu64 " (%.3f%%)", counters->malformed_message, CalcPct(counters->malformed_message, counters->events_received) );

#ifdef HAVE_LIBFASTJSON

            if ( config->parse_json_program == true || config->parse_json_message == true )
                {
                    Sagan_Log(NORMAL, "           JSON Input                 : %" PRIu64 " (%.3f%%)", counters->malformed_json_input_count, CalcPct(counters->malformed_json_input_count, counters->events_received) );
                    Sagan_Log(NORMAL, "           JSON Program/Messages      : %" PRIu64 " (%.3f%%)", counters->malformed_json_mp_count, CalcPct(counters->malformed_json_mp_count, counters->events_received) );

                }

#endif

            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "          -[ Sagan Processor Statistics ]-");
            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "           Dropped                    : %" PRIu64 " (%.3f%%)", counters->sagan_processor_drop, CalcPct(counters->sagan_processor_drop, counters->events_received) );

            if (config->blacklist_flag)
                {
                    Sagan_Log(NORMAL, "           Blacklist Lookups          : %" PRIu64 " (%.3f%%)", counters->blacklist_lookup_count, CalcPct(counters->blacklist_lookup_count, counters->events_received) );
                    Sagan_Log(NORMAL, "           Blacklist Hits             : %" PRIu64 " (%.3f%%)", counters->blacklist_hit_count, CalcPct(counters->blacklist_hit_count, counters->events_received) );

                }

            if (config->sagan_track_clients_flag)
                {
                    Sagan_Log(NORMAL, "           Tracking/Down              : %d / %d [%d minutes]", counters_ipc->track_clients_client_count, counters_ipc->track_clients_down, config->pp_sagan_track_clients);
                }


            if (config->output_thread_flag)
                {
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          -[ Sagan Output Plugin Statistics ]-");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL,"           Dropped                       : %" PRIu64 " (%.3f%%)", counters->sagan_output_drop, CalcPct(counters->sagan_output_drop, counters->events_received) );
                }

#ifdef HAVE_LIBESMTP
            if ( config->sagan_esmtp_flag )
                {
                    Sagan_Log(NORMAL, "           Email Success/Failed       : %" PRIu64 " / %" PRIu64 "", counters->esmtp_count_success, counters->esmtp_count_failed);
                }
#endif


            if (config->syslog_src_lookup)
                {
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          -[ Sagan DNS Cache Statistics ]-");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "           Cached                     : %" PRIu64 "", counters->dns_cache_count);
                    Sagan_Log(NORMAL, "           Missed                     : %" PRIu64 " (%.3f%%)", counters->dns_miss_count, CalcPct(counters->dns_miss_count, counters->dns_cache_count));
                }

            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "          -[ Sagan follow_flow Statistics ]-");
            Sagan_Log(NORMAL, "");
            Sagan_Log(NORMAL, "           Total                      : %" PRIu64 "", counters->follow_flow_total);
            Sagan_Log(NORMAL, "           Dropped                    : %" PRIu64 " (%.3f%%)", counters->follow_flow_drop, CalcPct(counters->follow_flow_drop, counters->follow_flow_total));

#ifdef WITH_BLUEDOT

            if (config->bluedot_flag)
                {
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          -[ Sagan Bluedot Processor ]-");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          * IP Reputation *");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          IP addresses in cache           : %" PRIu64 " (%.3f%%)", counters->bluedot_ip_cache_count, CalcPct(counters->bluedot_ip_cache_count, config->bluedot_ip_max_cache));
                    Sagan_Log(NORMAL, "          IP hits from cache              : %" PRIu64 " (%.3f%%)", counters->bluedot_ip_cache_hit, CalcPct(counters->bluedot_ip_cache_hit, counters->bluedot_ip_cache_count));
                    Sagan_Log(NORMAL, "          IP/Bluedot hits in logs         : %" PRIu64 "", counters->bluedot_ip_positive_hit);
                    Sagan_Log(NORMAL, "          IP with date > mdate            : %" PRIu64 "", counters->bluedot_mdate);
                    Sagan_Log(NORMAL, "          IP with date > cdate            : %" PRIu64 "", counters->bluedot_cdate);
                    Sagan_Log(NORMAL, "          IP with date > mdate [cache]    : %" PRIu64 "", counters->bluedot_mdate_cache);
                    Sagan_Log(NORMAL, "          IP with date > cdate [cache]    : %" PRIu64 "", counters->bluedot_cdate_cache);
                    Sagan_Log(NORMAL, "          IP queries per/second           : %lu (%" PRIu64 "/%" PRIu64 ")", bluedot_ip_total, counters->bluedot_ip_queue_current, config->bluedot_ip_queue);

                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          * File Hash *");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          Hashes in cache                 : %" PRIu64 " (%.3f%%)", counters->bluedot_hash_cache_count, CalcPct(counters->bluedot_hash_cache_count, config->bluedot_hash_max_cache));
                    Sagan_Log(NORMAL, "          Hash hits from cache            : %" PRIu64 " (%.3f%%)", counters->bluedot_hash_cache_hit, CalcPct(counters->bluedot_hash_cache_hit, counters->bluedot_hash_cache_count));
                    Sagan_Log(NORMAL, "          Hash/Bluedot hits in logs       : %" PRIu64 "", counters->bluedot_hash_positive_hit);
                    Sagan_Log(NORMAL, "          Hash queries per/second         : %lu (%" PRIu64 "/%" PRIu64 ")", bluedot_hash_total, counters->bluedot_hash_queue_current, config->bluedot_hash_queue);

                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          * URL Reputation *");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          URLs in cache                   : %" PRIu64 " (%.3f%%)", counters->bluedot_url_cache_count, CalcPct(counters->bluedot_url_cache_count, config->bluedot_url_max_cache));
                    Sagan_Log(NORMAL, "          URL hits from cache             : %" PRIu64 " (%.3f%%)", counters->bluedot_url_cache_hit, CalcPct(counters->bluedot_url_cache_hit, counters->bluedot_url_cache_count));
                    Sagan_Log(NORMAL, "          URL/Bluedot hits in logs        : %" PRIu64 "", counters->bluedot_url_positive_hit);
                    Sagan_Log(NORMAL, "          URL queries per/second          : %lu (%" PRIu64 "/%" PRIu64 ")", bluedot_url_total, counters->bluedot_url_queue_current, config->bluedot_url_queue);

                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          * Filename Reputation *");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          Filenames in cache              : %" PRIu64 " (%.3f%%)", counters->bluedot_filename_cache_count, CalcPct(counters->bluedot_filename_cache_count, config->bluedot_filename_max_cache));
                    Sagan_Log(NORMAL, "          Filename hits from cache        : %" PRIu64 " (%.3f%%)", counters->bluedot_filename_cache_hit, CalcPct(counters->bluedot_filename_cache_hit, counters->bluedot_filename_cache_count));
                    Sagan_Log(NORMAL, "          Filename/Bluedot hits in logs   : %" PRIu64 "", counters->bluedot_filename_positive_hit);
                    Sagan_Log(NORMAL, "          URL queries per/second          : %lu (%" PRIu64 "/%" PRIu64 ")", bluedot_filename_total, counters->bluedot_filename_queue_current, config->bluedot_filename_queue);
		    Sagan_Log(NORMAL, "");

                    Sagan_Log(NORMAL, "          * TLS/JA3 Reputation *");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          JA3 in cache                    : %" PRIu64 " (%.3f%%)", counters->bluedot_ja3_cache_count, CalcPct(counters->bluedot_ja3_cache_count, config->bluedot_ja3_max_cache));
                    Sagan_Log(NORMAL, "          JA3 hits from cache             : %" PRIu64 " (%.3f%%)", counters->bluedot_ja3_cache_hit, CalcPct(counters->bluedot_ja3_cache_hit, counters->bluedot_ja3_cache_count));
                    Sagan_Log(NORMAL, "          JA3/Bluedot hits in logs        : %" PRIu64 "", counters->bluedot_ja3_positive_hit);
                    Sagan_Log(NORMAL, "          JA3 queries per/second          : %lu (%" PRIu64 "/%" PRIu64 ")", bluedot_ja3_total, counters->bluedot_ja3_queue_current, config->bluedot_ja3_queue);

                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          * Bluedot Combined Statistics *");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          Lookup error count              : %" PRIu64 "", counters->bluedot_error_count);
                    Sagan_Log(NORMAL, "          Total query rate/per second     : %lu", bluedot_ip_total + bluedot_hash_total + bluedot_url_total + bluedot_filename_total);


                }
#endif


            if ( config->rule_tracking_console == true )
                {

                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          -[ Rule statistics ]-");
                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          * Fired rules *");
                    Sagan_Log(NORMAL, "");

                    flag = false;

                    for ( i = 0; i < counters->ruleset_track_count; i++ )
                        {

                            if ( Ruleset_Track[i].trigger == true )
                                {
                                    Sagan_Log(NORMAL, "          %s",  Ruleset_Track[i].ruleset );
                                    flag = true;
                                }

                        }

                    if ( flag == false )
                        {
                            Sagan_Log(NORMAL, "          [No rules fired]");
                        }

                    flag = false;

                    Sagan_Log(NORMAL, "");
                    Sagan_Log(NORMAL, "          * Non-Fired rules * ");
                    Sagan_Log(NORMAL, "");


                    for ( i = 0; i < counters->ruleset_track_count; i++ )
                        {
                            if ( Ruleset_Track[i].trigger == false )
                                {
                                    Sagan_Log(NORMAL, "          %s",  Ruleset_Track[i].ruleset );
                                    flag = true;
                                }
                        }

                    if ( flag == false )
                        {
                            Sagan_Log(NORMAL, "          [All rules fired]");
                        }
                }


            Sagan_Log(NORMAL, "-------------------------------------------------------------------------------");


        }
}
