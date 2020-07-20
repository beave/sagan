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

/* stats-json.c - write statistics about Sagan in a JSON format */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <json.h>


#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif


#include "version.h"

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "processors/stats-json.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _Sagan_IPC_Counters *counters_ipc;

void Stats_JSON_Init( void )
{

    if (( config->stats_json_file_stream = fopen(config->stats_json_filename, "a" )) == NULL )
        {
            Remove_Lock_File();
            Sagan_Log(ERROR, "[%s, line %d] Can't open %s - %s!", __FILE__, __LINE__, config->stats_json_filename, strerror(errno));
        }

    config->stats_json_file_stream_status = true;

}


void Stats_JSON_Close( void )
{

    fclose(config->stats_json_file_stream);
    config->stats_json_file_stream_status = false;

}

void Stats_JSON_Handler( void )
{

    (void)SetThreadName("SaganStatsJSON");

    time_t t;
    struct tm *now;

    char  timebuf[64] = { 0 };
    char  current_utime[64] = { 0 };

    uint64_t uptime_seconds;

    bool check = true;

    uint64_t last_events_received;
    uint64_t last_drop;
    uint64_t last_ignore;
    uint64_t last_threshold;
    uint64_t last_after;
    uint64_t last_alert;
    uint64_t last_match;

    uint64_t last_geoip_lookups;
    uint64_t last_geoip_hits;

    uint64_t last_blacklist_lookups;
    uint64_t last_blacklist_hits;

    uint64_t last_esmtp_success;
    uint64_t last_esmtp_failed;

    uint64_t last_dns_cached;
    uint64_t last_dns_missed;

    uint64_t last_flow_total;
    uint64_t last_flow_drop;

    unsigned long eps;

    while(1)
        {

            t = time(NULL);
            now=localtime(&t);
            strftime(current_utime, sizeof(current_utime), "%s",  now);
            uptime_seconds = atol(current_utime) - atol(config->sagan_startutime);

            CreateIsoTimeString(&t, timebuf, sizeof(timebuf));

            struct json_object *jobj;
            struct json_object *jobj_stats;
            struct json_object *jobj_captured;
            struct json_object *jobj_geoip;
            struct json_object *jobj_blacklist;
            struct json_object *jobj_smtp;
            struct json_object *jobj_dns;
            struct json_object *jobj_flow;
            struct json_object *jobj_bluedot;


            jobj = json_object_new_object();
            jobj_stats = json_object_new_object();
            jobj_captured = json_object_new_object();
            jobj_geoip = json_object_new_object();
            jobj_blacklist = json_object_new_object();
            jobj_smtp = json_object_new_object();
            jobj_dns = json_object_new_object();
            jobj_flow = json_object_new_object();
            jobj_bluedot = json_object_new_object();


            /* Top level */


            json_object *jdate = json_object_new_string(timebuf);
            json_object_object_add(jobj,"timestamp", jdate);

            json_object *jtype = json_object_new_string("stats");
            json_object_object_add(jobj,"event_type", jtype);

            json_object *jsource = json_object_new_string("sagan");
            json_object_object_add(jobj,"event_source", jsource);

            /* stats */

            json_object *juptime = json_object_new_int64(uptime_seconds);
            json_object_object_add(jobj_stats,"uptime", juptime);

            /* captured */

            json_object *jtotal = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->events_received - last_events_received ) : ( counters->events_received ) );
            json_object_object_add(jobj_captured,"total", jtotal);
            last_events_received = counters->events_received;

            json_object *jdrop = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->sagan_processor_drop - last_drop ) : ( counters->sagan_processor_drop ) );
            json_object_object_add(jobj_captured,"drop", jdrop);
            last_drop = counters->sagan_processor_drop;

            json_object *jignore = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->ignore_count - last_ignore ) : ( counters->ignore_count ) );
            json_object_object_add(jobj_captured,"ignore", jignore);
            last_ignore = counters->ignore_count;

            json_object *jthreshold = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->threshold_total - last_threshold ) : ( counters->threshold_total ) );
            json_object_object_add(jobj_captured,"threshold", jthreshold);
            last_threshold = counters->threshold_total;

            json_object *jafter = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->after_total - last_after ) : ( counters->after_total ) );
            json_object_object_add(jobj_captured,"after", jafter);
            last_after = counters->after_total;

            json_object *jalert = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->alert_total - last_alert ) : ( counters->alert_total ) );
            json_object_object_add(jobj_captured,"alert", jalert);
            last_alert = counters->alert_total;

            json_object *jmatch = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->saganfound - last_match ) : ( counters->saganfound ) );
            json_object_object_add(jobj_captured,"match", jmatch);
            last_match = counters->saganfound;

            /* prevent floating point exceptions */

            if ( uptime_seconds != 0 && counters->events_received != 0 )
                {
                    eps = counters->events_received / uptime_seconds;
                }

            json_object *jeps = json_object_new_int( eps );
            json_object_object_add(jobj_captured,"eps", jeps);

            /* GeoIP */

#ifdef HAVE_LIBMAXMINDDB

            if ( config->have_geoip2 == true )
                {

                    json_object *jgeoip_lookups = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->geoip2_lookup - last_geoip_lookups ) : ( counters->geoip2_lookup ) );
                    json_object_object_add(jobj_geoip,"lookups", jgeoip_lookups);
                    last_geoip_lookups = counters->geoip2_lookup;

                    json_object *jgeoip_hits = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->geoip2_hit - last_geoip_hits ) : ( counters->geoip2_hit ) );
                    json_object_object_add(jobj_geoip,"hits", jgeoip_hits);
                    last_geoip_hits = counters->geoip2_hit;

                }

#endif

            /* Blacklist */

            if ( config->blacklist_flag )
                {

                    json_object *jblacklist_lookups = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->blacklist_lookup_count - last_blacklist_lookups ) : ( counters->blacklist_lookup_count ) );
                    json_object_object_add(jobj_blacklist,"lookups", jblacklist_lookups);
                    last_blacklist_lookups = counters->blacklist_lookup_count;

                    json_object *jblacklist_hits = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->blacklist_hit_count - last_blacklist_hits ) : ( counters->blacklist_hit_count ) );
                    json_object_object_add(jobj_blacklist,"hits", jblacklist_hits);
                    last_blacklist_hits = counters->blacklist_hit_count;

                }

            /* SMTP */

#ifdef HAVE_LIBESMTP

            if( config->sagan_esmtp_flag == true )
                {

                    json_object *jsmtp_success = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->esmtp_count_success - last_esmtp_success ) : ( counters->esmtp_count_success ) );
                    json_object_object_add(jobj_smtp,"success", jsmtp_success);
                    last_esmtp_success = counters->esmtp_count_success;

                    json_object *jsmtp_failed = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->esmtp_count_failed - last_esmtp_failed ) : ( counters->esmtp_count_failed ) );
                    json_object_object_add(jobj_smtp,"failed", jsmtp_failed);
                    last_esmtp_failed = counters->esmtp_count_failed;

                }

#endif

            /* DNS */

            if ( config->syslog_src_lookup == true )
                {

                    json_object *jdns_cached = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->dns_cache_count - last_dns_cached ) : ( counters->dns_cache_count  ) );
                    json_object_object_add(jobj_dns,"cached", jdns_cached);
                    last_dns_cached = counters->dns_cache_count;

                    json_object *jdns_missed = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->dns_miss_count - last_dns_missed ) : ( counters->dns_miss_count  ) );
                    json_object_object_add(jobj_dns,"missed", jdns_missed);
                    last_dns_missed = counters->dns_miss_count;

                }

            /* Flow */

            json_object *jflow_total = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->follow_flow_total - last_flow_total) : ( counters->follow_flow_total ) );
            json_object_object_add(jobj_flow, "total", jflow_total);
            last_flow_total = counters->follow_flow_total;

            json_object *jflow_drop = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->follow_flow_drop - last_flow_drop) : ( counters->follow_flow_drop ) );
            json_object_object_add(jobj_flow, "dropped", jflow_drop);
            last_flow_drop = counters->follow_flow_drop;

            /* Bluedot */
            /*
                    json_object *jflow_total = json_object_new_int64( config->stats_json_sub_old_values == true ? ( counters->follow_flow_total - last_flow_total) : ( counters->follow_flow_total ) );
                    json_object_object_add(jobj_flow, "total", jflow_total);
                    last_flow_total = counters->follow_flow_total;
            */


            printf("%s\n", json_object_to_json_string(jobj));
            printf("  |---> stats: %s\n", json_object_to_json_string(jobj_stats));
            printf("             |---> captured: %s\n", json_object_to_json_string(jobj_captured));
            printf("	  |---> geoip: %s\n", json_object_to_json_string(jobj_geoip));
            printf("	  |---> blacklist: %s\n", json_object_to_json_string(jobj_blacklist));
            printf("          |---> smtp: %s\n", json_object_to_json_string(jobj_smtp));
            printf("	  |---> dns: %s\n", json_object_to_json_string(jobj_dns));
            printf("	  |---> flow: %s\n", json_object_to_json_string(jobj_flow));

            json_object_put(jobj);
            json_object_put(jobj_stats);
            json_object_put(jobj_captured);
            json_object_put(jobj_geoip);
            json_object_put(jobj_blacklist);
            json_object_put(jobj_smtp);
            json_object_put(jobj_dns);
            json_object_put(jobj_flow);





            sleep(1);

        }
}

#endif
