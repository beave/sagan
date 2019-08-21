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

/* client-stats.c
 *
 * This writes out data about clients reporting to Sagan.  In particular,  the last
 * time a client send Sagan data along with a copy of "example" data (program/
 * message) every so often (via the "data-interval" option).
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
#include <pthread.h>
#include <stdlib.h>


#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#ifdef HAVE_LIBFASTJSON

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "lockfile.h"

#include "processors/client-stats.h"

uint64_t old_epoch = 0;

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _SaganDebug *debug;

struct _Client_Stats_Struct *Client_Stats = NULL;

pthread_mutex_t ClientStatsMutex=PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************
 * Client_Stats_Iint
 ****************************************************************************/

void Client_Stats_Init( void )
{

    if (( config->client_stats_file_stream = fopen(config->client_stats_file_name, "a" )) == NULL )
        {
            Remove_Lock_File();
            Sagan_Log(ERROR, "[%s, line %d] Can't open %s - %s!", __FILE__, __LINE__, config->client_stats_file_name, strerror(errno));
        }

    config->client_stats_file_stream_status = true;
    counters->client_stats_count = 0;

    Client_Stats = malloc(config->client_stats_max * sizeof(struct _Client_Stats_Struct));

    if ( Client_Stats == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _Client_Stats_Struct. Abort!", __FILE__, __LINE__);
        }

    memset(Client_Stats, 0, sizeof(struct _Client_Stats_Struct));

}

/****************************************************************************
 * Client_Stats_Close - Closes clients stats files
 ****************************************************************************/

void Client_Stats_Close( void )
{

    config->client_stats_file_stream_status = false;
    fclose(config->client_stats_file_stream);

}

/****************************************************************************
 * Client_Stats_Handler - Thread that writes out client stat data
 ****************************************************************************/

void Client_Stats_Handler( void )
{

    struct json_object *jobj = NULL;

    struct timeval tp;
    char timebuf[64] = { 0 };


    int i=0;

    (void)SetThreadName("SaganClientStats");

    /* Wait some time before dumping stats */

    sleep(config->client_stats_time);

    while(1)
        {

            if ( debug->debugclient_stats )
                {
                    Sagan_Log(DEBUG,"[%s, line %d] Writing client stats %s.", __FILE__, __LINE__, config->client_stats_file_name );
                }


	    gettimeofday(&tp, 0);
	    CreateIsoTimeString(&tp, timebuf, sizeof(timebuf));

            jobj = json_object_new_object();

            json_object *jarray_ip = json_object_new_array();
            json_object *jarray_epoch = json_object_new_array();
            json_object *jarray_program = json_object_new_array();
            json_object *jarray_message = json_object_new_array();

            json_object *jdate = json_object_new_string(timebuf);
            json_object_object_add(jobj,"timestamp", jdate);

            json_object *jevent_type = json_object_new_string( "client_stats" );
            json_object_object_add(jobj,"event_type", jevent_type);

            /* Update any existing client stats */

            for ( i = 0; i < counters->client_stats_count; i++ )
                {

                    json_object *jstring_ip = json_object_new_string(Client_Stats[i].ip);
                    json_object_array_add(jarray_ip,jstring_ip);

                    json_object *jstring_epoch = json_object_new_int(Client_Stats[i].epoch);
                    json_object_array_add(jarray_epoch,jstring_epoch);

                    json_object *jstring_program = json_object_new_string(Client_Stats[i].program);
                    json_object_array_add(jarray_program,jstring_program);

                    json_object *jstring_message = json_object_new_string(Client_Stats[i].message);
                    json_object_array_add(jarray_message,jstring_message);

                }

            /* If there is no data,  don't bother writing */

            if ( counters->client_stats_count != 0 )
                {

                    json_object_object_add(jobj,"ip_addresses", jarray_ip);
                    json_object_object_add(jobj,"timestamp", jarray_epoch);
                    json_object_object_add(jobj,"program", jarray_program);
                    json_object_object_add(jobj,"message", jarray_message);

                    fprintf(config->client_stats_file_stream, "%s\n", json_object_to_json_string(jobj));
                    fflush(config->client_stats_file_stream);

                }

            json_object_put(jobj);
            sleep(config->client_stats_time);
        }


}

/****************************************************************************
 * Client_Stats_Add_Update_IP - Adds IP addresses and other data to the
 * array of systems Sagan is keeping track of.
 ****************************************************************************/

void Client_Stats_Add_Update_IP( char *ip, char *program, char *message )
{

    uint32_t hash = Djb2_Hash( ip );

    int i = 0;
    time_t t;
    struct tm *now;
    uint64_t epoch = 0;
    char timet[20];

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);
    epoch = atol(timet);


    for ( i = 0; i < counters->client_stats_count; i++ )
        {

            /* Search here */

            if ( Client_Stats[i].hash == hash )
                {
                    Client_Stats[i].epoch = epoch;

                    if ( Client_Stats[i].epoch > Client_Stats[i].old_epoch + config->client_stats_interval)
                        {


                            if ( debug->debugclient_stats )
                                {
                                    Sagan_Log(DEBUG,"[%s, line %d] Updating program/message data for IP address %s [%d]", __FILE__, __LINE__, ip, i);
                                }

                            pthread_mutex_lock(&ClientStatsMutex);

                            strlcpy( Client_Stats[i].program, program, sizeof(Client_Stats[i].program) );
                            strlcpy( Client_Stats[i].message, message, sizeof(Client_Stats[i].message) );

                            Client_Stats[i].old_epoch = epoch;

                            pthread_mutex_unlock(&ClientStatsMutex);

                        }

                    return;

                }

        }

    if ( counters->client_stats_count < config->client_stats_max )
        {

            pthread_mutex_lock(&ClientStatsMutex);

            if ( debug->debugclient_stats )
                {
                    Sagan_Log(DEBUG,"[%s, line %d] Adding client IP address %s [%d]", __FILE__, __LINE__, ip, counters->client_stats_count);
                }


            Client_Stats[counters->client_stats_count].hash = hash;
            Client_Stats[counters->client_stats_count].epoch = epoch;
            Client_Stats[counters->client_stats_count].old_epoch = epoch;

            strlcpy(Client_Stats[counters->client_stats_count].ip, ip, sizeof(Client_Stats[counters->client_stats_count].ip));
            strlcpy( Client_Stats[counters->client_stats_count].program, program, sizeof(Client_Stats[counters->client_stats_count].program ) );
            strlcpy( Client_Stats[counters->client_stats_count].message, message, sizeof(Client_Stats[counters->client_stats_count].message ) );

            counters->client_stats_count++;

            pthread_mutex_unlock(&ClientStatsMutex);

        }
    else

        {

            Sagan_Log(WARN, "[%s, line %d] 'clients-stats' processors ran out of space.  Consider increasing 'max-clients'!", __FILE__, __LINE__);


        }

}

#endif
