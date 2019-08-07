
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

#ifdef HAVE_LIBFASTJSON

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "processors/client-stats.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _Client_Stats_Struct *Client_Stats;

void Client_Stats_Init( void )
{

    if (( config->client_stats_file_stream = fopen(config->client_stats_file_name, "a" )) == NULL )
        {
            Remove_Lock_File();
            Sagan_Log(ERROR, "[%s, line %d] Can't open %s - %s!", __FILE__, __LINE__, config->client_stats_file_name, strerror(errno));
        }

    config->client_stats_file_stream_status = true;

}

void Client_Stats_Close( void )
{

    config->client_stats_file_stream_status = false;
    fclose(config->client_stats_file_stream);

}


void Client_Stats_Handler( void )
{

    struct json_object *jobj = NULL;

    int i=0;

    (void)SetThreadName("SaganClientStats");

    /* Wait some time before dumping stats */

    sleep(config->client_stats_time);

    while(1)
        {

            jobj = json_object_new_object();

            json_object *jarray_ip = json_object_new_array();
            json_object *jarray_epoch = json_object_new_array();
            json_object *jarray_program = json_object_new_array();
	    json_object *jarray_message = json_object_new_array();


            json_object *jevent_type = json_object_new_string( "client_stats" );
            json_object_object_add(jobj,"event_type", jevent_type);

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

            json_object_object_add(jobj,"ip_addresses", jarray_ip);
            json_object_object_add(jobj,"timestamp", jarray_epoch);
            json_object_object_add(jobj,"program", jarray_program);
  	    json_object_object_add(jobj,"message", jarray_message);

            fprintf(config->client_stats_file_stream, "%s\n", json_object_to_json_string(jobj));
            fflush(config->client_stats_file_stream);

            json_object_put(jobj);
            sleep(config->client_stats_time);
        }


}

void Client_Stats_Add_Update_IP( char *ip, char *program, char *message )
{

    int i = 0;
    bool flag = false;
    uint32_t hash = Djb2_Hash( ip );

    time_t t;
    struct tm *now;
    uint32_t epoch = 0;
    char timet[20];

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);
    epoch = atol(timet);

    for ( i = 0; i < counters->client_stats_count; i++ )
        {

            if ( hash == Client_Stats[i].hash )
                {
                   Client_Stats[i].epoch = epoch;

		   /* DEBUG needs to be an interval, not every time */

		   strlcpy( Client_Stats[i].program, program, sizeof(Client_Stats[i].program) );
		   strlcpy( Client_Stats[i].message, message, sizeof(Client_Stats[i].message) );
		   
//		   printf("Got hit: %d, %d, %s\n", Client_Stats[i].hash, Client_Stats[i].epoch, Client_Stats[i].ip);
                    return;
                }

        }

    /* Allocate memory for new stats */

    Client_Stats = (_Client_Stats_Struct *) realloc(Client_Stats, (counters->client_stats_count+1) * sizeof(_Client_Stats_Struct));

    if ( Client_Stats == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for _Client_Stats. Abort!", __FILE__, __LINE__);
        }

    Client_Stats[counters->client_stats_count].hash = hash;
    Client_Stats[counters->client_stats_count].epoch = epoch;

    strlcpy( Client_Stats[counters->client_stats_count].program, program, sizeof(Client_Stats[counters->client_stats_count].program ) );

    strlcpy( Client_Stats[counters->client_stats_count].message, message, sizeof(Client_Stats[counters->client_stats_count].message ) );

    strlcpy(Client_Stats[counters->client_stats_count].ip, ip, sizeof(Client_Stats[counters->client_stats_count].ip));

    __atomic_add_fetch(&counters->client_stats_count, 1, __ATOMIC_SEQ_CST);

//printf("In add! %s, %d, %d\n", ip, hash, epoch);


}

#endif
