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

/* sagan-peek.c
 *
 * This small utility "peeks" into Sagan memory to display thresholds,
 * afters, xbits, flexbits, etc.  The term "peek" goes back to old BASIC "peek"
 * in memory.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>

#include "../src/sagan.h"
#include "../src/sagan-defs.h"
#include "../src/flexbit-mmap.h"
#include "../src/xbit-mmap.h"
#include "../src/util-time.h"

#include "../src/processors/track-clients.h"

#define ALL_TYPES 0
#define THRESHOLD_TYPE 1
#define AFTER_TYPE 2
#define FLEXBIT_TYPE 3
#define TRACK_TYPE 4
#define XBIT_TYPE 5

/* Linking with ../util.o pulls in dependencies on these globals. Provide them here,
 * even though they do not appear to be used by any code that is executed in this program. */
#include "../src/sagan-config.h"
struct _SaganConfig config;
struct _SaganCounters counters;


/****************************************************************************
 * usage - Give the user some hints about how to use this utility!
 ****************************************************************************/

void Usage( void )
{

    fprintf(stderr, "\n--[ saganpeek help ]---------------------------------------------------------\n\n");
    fprintf(stderr, "-t, --type\tthreshold, after, flexbit, track, all (default: all)\n");
    fprintf(stderr, "-h, --help\tThis screen.\n");
    fprintf(stderr, "-i, --ipc\tIPC source directory. (default: %s)\n", IPC_DIRECTORY);
    fprintf(stderr, "-a, --all\tShow active/inactive data (default shows only active)\n\n");

}

/****************************************************************************
 * object_check - Verifies a memory object exists before doing an open.
 * This way,  we don't mistakingly "create" the object!
 ****************************************************************************/

int object_check( char *object )
{

    struct stat object_check;

    if ( ( stat(object, &object_check) == -1 ))
        {
            return(false);
        }

    return(true);
}

/****************************************************************************
 * u32_time_to_human - Convert epoch time to human readable
 ****************************************************************************/

/* DEBUG - this is like in util-time.c */

char *u32_time_to_human( uint64_t utime )
{

    struct tm tm;
    static char time_buf[80];
    char tmp[80];

    char *return_time = NULL;

    memset(&tm, 0, sizeof(struct tm));
    snprintf(tmp, sizeof(tmp) - 1, "%" PRIu64 "", utime);

    strptime(tmp, "%s", &tm);
    strftime(time_buf, sizeof(time_buf), "%b %d %H:%M:%S %Y", &tm);

    return_time = (char*)&time_buf;

    return(return_time);

}

/****************************************************************************
 * main - Pull data from shared memory and display it!
 ****************************************************************************/

int main(int argc, char **argv)
{

    const struct option long_options[] =
    {
        { "help",         no_argument,          NULL,   'h' },
        { "ipc", 	  required_argument, 	NULL,	'i' },
        { "type", 	  required_argument, 	NULL,	't' },
        { "all", 	  no_argument, 	  	NULL,   'a' },
        {0, 0, 0, 0}
    };

    static const char *short_options =
        "i:t:ha";

    int option_index = 0;

    struct _Sagan_IPC_Counters *counters_ipc;
    struct _Sagan_IPC_Flexbit *flexbit_ipc;
    struct _Sagan_IPC_Xbit *xbit_ipc;
    struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;
    struct _After2_IPC *After2_IPC;
    struct _Threshold2_IPC *Threshold2_IPC;

    signed char c;

    time_t t;
    struct tm *now;
    char  timet[20];

    uint64_t current_time;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    current_time = atoi(timet);

    uint64_t thresh_oldtime;
    uint64_t after_oldtime;
    uint64_t flexbit_oldtime;

    /* For convert to IP string */

    char ip_src[MAXIP] = { 0 };
    char time_buf[80] = { 0 };

    /* Shared memory descriptors */

    int shm_counters;
    int shm;

    int i;

    bool typeflag = 0;
    unsigned char type = ALL_TYPES;
    bool all_flag = false;
    bool err = false;

    char tmp_object_check[255];

    char *ipc_directory = IPC_DIRECTORY;

    /* Get command line arg's */

    while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {

            switch(c)
                {

                    if ( c == -1 ) break;

                case 'h':
                    Usage();
                    exit(0);
                    break;

                case 'i':
                    ipc_directory = optarg;
                    break;

                case 'a':
                    all_flag = true;
                    break;

                case 't':

                    if (!strcmp(optarg, "threshold"))
                        {
                            type = THRESHOLD_TYPE;
                            typeflag = true;
                        }

                    else if (!strcmp(optarg, "after"))
                        {
                            type = AFTER_TYPE;
                            typeflag = true;
                        }

                    else if (!strcmp(optarg, "flexbit"))
                        {
                            type = FLEXBIT_TYPE;
                            typeflag = true;
                        }

                    else if (!strcmp(optarg, "xbit"))
                        {
                            type = XBIT_TYPE;
                            typeflag = true;
                        }

                    else if (!strcmp(optarg, "track"))
                        {
                            type = TRACK_TYPE;
                            typeflag = true;
                        }


                    if ( typeflag == false )
                        {
                            printf("Unknown option '%s'\n", optarg);
                            exit(1);
                        }

                    break;

                default:
                    fprintf(stderr, "Invalid argument!\n");
                    Usage();
                    exit(0);
                    break;

                }

        }


    /* Load the "counters" first.  The "counters" keep track of the number of elements on the
     * other arrays */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, COUNTERS_IPC_FILE);

    if ( object_check(tmp_object_check) == false )
        {
            fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
            Usage();
            exit(1);
        }

    if ( ( shm_counters = open(tmp_object_check, O_RDONLY ) ) == -1 )

        {
            fprintf(stderr, "[%s, line %d] Cannot open() for counters (%s)\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    if (( counters_ipc = mmap(0, sizeof(_Sagan_IPC_Counters) , PROT_READ, MAP_SHARED, shm_counters, 0)) == MAP_FAILED )

        {
            fprintf(stderr, "[%s, line %d] Error allocating memory for counters object! [%s]\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    close(shm_counters);

    /*** Get "Threshold" data ***/

    if ( type == ALL_TYPES || type == THRESHOLD_TYPE )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESHOLD2_IPC_FILE);

            if ( object_check(tmp_object_check) == false )
                {
                    fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
                    Usage();
                    exit(1);
                }

            if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
                {
                    fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            if (( Threshold2_IPC = mmap(0, sizeof(_Threshold2_IPC) + (sizeof(_Threshold2_IPC) * counters_ipc->thresh2_count ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                {
                    fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            close(shm);

            if ( counters_ipc->thresh2_count >= 1 )
                {


                    for ( i = 0; i < counters_ipc->thresh2_count; i++)
                        {

                            thresh_oldtime = current_time - Threshold2_IPC[i].utime;

                            /* Show only active threshold unless told otherwise */

                            if ( ( thresh_oldtime < Threshold2_IPC[i].expire &&
                                    Threshold2_IPC[i].count > Threshold2_IPC[i].target_count ) ||
                                    all_flag == true )
                                {

                                    u32_Time_To_Human(Threshold2_IPC[i].utime, time_buf, sizeof(time_buf));

                                    printf("Type: Threshold [%d].\n", i);

                                    printf("Tracking hash: %u\n", Threshold2_IPC[i].hash);

                                    printf("Tracking by:");

                                    if ( Threshold2_IPC[i].threshold2_method_src == true )
                                        {
                                            printf(" by_src");
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_dst == true )
                                        {
                                            printf(" by_dst");
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_username == true )
                                        {
                                            printf(" by_username");
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_srcport == true )
                                        {
                                            printf(" by_srcport");
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_dstport == true )
                                        {
                                            printf(" by_dstport");
                                        }

                                    printf("\n");

                                    if ( Threshold2_IPC[i].threshold2_method_src == true )
                                        {
                                            printf("IP SRC: %s\n", Threshold2_IPC[i].ip_src);
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_srcport == true )
                                        {
                                            printf("SRC Port: %d\n", Threshold2_IPC[i].src_port);
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_dst == true )
                                        {
                                            printf("IP DST: %s\n", Threshold2_IPC[i].ip_dst);
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_dstport == true )
                                        {
                                            printf("DST Port: %d\n", Threshold2_IPC[i].dst_port);
                                        }

                                    if ( Threshold2_IPC[i].threshold2_method_username == true )
                                        {
                                            printf("Username: %s\n",  Threshold2_IPC[i].username);
                                        }


                                    printf("Signature: \"%s\" (%" PRIu64 ")\n", Threshold2_IPC[i].signature_msg, Threshold2_IPC[i].sid);
                                    printf("Syslog Message: \"%s\"\n", Threshold2_IPC[i].syslog_message);
                                    printf("Date added/modified: %s\n", time_buf);
                                    printf("Target Count: %" PRIu64 "\n", Threshold2_IPC[i].target_count);
                                    printf("Counter: %" PRIu64 "\n", Threshold2_IPC[i].count);
                                    printf("Time until expire: %" PRIi64 " seconds.\n", Threshold2_IPC[i].expire - thresh_oldtime);
                                    printf("Expire Time: %d seconds.\n\n", Threshold2_IPC[i].expire);

                                }

                        }
                }
        }


    /*** Get "After" data ***/

    if ( type == ALL_TYPES || type == AFTER_TYPE )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER2_IPC_FILE);


            if ( object_check(tmp_object_check) == false )
                {
                    fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
                    Usage();
                    exit(1);
                }

            if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
                {
                    fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            if (( After2_IPC = mmap(0, sizeof(_After2_IPC) + (sizeof(_After2_IPC) * counters_ipc->after2_count ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                {
                    fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            close(shm);

            if ( counters_ipc->after2_count >= 1 )
                {

                    for ( i = 0; i < counters_ipc->after2_count; i++)
                        {

                            after_oldtime = current_time - After2_IPC[i].utime;

                            /* Show only active after unless told otherwise */

                            if ( ( after_oldtime < After2_IPC[i].expire &&
                                    After2_IPC[i].count > After2_IPC[i].target_count ) ||
                                    all_flag == true )
                                {

                                    printf("Type: After [%d].\n", i);

                                    u32_Time_To_Human(After2_IPC[i].utime, time_buf, sizeof(time_buf));

                                    printf("Tracking hash: %u\n", After2_IPC[i].hash);

                                    printf("Tracking by:");

                                    if ( After2_IPC[i].after2_method_src == true )
                                        {
                                            printf(" by_src");
                                        }

                                    if ( After2_IPC[i].after2_method_dst == true )
                                        {
                                            printf(" by_dst");
                                        }

                                    if ( After2_IPC[i].after2_method_username == true )
                                        {
                                            printf(" by_username");
                                        }

                                    if ( After2_IPC[i].after2_method_srcport == true )
                                        {
                                            printf(" by_username");
                                        }

                                    if ( After2_IPC[i].after2_method_dstport == true )
                                        {
                                            printf(" by_username");
                                        }

                                    printf("\n");

                                    if ( After2_IPC[i].after2_method_src == true )
                                        {
                                            printf("IP SRC: %s\n", After2_IPC[i].ip_src);
                                        }

                                    if ( After2_IPC[i].after2_method_srcport == true )
                                        {
                                            printf("SRC Port: %d\n", After2_IPC[i].src_port);
                                        }

                                    if ( After2_IPC[i].after2_method_dst == true )
                                        {
                                            printf("IP DST: %s\n", After2_IPC[i].ip_dst);
                                        }

                                    if ( After2_IPC[i].after2_method_dstport == true )
                                        {
                                            printf("DST Port: %d\n", After2_IPC[i].dst_port);
                                        }

                                    if ( After2_IPC[i].after2_method_username == true )
                                        {
                                            printf("Username: %s\n",  After2_IPC[i].username);
                                        }


                                    printf("Signature: \"%s\" (Signature ID: %" PRIu64 " Revision: %d)\n", After2_IPC[i].signature_msg, After2_IPC[i].sid, After2_IPC[i].rev);
                                    printf("Syslog Message: \"%s\"\n", After2_IPC[i].syslog_message);
                                    printf("Date added/modified: %s\n", time_buf);
                                    printf("Counter: %" PRIu64 "\n", After2_IPC[i].count);

                                    printf("Time until expire: %" PRIi64 " seconds.\n", After2_IPC[i].expire - after_oldtime);
                                    printf("Expire Time: %d seconds.\n\n", After2_IPC[i].expire);

                                }

                        }
                }
        }

    /*** Get "flexbit" data ***/

    if ( type == ALL_TYPES || type == FLEXBIT_TYPE )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, FLEXBIT_IPC_FILE);

            if ( object_check(tmp_object_check) == false )
                {
                    fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
                    Usage();
                    exit(1);
                }

            if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
                {
                    fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            if (( flexbit_ipc = mmap(0, sizeof(_Sagan_IPC_Flexbit) + (sizeof(_Sagan_IPC_Flexbit) * counters_ipc->flexbit_count ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                {
                    fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            close(shm);


            if ( counters_ipc->flexbit_count >= 1 )
                {

                    for (i= 0; i < counters_ipc->flexbit_count; i++ )
                        {

                            if ( flexbit_ipc[i].flexbit_state == 1 || all_flag == true )
                                {

                                    u32_Time_To_Human(flexbit_ipc[i].flexbit_expire, time_buf, sizeof(time_buf));
                                    flexbit_oldtime = flexbit_ipc[i].flexbit_expire - current_time;

                                    printf("Type: flexbit [%d].\n", i);

                                    printf("Flexbit name: \"%s\"\n", flexbit_ipc[i].flexbit_name);
                                    printf("State: %s\n", flexbit_ipc[i].flexbit_state == 1 ? "ACTIVE" : "INACTIVE");
                                    printf("IP: %s:%d -> %s:%d\n", flexbit_ipc[i].ip_src, flexbit_ipc[i].src_port, flexbit_ipc[i].ip_dst, flexbit_ipc[i].dst_port);
                                    printf("Username: \"%s\"\n", flexbit_ipc[i].username);
                                    printf("Signature: \"%s\" (Signature ID: %" PRIu64 ")\n", flexbit_ipc[i].signature_msg, flexbit_ipc[i].sid);
                                    printf("Expire Time: %s (%d seconds)\n", time_buf, flexbit_ipc[i].expire);
                                    printf("Time until expire: %" PRIi64 " seconds.\n", flexbit_oldtime);
                                    printf("Syslog message: \"%s\"\n\n", flexbit_ipc[i].syslog_message );

                                }

                        }
                }
        }

    /*** Get "xbit" data ***/

    if ( type == ALL_TYPES || type == XBIT_TYPE )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, XBIT_IPC_FILE);


            if ( object_check(tmp_object_check) == false )
                {
                    fprintf(stderr, "Warning: Can't locate %s. This might be normal if using 'xbits' with Redis storage.\n", tmp_object_check);
                    err = true;
                }

	    /* If using "redis" for xbit storage, this mmap() file might not exsist.  In that
	     * case,  we just pass a warning - Champ Clark (2019/06/20) */

            if ( err == false )
                {

                    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
                        {
                            fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
                            exit(1);
                        }

                    if (( xbit_ipc = mmap(0, sizeof(_Sagan_IPC_Xbit) + (sizeof(_Sagan_IPC_Xbit) * counters_ipc->xbit_count ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                        {
                            fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                            exit(1);
                        }

                    close(shm);

                    if ( counters_ipc->xbit_count >= 1 )
                        {

                            for (i= 0; i < counters_ipc->xbit_count; i++ )
                                {

                                    u32_Time_To_Human(xbit_ipc[i].xbit_expire, time_buf, sizeof(time_buf));

                                    if ( all_flag == true || ( xbit_ipc[i].xbit_expire != 0 && xbit_ipc[i].xbit_expire <= current_time ) )
                                        {

                                            printf("Type: xbit [%d].\n", i);
                                            printf("Xbit name: \"%s\" (Hash name: %u)\n", xbit_ipc[i].xbit_name, xbit_ipc[i].xbit_name_hash);
                                            printf("State: ");

                                            if (  xbit_ipc[i].xbit_expire != 0 && xbit_ipc[i].xbit_expire <= current_time )
                                                {
                                                    printf("Active\n");
                                                }
                                            else
                                                {
                                                    printf("Inactive\n");
                                                }

                                            printf("IP Hash: %u\n", xbit_ipc[i].xbit_hash);
                                            printf("Signature: \"%s\" (Signature ID: %" PRIu64 ")\n", xbit_ipc[i].signature_msg, xbit_ipc[i].sid);
                                            printf("Expire Time: %d\n", xbit_ipc[i].expire);
                                            printf("Expired at: ");

                                            if ( xbit_ipc[i].xbit_expire == 0 )
                                                {
                                                    printf("[Unset]\n");
                                                }
                                            else
                                                {
                                                    printf("%s\n", time_buf);
                                                }

                                            printf("Syslog Message: \"%s\"\n\n", xbit_ipc[i].syslog_message );

                                        }

                                }
                        }
                }
        }

    /**** Get "Tracking" data (if enabled) ****/

    if ( type == ALL_TYPES || type == TRACK_TYPE )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, CLIENT_TRACK_IPC_FILE);

            if ( object_check(tmp_object_check) == true )
                {

                    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
                        {
                            fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
                            exit(1);
                        }

                    if (( SaganTrackClients_ipc = mmap(0, sizeof(_Sagan_Track_Clients_IPC) + (sizeof(_Sagan_Track_Clients_IPC) * counters_ipc->track_clients_client_count ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                        {
                            fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                            exit(1);
                        }

                    close(shm);


                    if ( counters_ipc->track_clients_client_count >= 1 )
                        {

                            for ( i = 0; i < counters_ipc->track_clients_client_count; i++)
                                {

                                    Bit2IP(SaganTrackClients_ipc[i].hostbits, ip_src, sizeof(SaganTrackClients_ipc[i].hostbits));
                                    u32_Time_To_Human(SaganTrackClients_ipc[i].utime, time_buf, sizeof(time_buf));

                                    printf("Type: Tracking. [%d]\n", i);
                                    printf("State: %s.\n", 0 == SaganTrackClients_ipc[i].status ? "ACTIVE" : "INACTIVE");
                                    printf("Source tracking: %s\n", ip_src);
                                    printf("Last seen: %s (%d/%d)\n\n", time_buf, SaganTrackClients_ipc[i].expire, SaganTrackClients_ipc[i].expire / 60);

                                }
                        }

                    close(shm);

                } /* object_check */
        }

    return(0);        /* Clean exit */

}


