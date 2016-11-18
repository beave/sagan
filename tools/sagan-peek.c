/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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
 * afters, flowbis, etc.  The term "peek" goes back to old BASIC "peek"
 * and "poke" of memory.
 *
 */

/* DEBUG: need to add dstport, srcport for threshold/after */


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

#include "../src/sagan.h"
#include "../src/sagan-defs.h"
#include "../src/sagan-xbit.h"

#include "../src/processors/sagan-track-clients.h"

/****************************************************************************
 * usage - Give the user some hints about how to use this utility!
 ****************************************************************************/

void usage( void )
{

    fprintf(stderr, "\nsagan-peek [IPC directory]\n");

}

/****************************************************************************
 * object_check - Verifies a memory object exists before doing an open.
 * This way,  we don't mistakingly "create" the object!
 ****************************************************************************/

int object_check( char *object )
{

    struct stat object_check;

    if ( ( stat(object, &object_check) == -1 )) {
        return(false);
    }

    return(true);
}

/****************************************************************************
 * u32_time_to_human - Convert epoch time to human readable
 ****************************************************************************/

char *u32_time_to_human( uint64_t utime )
{

    struct tm tm;
    static char time_buf[80];
    char tmp[80];

    char *return_time = NULL;

    memset(&tm, 0, sizeof(struct tm));
    snprintf(tmp, sizeof(tmp) - 1, "%lu", utime);

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

    struct _Sagan_IPC_Counters *counters_ipc;

    struct _Sagan_IPC_Xbit *xbit_ipc;
    struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;

    struct thresh_by_src_ipc *threshbysrc_ipc;
    struct thresh_by_dst_ipc *threshbydst_ipc;
    struct thresh_by_username_ipc *threshbyusername_ipc;

    struct after_by_src_ipc *afterbysrc_ipc;
    struct after_by_dst_ipc *afterbydst_ipc;
    struct after_by_username_ipc *afterbyusername_ipc;

    /* For convert 32 bit IP to octet */

    struct in_addr ip_addr_src;
    struct in_addr ip_addr_dst;

    /* Shared memory descriptors */

    int shm_counters;
    int shm;

    int i;
    int file_check;

    char tmp_object_check[255];
    char tmp[64];

    char *ipc_directory = IPC_DIRECTORY;

    /* So users can point at the proper IPC location */

    if ( argc == 2 ) {
        ipc_directory = argv[1];
    }

    /* Load the "counters" first.  The "counters" keep track of the number of elements on the
     * other arrays */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, COUNTERS_IPC_FILE);

    if ( object_check(tmp_object_check) == false ) {
        fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
        usage();
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

    /*** Get "threshold by source" data ****/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESH_BY_SRC_IPC_FILE);

    if ( object_check(tmp_object_check) == false ) {
        fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
        usage();
        exit(1);
    }

    if ( (shm = open(tmp_object_check, O_RDONLY ) ) == -1 ) {
        fprintf(stderr, "[%s, line %d] Cannot open() for thresh_by_src (%s)\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    if (( threshbysrc_ipc = mmap(0, sizeof(thresh_by_src_ipc) + (sizeof(thresh_by_src_ipc) * counters_ipc->thresh_count_by_src), PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED ) {
        fprintf(stderr, "[%s, line %d] Error allocating memory for thresh_by_src object! [%s]\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    close(shm);

    if ( counters_ipc->thresh_count_by_src >= 1 ) {


        printf("\n***  Threshold by source (%d) ***\n", counters_ipc->thresh_count_by_src);
        printf("---------------------------------------------------------------------------------\n");
        printf("%-16s| %-15s| %-21s| %-11s| %s\n", "SRC IP", "Counter","Date added/modified", "SID", "Expire" );
        printf("---------------------------------------------------------------------------------\n");

        for ( i = 0; i < counters_ipc->thresh_count_by_src; i++) {

            ip_addr_src.s_addr = htonl(threshbysrc_ipc[i].ipsrc);

            printf("%-16s| %-15d| %-21s| %-11s| %d\n", inet_ntoa(ip_addr_src), threshbysrc_ipc[i].count, u32_time_to_human(threshbysrc_ipc[i].utime), threshbysrc_ipc[i].sid, threshbysrc_ipc[i].expire);

        }
    }

    /*** Get "threshold by destination" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESH_BY_DST_IPC_FILE);

    if ( object_check(tmp_object_check) == false ) {
        fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
        usage();
        exit(1);
    }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 ) {
        fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    if (( threshbydst_ipc = mmap(0, sizeof(thresh_by_dst_ipc) + (sizeof(thresh_by_dst_ipc) * counters_ipc->thresh_count_by_dst) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED ) {
        fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    close(shm);


    if ( counters_ipc->thresh_count_by_dst >= 1 ) {


        printf("\n***  Threshold by destination (%d)***\n", counters_ipc->thresh_count_by_dst );
        printf("---------------------------------------------------------------------------------\n");
        printf("%-16s| %-15s| %-21s| %-11s| %s\n", "DST IP", "Counter","Date added/modified", "SID", "Expire" );
        printf("---------------------------------------------------------------------------------\n");

        for ( i = 0; i < counters_ipc->thresh_count_by_dst; i++) {
            ip_addr_dst.s_addr = htonl(threshbydst_ipc[i].ipdst);

            printf("%-16s| %-15d| %-21s| %-11s| %d\n", inet_ntoa(ip_addr_dst), threshbydst_ipc[i].count, u32_time_to_human(threshbydst_ipc[i].utime), threshbydst_ipc[i].sid, threshbydst_ipc[i].expire);
        }

    }

    /*** Get "threshold by username" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESH_BY_USERNAME_IPC_FILE);

    if ( object_check(tmp_object_check) == false ) {
        fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
        usage();
        exit(1);
    }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 ) {
        fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    if (( threshbyusername_ipc = mmap(0, sizeof(thresh_by_username_ipc) + (sizeof(thresh_by_username_ipc) *  counters_ipc->thresh_count_by_username ), PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED ) {
        fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    close(shm);


    if ( counters_ipc->thresh_count_by_username >= 1 ) {


        printf("\n***  Threshold by username (%d) ***\n", counters_ipc->thresh_count_by_username);
        printf("---------------------------------------------------------------------------------\n");
        printf("%-16s| %-15s| %-21s| %-11s| %s\n", "Username", "Counter","Date added/modified", "SID", "Expire" );
        printf("---------------------------------------------------------------------------------\n");


        for ( i = 0; i < counters_ipc->thresh_count_by_username; i++) {
            printf("%-16s| %-15d| %-21s| %-11s| %d\n", inet_ntoa(ip_addr_src), threshbyusername_ipc[i].count, u32_time_to_human(threshbyusername_ipc[i].utime), threshbyusername_ipc[i].sid, threshbyusername_ipc[i].expire);
        }
    }

    /*** Get "after by source" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_SRC_IPC_FILE);

    if ( object_check(tmp_object_check) == false ) {
        fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
        usage();
        exit(1);
    }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 ) {
        fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    if (( afterbysrc_ipc = mmap(0, sizeof(after_by_src_ipc) + (sizeof(after_by_src_ipc) * counters_ipc->after_count_by_src ),  PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED ) {
        fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    close(shm);

    if ( counters_ipc->after_count_by_src >= 1 ) {

        printf("\n***  After by source (%d) ***\n", counters_ipc->after_count_by_src);
        printf("---------------------------------------------------------------------------------\n");
        printf("%-16s| %-15s| %-21s| %-11s| %s\n", "SRC IP", "Counter","Date added/modified", "SID", "Expire" );
        printf("---------------------------------------------------------------------------------\n");

        for ( i = 0; i < counters_ipc->after_count_by_src; i++) {
            ip_addr_src.s_addr = htonl(afterbysrc_ipc[i].ipsrc);
            printf("%-16s| %-15d| %-21s| %-11s| %d\n", inet_ntoa(ip_addr_src), afterbysrc_ipc[i].count, u32_time_to_human(afterbysrc_ipc[i].utime), afterbysrc_ipc[i].sid, afterbysrc_ipc[i].expire);
        }
    }


    /*** Get "After by destination" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_DST_IPC_FILE);

    if ( object_check(tmp_object_check) == false ) {
        fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
        usage();
        exit(1);
    }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 ) {
        fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    if (( afterbydst_ipc = mmap(0, sizeof(after_by_dst_ipc) + (sizeof(after_by_dst_ipc) * counters_ipc->after_count_by_dst ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED ) {
        fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    close(shm);

    if ( counters_ipc->after_count_by_dst >= 1 ) {

        printf("\n***  After by destination (%d)***\n", counters_ipc->after_count_by_dst);
        printf("---------------------------------------------------------------------------------\n");
        printf("%-16s| %-15s| %-21s| %-11s| %s\n", "DST IP", "Counter","Date added/modified", "SID", "Expire" );
        printf("---------------------------------------------------------------------------------\n");

        for ( i = 0; i < counters_ipc->after_count_by_dst; i++) {
            ip_addr_dst.s_addr = htonl(afterbydst_ipc[i].ipdst);

            printf("%-16s| %-15d| %-21s| %-11s| %d\n", inet_ntoa(ip_addr_dst), afterbydst_ipc[i].count, u32_time_to_human(afterbydst_ipc[i].utime), afterbydst_ipc[i].sid, afterbydst_ipc[i].expire);
        }
    }

    /*** Get "after by username" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_USERNAME_IPC_FILE);

    if ( object_check(tmp_object_check) == false ) {
        fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
        usage();
        exit(1);
    }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 ) {
        fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    if (( afterbyusername_ipc = mmap(0, sizeof(after_by_username_ipc) + (sizeof(after_by_username_ipc) * counters_ipc->after_count_by_username ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED ) {
        fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    close(shm);


    if ( counters_ipc->after_count_by_username >= 1 ) {

        printf("\n***  After by username ***(%d)\n", counters_ipc->after_count_by_username);
        printf("---------------------------------------------------------------------------------\n");
        printf("%-16s| %-15s| %-21s| %-11s| %s\n", "Username", "Counter","Date added/modified", "SID", "Expire" );
        printf("---------------------------------------------------------------------------------\n");



        for ( i = 0; i < counters_ipc->after_count_by_username; i++) {
            printf("%-16s| %-15d| %-21s| %-11s| %d\n", afterbyusername_ipc[i].username, afterbyusername_ipc[i].count, u32_time_to_human(afterbyusername_ipc[i].utime), afterbyusername_ipc[i].sid, afterbyusername_ipc[i].expire);
        }
    }

    /*** Get "xbit" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, XBIT_IPC_FILE);

    if ( object_check(tmp_object_check) == false ) {
        fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
        usage();
        exit(1);
    }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 ) {
        fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    if (( xbit_ipc = mmap(0, sizeof(_Sagan_IPC_Xbit) + (sizeof(_Sagan_IPC_Xbit) * counters_ipc->xbit_count ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED ) {
        fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
        exit(1);
    }

    close(shm);


    if ( counters_ipc->xbit_count >= 1 ) {

        printf("\n*** Xbits (%d) ****\n", counters_ipc->xbit_count);
        printf("-----------------------------------------------------------------------------------------------------------------------------\n");
        printf("%-9s| %-25s| %-16s| %-16s| %-21s| %s\n", "S", "Xbit name", "SRC IP", "DST IP", "Date added/modified", "Expire");
        printf("-----------------------------------------------------------------------------------------------------------------------------\n");

        for ( i = 0; i < counters_ipc->xbit_count; i++) {

            ip_addr_src.s_addr = htonl(xbit_ipc[i].ip_src);
            ip_addr_dst.s_addr = htonl(xbit_ipc[i].ip_dst);

            if ( xbit_ipc[i].xbit_state == 1 ) {

                printf("ACTIVE   | %-25s| ", xbit_ipc[i].xbit_name);
            } else {
                printf("INACTIVE | %-25s| ", xbit_ipc[i].xbit_name);
            }

            printf("%-16s| ", inet_ntoa(ip_addr_src));
            printf("%-16s| ", inet_ntoa(ip_addr_dst));
            printf("%-21s| ", u32_time_to_human(xbit_ipc[i].xbit_date));
            printf("%d (%s)\n", xbit_ipc[i].expire, u32_time_to_human(xbit_ipc[i].xbit_date + xbit_ipc[i].expire));

        }
    }

    /**** Get "Tracking" data (if enabled) ****/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, CLIENT_TRACK_IPC_FILE);

    if ( object_check(tmp_object_check) == true ) {

        if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 ) {
            fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

        if (( SaganTrackClients_ipc = mmap(0, sizeof(_Sagan_Track_Clients_IPC) + (sizeof(_Sagan_Track_Clients_IPC) * counters_ipc->track_clients_client_count ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED ) {
            fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

        close(shm);


        if ( counters_ipc->track_clients_client_count >= 1 ) {

            printf("\n*** Client Tracking (%d) ****\n", counters_ipc->track_clients_client_count);
            printf("-----------------------------------------------------------------------------------------------\n");
            printf("%-9s| %-16s| %-25s| %s\n", "State", "IP Address", "Last Seen Time", "Expire Seconds/Minutes" );
            printf("-----------------------------------------------------------------------------------------------\n");

            for ( i = 0; i < counters_ipc->track_clients_client_count; i++) {

                ip_addr_src.s_addr = htonl(SaganTrackClients_ipc[i].host_u32);

                if ( SaganTrackClients_ipc[i].status == 0 ) {
                    printf("ACTIVE   | %-16s| %-25s| %d/%d \n", inet_ntoa(ip_addr_src), u32_time_to_human(SaganTrackClients_ipc[i].utime), SaganTrackClients_ipc[i].expire, SaganTrackClients_ipc[i].expire / 60 );
                } else {
                    printf("INACTIVE | %-16s| %-25s| %d/%d \n", inet_ntoa(ip_addr_src), u32_time_to_human(SaganTrackClients_ipc[i].utime), SaganTrackClients_ipc[i].expire, SaganTrackClients_ipc[i].expire / 60 );

                }

            }
        }

        close(shm);

    } /* object_check */

    return(0);		/* Clean exit */

}


