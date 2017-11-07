/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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

/* TODO: need to add dstport, srcport for threshold/after */

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

#include "../src/sagan.h"
#include "../src/sagan-defs.h"
#include "../src/xbit-mmap.h"
#include "../src/util-time.h"

#include "../src/processors/track-clients.h"

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

    if ( ( stat(object, &object_check) == -1 ))
        {
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

    /* For convert to IP string */
    char ip_src[MAXIP];
    char ip_dst[MAXIP];

    char time_buf[80];

    /* Shared memory descriptors */

    int shm_counters;
    int shm;

    int i;
    int file_check;

    char tmp_object_check[255];
    char tmp[64];

    char *ipc_directory = IPC_DIRECTORY;

    /* So users can point at the proper IPC location */

    if ( argc == 2 )
        {
            ipc_directory = argv[1];
        }

    /* Load the "counters" first.  The "counters" keep track of the number of elements on the
     * other arrays */

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, COUNTERS_IPC_FILE);

    if ( object_check(tmp_object_check) == false )
        {
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

    if ( object_check(tmp_object_check) == false )
        {
            fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
            usage();
            exit(1);
        }

    if ( (shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
        {
            fprintf(stderr, "[%s, line %d] Cannot open() for thresh_by_src (%s)\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    if (( threshbysrc_ipc = mmap(0, sizeof(thresh_by_src_ipc) + (sizeof(thresh_by_src_ipc) * counters_ipc->thresh_count_by_src), PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
        {
            fprintf(stderr, "[%s, line %d] Error allocating memory for thresh_by_src object! [%s]\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    close(shm);

    if ( counters_ipc->thresh_count_by_src >= 1 )
        {


            printf("\n***  Threshold by source (%d) ***\n", counters_ipc->thresh_count_by_src);
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");
            printf("%-10s| %-45s| %-11s| %-21s| %-11s| %s\n", "Selector", "SRC IP", "Counter","Date added/modified", "SID", "Expire" );
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");

            for ( i = 0; i < counters_ipc->thresh_count_by_src; i++)
                {

                    Bit2IP(threshbysrc_ipc[i].ipsrc, ip_src, sizeof(ip_src));

                    u32_Time_To_Human(threshbysrc_ipc[i].utime, time_buf, sizeof(time_buf));

                    printf("%-10s| %-45s| %-11d| %-21s| %-11s| %d\n", threshbysrc_ipc[i].selector, ip_src, threshbysrc_ipc[i].count, time_buf, threshbysrc_ipc[i].sid, threshbysrc_ipc[i].expire);

                }

        }

    /*** Get "threshold by destination" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESH_BY_DST_IPC_FILE);

    if ( object_check(tmp_object_check) == false )
        {
            fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
            usage();
            exit(1);
        }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
        {
            fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    if (( threshbydst_ipc = mmap(0, sizeof(thresh_by_dst_ipc) + (sizeof(thresh_by_dst_ipc) * counters_ipc->thresh_count_by_dst) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
        {
            fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    close(shm);


    if ( counters_ipc->thresh_count_by_dst >= 1 )
        {

            printf("\n***  Threshold by destination (%d) ***\n", counters_ipc->thresh_count_by_dst);
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");
            printf("%-10s| %-45s| %-11s| %-21s| %-11s| %s\n", "Selector", "DST IP", "Counter","Date added/modified", "SID", "Expire" );
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");

            for ( i = 0; i < counters_ipc->thresh_count_by_dst; i++)
                {

                    Bit2IP(threshbydst_ipc[i].ipdst, ip_dst, sizeof(ip_dst));

                    u32_Time_To_Human(threshbydst_ipc[i].utime, time_buf, sizeof(time_buf));

                    printf("%-10s| %-45s| %-11d| %-21s| %-11s| %d\n", threshbydst_ipc[i].selector, ip_dst, threshbydst_ipc[i].count, time_buf, threshbydst_ipc[i].sid, threshbydst_ipc[i].expire);

                }

        }

    /*** Get "threshold by username" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESH_BY_USERNAME_IPC_FILE);

    if ( object_check(tmp_object_check) == false )
        {
            fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
            usage();
            exit(1);
        }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
        {
            fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    if (( threshbyusername_ipc = mmap(0, sizeof(thresh_by_username_ipc) + (sizeof(thresh_by_username_ipc) *  counters_ipc->thresh_count_by_username ), PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
        {
            fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    close(shm);


    if ( counters_ipc->thresh_count_by_username >= 1 )
        {

            printf("\n***  Threshold by username (%d) ***\n", counters_ipc->thresh_count_by_username);
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");
            printf("%-10s| %-16s| %-11s| %-21s| %-11s| %s\n", "Selector", "Username", "Counter","Date added/modified", "SID", "Expire" );
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");

            for ( i = 0; i < counters_ipc->thresh_count_by_username; i++)
                {

                    u32_Time_To_Human(threshbyusername_ipc[i].utime, time_buf, sizeof(time_buf));

                    printf("%-10s| %-16s| %-11d| %-21s| %-11s| %d\n", threshbyusername_ipc[i].selector, threshbyusername_ipc[i].username, threshbyusername_ipc[i].count, time_buf, threshbyusername_ipc[i].sid, threshbyusername_ipc[i].expire);
                }
        }

    /*** Get "after by source" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_SRC_IPC_FILE);

    if ( object_check(tmp_object_check) == false )
        {
            fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
            usage();
            exit(1);
        }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
        {
            fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    if (( afterbysrc_ipc = mmap(0, sizeof(after_by_src_ipc) + (sizeof(after_by_src_ipc) * counters_ipc->after_count_by_src ),  PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
        {
            fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    close(shm);

    if ( counters_ipc->after_count_by_src >= 1 )
        {

            printf("\n***  After by source (%d) ***\n", counters_ipc->after_count_by_src);
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");
            printf("%-10s| %-45s| %-11s| %-21s| %-11s| %s\n", "Selector", "SRC IP", "Counter","Date added/modified", "SID", "Expire" );
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");

            for ( i = 0; i < counters_ipc->after_count_by_src; i++ )
                {
                    Bit2IP(afterbysrc_ipc[i].ipsrc, ip_src, sizeof(ip_src));

                    u32_Time_To_Human(afterbysrc_ipc[i].utime, time_buf, sizeof(time_buf));

                    printf("%-10s| %-45s| %-11ld| %-21s| %-11s| %d\n", afterbysrc_ipc[i].selector, ip_src, afterbysrc_ipc[i].count, time_buf, afterbysrc_ipc[i].sid, afterbysrc_ipc[i].expire);
                }

        }


    /*** Get "After by destination" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_DST_IPC_FILE);

    if ( object_check(tmp_object_check) == false )
        {
            fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
            usage();
            exit(1);
        }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
        {
            fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    if (( afterbydst_ipc = mmap(0, sizeof(after_by_dst_ipc) + (sizeof(after_by_dst_ipc) * counters_ipc->after_count_by_dst ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
        {
            fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    close(shm);

    if ( counters_ipc->after_count_by_dst >= 1 )
        {

            printf("\n***  After by destination (%d)***\n", counters_ipc->after_count_by_dst);
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");
            printf("%-10s| %-45s| %-11s| %-21s| %-11s| %s\n", "Selector", "DST IP", "Counter","Date added/modified", "SID", "Expire" );
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");

            for ( i = 0; i < counters_ipc->after_count_by_dst; i++)
                {

                    Bit2IP(afterbydst_ipc[i].ipdst, ip_dst, sizeof(ip_dst));

                    u32_Time_To_Human(afterbydst_ipc[i].utime, time_buf, sizeof(time_buf));

                    printf("%-10s| %-45s| %-11d| %-21s| %-11s| %d\n", afterbydst_ipc[i].selector, ip_dst, afterbydst_ipc[i].count, time_buf, afterbydst_ipc[i].sid, afterbydst_ipc[i].expire);
                }
        }

    /*** Get "after by username" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_USERNAME_IPC_FILE);

    if ( object_check(tmp_object_check) == false )
        {
            fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
            usage();
            exit(1);
        }

    if ((shm = open(tmp_object_check, O_RDONLY ) ) == -1 )
        {
            fprintf(stderr, "[%s, line %d] Cannot open() (%s)\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    if (( afterbyusername_ipc = mmap(0, sizeof(after_by_username_ipc) + (sizeof(after_by_username_ipc) * counters_ipc->after_count_by_username ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
        {
            fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
            exit(1);
        }

    close(shm);


    if ( counters_ipc->after_count_by_username >= 1 )
        {

            printf("\n***  After by username ***(%d)\n", counters_ipc->after_count_by_username);
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");
            printf("%-10s| %-16s| %-11s| %-21s| %-11s| %s\n", "Selector", "Username", "Counter","Date added/modified", "SID", "Expire" );
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");

            for ( i = 0; i < counters_ipc->after_count_by_username; i++)
                {

                    u32_Time_To_Human(afterbyusername_ipc[i].utime, time_buf, sizeof(time_buf));

                    printf("%-10s| %-16s| %-11ld| %-21s| %-11s| %d\n", afterbyusername_ipc[i].selector, afterbyusername_ipc[i].username, afterbyusername_ipc[i].count, time_buf, afterbyusername_ipc[i].sid, afterbyusername_ipc[i].expire);
                }
        }

    /*** Get "xbit" data ***/

    snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, XBIT_IPC_FILE);

    if ( object_check(tmp_object_check) == false )
        {
            fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
            usage();
            exit(1);
        }

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

            printf("\n*** Xbits (%d) ****\n", counters_ipc->xbit_count);
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");
            printf("%-9s| %-10s| %-25s| %-45s| %-45s| %-8s| %-8s| %-21s| %s\n", "S", "Selector", "Xbit name", "SRC IP", "DST IP", "SRC PRT", "DST PRT", "Date added/modified", "Expire");
            printf("-----------------------------------------------------------------------------------------------------------------------------------\n");

            for (i= 0; i < counters_ipc->xbit_count; i++ )
                {

                    Bit2IP(xbit_ipc[i].ip_src, ip_src, sizeof(ip_src));
                    Bit2IP(xbit_ipc[i].ip_dst, ip_dst, sizeof(ip_dst));

                            u32_Time_To_Human(xbit_ipc[i].xbit_expire, time_buf, sizeof(time_buf));

                            printf("%-9s| %-10s| %-25s| %-45s| %-45s| %-8d| %8d| %-21s| %d\n",
                                   1 == xbit_ipc[i].xbit_state ? "ACTIVE" : "INACTIVE",
                                   xbit_ipc[i].selector,
                                   xbit_ipc[i].xbit_name,
                                   ip_src,
                                   ip_dst,
                                   xbit_ipc[i].src_port,
                                   xbit_ipc[i].dst_port,
                                   time_buf, xbit_ipc[i].expire );
                }
        }

    /**** Get "Tracking" data (if enabled) ****/

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

                    printf("\n*** Client Tracking (%d) ****\n", counters_ipc->track_clients_client_count);
                    printf("-----------------------------------------------------------------------------------------------------------------------------------\n");
                    printf("%-9s| %-45s| %-25s| %s\n", "State", "IP Address", "Last Seen Time", "Expire Seconds/Minutes");
                    printf("-----------------------------------------------------------------------------------------------------------------------------------\n");

                    for ( i = 0; i < counters_ipc->track_clients_client_count; i++)
                        {

                            Bit2IP(SaganTrackClients_ipc[i].hostbits, ip_src, sizeof(SaganTrackClients_ipc[i].hostbits));

                            u32_Time_To_Human(SaganTrackClients_ipc[i].expire, time_buf, sizeof(time_buf));

                            printf("%-9s| %-45s| %-25s| %d/%d\n",
                                   0 == SaganTrackClients_ipc[i].status ? "ACTIVE" : "INACTIVE",
                                   ip_src,
                                   time_buf,
                                   SaganTrackClients_ipc[i].expire,
                                   SaganTrackClients_ipc[i].expire / 60 );

                        }
                }

            close(shm);

        } /* object_check */

    return(0);        /* Clean exit */

}


