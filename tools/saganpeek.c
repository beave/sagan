/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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

/* TODO: need to add dstport, srcport for threshold/after
   DEBUG: Need ports?
   DEBUG: --debug limits isn't show after?!? in ./sagan
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
#include "../src/xbit-mmap.h"
#include "../src/util-time.h"

#include "../src/processors/track-clients.h"

#define ALL_TYPES 0
#define THRESHOLD_TYPE 1
#define AFTER_TYPE 2
#define XBIT_TYPE 3
#define TRACK_TYPE 4

/****************************************************************************
 * usage - Give the user some hints about how to use this utility!
 ****************************************************************************/

void Usage( void )
{

    fprintf(stderr, "\n--[ saganpeek help ]---------------------------------------------------------\n\n");
    fprintf(stderr, "-t, --type\tthreshold, after, xbit, track, all (default: all)\n");
    fprintf(stderr, "-h, --help\tThis screen.\n");
    fprintf(stderr, "-i, --ipc\tIPC source directory. (default: %s)\n", IPC_DIRECTORY);
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

/* DEBUG - this is like in util-time.c */

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

    const struct option long_options[] =
    {
        { "help",         no_argument,          NULL,   'h' },
        { "ipc", 	  required_argument, 	NULL,	'i' },
        { "type", 	  required_argument, 	NULL,	't' },
        {0, 0, 0, 0}
    };

    static const char *short_options =
        "i:t:h";

    int option_index = 0;

    struct _Sagan_IPC_Counters *counters_ipc;

    struct _Sagan_IPC_Xbit *xbit_ipc;
    struct _Sagan_Track_Clients_IPC *SaganTrackClients_ipc;

    struct thresh_by_src_ipc *threshbysrc_ipc;
    struct thresh_by_dst_ipc *threshbydst_ipc;
    struct thresh_by_username_ipc *threshbyusername_ipc;

    struct after_by_src_ipc *afterbysrc_ipc;
    struct after_by_dst_ipc *afterbydst_ipc;
    struct after_by_username_ipc *afterbyusername_ipc;

    struct _After2_IPC *After2_IPC; 

    signed char c;

    /* For convert to IP string */
    char ip_src[MAXIP];
    char ip_dst[MAXIP];

    char time_buf[80];

    /* Shared memory descriptors */

    int shm_counters;
    int shm;

    int i;

    bool typeflag = 0;
    unsigned char type = ALL_TYPES;

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

    /*** Get "threshold by source" data ****/

    if ( type == ALL_TYPES || type == THRESHOLD_TYPE )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESH_BY_SRC_IPC_FILE);

            if ( object_check(tmp_object_check) == false )
                {
                    fprintf(stderr, "Error.  Can't locate %s. Abort!\n", tmp_object_check);
                    Usage();
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

                    for ( i = 0; i < counters_ipc->thresh_count_by_src; i++)
                        {

                            Bit2IP(threshbysrc_ipc[i].ipsrc, ip_src, sizeof(ip_src));

                            printf("Type: Threshold by source [%d].\n", i);

                            u32_Time_To_Human(threshbysrc_ipc[i].utime, time_buf, sizeof(time_buf));

                            printf("Selector: ");

                            if ( threshbysrc_ipc[i].selector[0] == 0 )
                                {
                                    printf("[None]\n");
                                }
                            else
                                {
                                    printf("%s\n", threshbysrc_ipc[i].selector);
                                }

                            printf("Source IP: %s\n", ip_src);
                            printf("Signature: \"%s\" (%s)\n", threshbysrc_ipc[i].signature_msg, threshbysrc_ipc[i].sid);
                            printf("Syslog Message: \"%s\"\n", threshbysrc_ipc[i].syslog_message);
                            printf("Date added/modified: %s\n", time_buf);
                            printf("Counter: %d\n", threshbysrc_ipc[i].count);
                            printf("Expire Time: %d\n\n", threshbysrc_ipc[i].expire);

                        }


                }

            /*** Get "threshold by destination" data ***/

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESH_BY_DST_IPC_FILE);

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

            if (( threshbydst_ipc = mmap(0, sizeof(thresh_by_dst_ipc) + (sizeof(thresh_by_dst_ipc) * counters_ipc->thresh_count_by_dst) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                {
                    fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            close(shm);


            if ( counters_ipc->thresh_count_by_dst >= 1 )
                {

                    for ( i = 0; i < counters_ipc->thresh_count_by_dst; i++)
                        {

                            Bit2IP(threshbydst_ipc[i].ipdst, ip_dst, sizeof(ip_dst));

                            u32_Time_To_Human(threshbydst_ipc[i].utime, time_buf, sizeof(time_buf));

                            printf("Type: Threshold by destination [%d].\n", i);

                            printf("Selector: ");

                            if ( threshbydst_ipc[i].selector[0] == 0 )
                                {
                                    printf("[None]\n");
                                }
                            else
                                {
                                    printf("%s\n", threshbydst_ipc[i].selector);
                                }

                            printf("Destination IP: %s\n", ip_dst);
                            printf("Signature: \"%s\" (%s)\n", threshbydst_ipc[i].signature_msg, threshbydst_ipc[i].sid);
                            printf("Syslog Message: \"%s\"\n", threshbydst_ipc[i].syslog_message);
                            printf("Date added/modified: %s\n", time_buf);
                            printf("Counter: %d\n", threshbydst_ipc[i].count);
                            printf("Expire Time: %d\n\n", threshbydst_ipc[i].expire);

                        }

                }


            /*** Get "threshold by username" data ***/

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, THRESH_BY_USERNAME_IPC_FILE);

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

            if (( threshbyusername_ipc = mmap(0, sizeof(thresh_by_username_ipc) + (sizeof(thresh_by_username_ipc) *  counters_ipc->thresh_count_by_username ), PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                {
                    fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            close(shm);


            if ( counters_ipc->thresh_count_by_username >= 1 )
                {

                    for ( i = 0; i < counters_ipc->thresh_count_by_username; i++)
                        {

                            printf("Type: Threshold by username [%d].\n", i);

                            u32_Time_To_Human(threshbyusername_ipc[i].utime, time_buf, sizeof(time_buf));

                            printf("Selector: ");

                            if ( threshbyusername_ipc[i].selector[0] == 0 )
                                {
                                    printf("[None]\n");
                                }
                            else
                                {
                                    printf("%s\n", threshbyusername_ipc[i].selector);
                                }

                            printf("Username: %s\n", threshbyusername_ipc[i].username);
                            printf("Signature: \"%s\" (%s)\n", threshbyusername_ipc[i].signature_msg, threshbyusername_ipc[i].sid);
                            printf("Syslog Message: \"%s\"\n", threshbyusername_ipc[i].syslog_message);
                            printf("Date added/modified: %s\n", time_buf);
                            printf("Counter: %d\n", threshbyusername_ipc[i].count);
                            printf("Expire Time: %d\n\n", threshbyusername_ipc[i].expire);


                        }
                }

        }

    /*** Get "after by source" data ***/

    if ( type == ALL_TYPES || type == AFTER_TYPE )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_SRC_IPC_FILE);

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

            if (( afterbysrc_ipc = mmap(0, sizeof(after_by_src_ipc) + (sizeof(after_by_src_ipc) * counters_ipc->after_count_by_src ),  PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                {
                    fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            close(shm);

            if ( counters_ipc->after_count_by_src >= 1 )
                {

                    for ( i = 0; i < counters_ipc->after_count_by_src; i++ )
                        {
                            Bit2IP(afterbysrc_ipc[i].ipsrc, ip_src, sizeof(ip_src));

                            printf("Type: After by source [%d].\n", i);

                            u32_Time_To_Human(afterbysrc_ipc[i].utime, time_buf, sizeof(time_buf));

                            printf("Selector: ");

                            if ( afterbysrc_ipc[i].selector[0] == 0 )
                                {
                                    printf("[None]\n");
                                }
                            else
                                {
                                    printf("%s\n", afterbysrc_ipc[i].selector);
                                }

                            printf("Source IP: %s\n", ip_src);
                            printf("Signature: \"%s\" (%s)\n", afterbysrc_ipc[i].signature_msg, afterbysrc_ipc[i].sid);
                            printf("Syslog Message: \"%s\"\n", afterbysrc_ipc[i].syslog_message);
                            printf("Date added/modified: %s\n", time_buf);
                            printf("Counter: %" PRIu64 "\n", afterbysrc_ipc[i].count);
                            printf("Expire Time: %d\n\n", afterbysrc_ipc[i].expire);

                        }

                }


            /*** Get "After by destination" data ***/

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

                            printf("Type: After2 [%d].\n", i);

                            u32_Time_To_Human(After2_IPC[i].utime, time_buf, sizeof(time_buf));

                            printf("Selector: ");

                            if ( After2_IPC[i].selector[0] == 0 )
                                {
                                    printf("[None]\n");
                                }
                            else
                                {
                                    printf("%s\n", After2_IPC[i].selector);
                                }


                            printf("Hash: %lu\n", After2_IPC[i].hash);

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

				printf("\n");

			    if ( After2_IPC[i].after2_method_src == true )
			    {
			    printf("IP SRC: %s\n", After2_IPC[i].ip_src); 
			    }

			    if ( After2_IPC[i].after2_method_dst == true )
			    {
		            printf("IP DST: %s\n", After2_IPC[i].ip_dst);
		            }

			    if ( After2_IPC[i].after2_method_username == true )
			    {
			    printf("String: %s\n",  After2_IPC[i].string1);
			    }


                            printf("Signature: \"%s\" (%s)\n", After2_IPC[i].signature_msg, After2_IPC[i].sid);
                            printf("Syslog Message: \"%s\"\n", After2_IPC[i].syslog_message);
                            printf("Date added/modified: %s\n", time_buf);
                            printf("Counter: %d\n", After2_IPC[i].count);
                            printf("Expire Time: %d\n\n", After2_IPC[i].expire);

                        }
                }


            /*** Get "After by destination" data ***/

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_DST_IPC_FILE);

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

            if (( afterbydst_ipc = mmap(0, sizeof(after_by_dst_ipc) + (sizeof(after_by_dst_ipc) * counters_ipc->after_count_by_dst ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                {
                    fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            close(shm);

            if ( counters_ipc->after_count_by_dst >= 1 )
                {

                    for ( i = 0; i < counters_ipc->after_count_by_dst; i++)
                        {

                            Bit2IP(afterbydst_ipc[i].ipdst, ip_dst, sizeof(ip_dst));

                            printf("Type: After by destination [%d].\n", i);

                            u32_Time_To_Human(afterbydst_ipc[i].utime, time_buf, sizeof(time_buf));

                            printf("Selector: ");

                            if ( afterbydst_ipc[i].selector[0] == 0 )
                                {
                                    printf("[None]\n");
                                }
                            else
                                {
                                    printf("%s\n", afterbydst_ipc[i].selector);
                                }

                            printf("Source IP: %s\n", ip_dst);
                            printf("Signature: \"%s\" (%s)\n", afterbydst_ipc[i].signature_msg, afterbydst_ipc[i].sid);
                            printf("Syslog Message: \"%s\"\n", afterbydst_ipc[i].syslog_message);
                            printf("Date added/modified: %s\n", time_buf);
                            printf("Counter: %d\n", afterbydst_ipc[i].count);
                            printf("Expire Time: %d\n\n", afterbydst_ipc[i].expire);

                        }
                }

            /*** Get "after by username" data ***/

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, AFTER_BY_USERNAME_IPC_FILE);

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

            if (( afterbyusername_ipc = mmap(0, sizeof(after_by_username_ipc) + (sizeof(after_by_username_ipc) * counters_ipc->after_count_by_username ) , PROT_READ, MAP_SHARED, shm, 0)) == MAP_FAILED )
                {
                    fprintf(stderr, "[%s, line %d] Error allocating memory object! [%s]\n", __FILE__, __LINE__, strerror(errno));
                    exit(1);
                }

            close(shm);


            if ( counters_ipc->after_count_by_username >= 1 )
                {

                    for ( i = 0; i < counters_ipc->after_count_by_username; i++)
                        {


                            printf("Type: After by username [%d].\n", i);

                            u32_Time_To_Human(afterbyusername_ipc[i].utime, time_buf, sizeof(time_buf));

                            printf("Selector: ");

                            if ( afterbyusername_ipc[i].selector[0] == 0 )
                                {
                                    printf("[None]\n");
                                }
                            else
                                {
                                    printf("%s\n", afterbyusername_ipc[i].selector);
                                }

                            printf("Username: %s\n", afterbyusername_ipc[i].username);
                            printf("Signature: \"%s\" (%s)\n", afterbyusername_ipc[i].signature_msg, afterbyusername_ipc[i].sid);
                            printf("Syslog Message: \"%s\"\n", afterbyusername_ipc[i].syslog_message);
                            printf("Date added/modified: %s\n", time_buf);
                            printf("Counter: %" PRIu64 "\n", afterbyusername_ipc[i].count);
                            printf("Expire Time: %d\n\n", afterbyusername_ipc[i].expire);


                        }
                }

        }

    /*** Get "xbit" data ***/

    if ( type == ALL_TYPES || type == XBIT_TYPE )
        {

            snprintf(tmp_object_check, sizeof(tmp_object_check) - 1, "%s/%s", ipc_directory, XBIT_IPC_FILE);

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

                            printf("Type: xbit [%d].\n", i);
                            printf("Selector: ");

                            if ( xbit_ipc[i].selector[0] == 0 )
                                {
                                    printf("[None]\n");
                                }
                            else
                                {
                                    printf("%s\n", xbit_ipc[i].selector);
                                }

                            printf("Xbit name: \"%s\"\n", xbit_ipc[i].xbit_name);
                            printf("State: %s\n", xbit_ipc[i].xbit_state == 1 ? "ACTIVE" : "INACTIVE");
                            printf("IP: %s:%d -> %s:%d\n", xbit_ipc[i].ip_src, xbit_ipc[i].src_port, xbit_ipc[i].ip_dst, xbit_ipc[i].dst_port);
                            printf("Signature: \"%s\" (%s)\n", xbit_ipc[i].signature_msg, xbit_ipc[i].sid);
                            printf("Expire Time: %s (%d seconds)\n", time_buf, xbit_ipc[i].expire);
                            printf("Syslog message: \"%s\"\n\n", xbit_ipc[i].syslog_message );

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


