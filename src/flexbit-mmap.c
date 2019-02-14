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

/*
 * xbit-mmap.c - Functions used for tracking events over multiple log
 * lines.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "ipc.h"
#include "flexbit-mmap.h"
#include "rules.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

pthread_mutex_t Flexbit_Mutex=PTHREAD_MUTEX_INITIALIZER;

struct _Sagan_IPC_Counters *counters_ipc;
struct _Sagan_IPC_Flexbit *xbit_ipc;

/*****************************************************************************
 * Flexbit_Condition - Used for testing "isset" & "isnotset".  Full
 * rule condition is tested here and returned.
 *****************************************************************************/

bool Flexbit_Condition_MMAP(int rule_position, char *ip_src, char *ip_dst, int src_port, int dst_port, char *selector )
{

    time_t t;
    struct tm *now;
    char  timet[20];

    int i;
    int a;

    int xbit_total_match = 0;
    bool xbit_match = 0;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    Flexbit_Cleanup_MMAP();

    for (i = 0; i < rulestruct[rule_position].xbit_count; i++)
        {

            /*******************
             *      ISSET      *
             *******************/

            if ( rulestruct[rule_position].xbit_type[i] == 3 )
                {


                    if ( debug->debugflexbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Condition \"isset\" found in rule.", __FILE__, __LINE__);
                        }


                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {

                            /* Short circuit if no selector match */

                            if (
                                (selector == NULL && xbit_ipc[a].selector[0] != '\0') ||
                                (selector != NULL && strcmp(selector, xbit_ipc[a].selector) != 0)
                            )
                                {

                                    continue;
                                }

                            if ( !memcmp(rulestruct[rule_position].xbit_name[i], xbit_ipc[a].flexbit_name, sizeof(rulestruct[rule_position].xbit_name[i])) &&
                                    xbit_ipc[a].flexbit_state == true )
                                {

                                    /* direction: by_src - most common check */

                                    if ( rulestruct[rule_position].xbit_direction[i] == 2 &&
                                            !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) )

                                        {

                                            if ( debug->debugflexbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, xbit_ipc[a].ip_src);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: none */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 0 )

                                        {

                                            if ( debug->debugflexbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"none\"). (any -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: both */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 1 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) )

                                        {

                                            if ( debug->debugflexbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src, ip_dst);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: by_dst */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 3 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: reverse */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 4 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) )

                                        {
                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst, ip_src);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: src_xbitdst */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 5 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"src_xbitdst\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: dst_xbitsrc */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 6 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"dst_xbitsrc\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: both_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 7 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                              xbit_ipc[a].src_port == src_port &&
                                              xbit_ipc[a].dst_port == dst_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"both_p\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src, ip_dst);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: by_src_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 8 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                              xbit_ipc[a].src_port == src_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"by_src_p\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: by_dst_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 9 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst))  &&
                                              xbit_ipc[a].dst_port == dst_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"by_dst_p\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: reverse_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 10 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) &&
                                              xbit_ipc[a].src_port == dst_port &&
                                              xbit_ipc[a].dst_port == src_port )


                                        {
                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"reverse_p\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst, ip_src);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: src_xbitdst_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 11 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) &&
                                              xbit_ipc[a].dst_port == src_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"src_xbitdst_p\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            xbit_total_match++;

                                        }

                                    /* direction: dst_xbitsrc_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 12 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) &&
                                              xbit_ipc[a].src_port == dst_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"dst_xbitsrc_p\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            xbit_total_match++;

                                        }

                                } /* End of strcmp flexbit_name & flexbit_state = 1 */

                        } /* End of "for a" */

                } /* End "if" xbit_type == 3 (ISSET) */

            /*******************
            *    ISNOTSET     *
            *******************/

            if ( rulestruct[rule_position].xbit_type[i] == 4 )
                {


                    if ( debug->debugflexbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Condition \"isnotset\" found in rule.", __FILE__, __LINE__);
                        }

                    xbit_match = false;

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {
                            if ( !memcmp(rulestruct[rule_position].xbit_name[i], xbit_ipc[a].flexbit_name, sizeof(rulestruct[rule_position].xbit_name[i])) )
                                {

                                    /* direction: none */

                                    if ( rulestruct[rule_position].xbit_direction[i] == 0 )
                                        {

                                            if ( xbit_ipc[a].flexbit_state == true )
                                                {
                                                    if ( debug->debugflexbit )
                                                        {
                                                            Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"none\"). (any -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name);

                                                        }

                                                    xbit_match = true;
                                                }
                                        }

                                    /* direction: both */

                                    if ( rulestruct[rule_position].xbit_direction[i] == 1 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                                    !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) )
                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"by_src\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src, ip_dst);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: by_src */

                                    if ( rulestruct[rule_position].xbit_direction[i] == 2 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) )
                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: by_dst */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 3 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) )
                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: reverse */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 4 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) &&
                                                    !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) )
                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst, ip_src);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direciton: src_xbitdst */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 5 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) )
                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"src_xbitdst\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: dst_xbitsrc */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 6 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) )
                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"src_xbitdst\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: both_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 7 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                                    !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                                    xbit_ipc[a].src_port == src_port &&
                                                    xbit_ipc[a].dst_port == dst_port )

                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"src_xbitdst\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: by_src_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 8 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                                    xbit_ipc[a].src_port == src_port )

                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"by_src_p\"). (%s:%d -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src, src_port);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: by_dst_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 9 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                                    xbit_ipc[a].dst_port == dst_port )

                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"by_dst_p\"). (any -> %s:%d)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst, dst_port);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: reverse_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 10 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) &&
                                                    !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) &&
                                                    xbit_ipc[a].src_port == dst_port &&
                                                    xbit_ipc[a].dst_port == src_port)
                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"reverse_p\"). (%s:%d -> %s:%d)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src, dst_port, ip_dst, src_port);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: src_xbitdst_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 11 )
                                        {

                                            if ( !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) &&
                                                    xbit_ipc[a].dst_port == src_port )

                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"src_xbitdst_p\"). (any -> %s:%d)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src, src_port);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                    /* direction: dst_xbitsrc_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 12 )
                                        {


                                            if ( !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) &&
                                                    xbit_ipc[a].src_port == dst_port )
                                                {
                                                    if ( xbit_ipc[a].flexbit_state == true )
                                                        {
                                                            if ( debug->debugflexbit )
                                                                {
                                                                    Sagan_Log(DEBUG, "[%s, line %d] \"isnotset\" xbit \"%s\" true (direction: \"dst_xbitsrc_p\"). (%s:%d-> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst, dst_port);

                                                                }

                                                            xbit_match = true;
                                                        }
                                                }
                                        }

                                } /* if memcmp(rulestruct[rule_position].xbit_name[i] */
                        } /* for a = 0 */

                    /* xbit wasn't found for isnotset */

                    if ( xbit_match == false )
                        {
                            xbit_total_match++;
                        }

                } /* rulestruct[rule_position].xbit_type[i] == 4 */

        } /* for (i = 0; i < rulestruct[rule_position].xbit_count; i++) */


    if ( xbit_total_match == rulestruct[rule_position].xbit_condition_count )
        {

            if ( debug->debugflexbit )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Got %d xbits & needed %d. Got corrent number of xbits, return true!", __FILE__, __LINE__, xbit_total_match, rulestruct[rule_position].xbit_condition_count );
                }

            return(true);

        }
    else
        {

            if ( debug->debugflexbit )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Got %d xbits, needed %d", __FILE__, __LINE__, xbit_total_match, rulestruct[rule_position].xbit_condition_count );
                }

            return(false);

        }

    Sagan_Log(WARN, "Shouldn't make it this far in Xbit_Condition()!\n");

}  /* End of Xbit_Condition(); */


/*****************************************************************************
 * Flexbit_Count - Used to determine how many xbits have been set based on a
 * source or destination address.  This is useful for identification of
 * distributed attacks.
 *****************************************************************************/

bool Flexbit_Count_MMAP( int rule_position, char *ip_src, char *ip_dst, char *selector )
{

    uint32_t a = 0;
    uint32_t i = 0;
    uint32_t counter = 0;

    for (i = 0; i < rulestruct[rule_position].xbit_count_count; i++)
        {

            for (a = 0; a < counters_ipc->flexbit_count; a++)
                {
                    /* Short circuit if no selector match */

                    if (
                        (selector == NULL && xbit_ipc[a].selector[0] != '\0') ||
                        (selector != NULL && 0 != strcmp(selector, xbit_ipc[a].selector))
                    )
                        {

                            continue;
                        }

                    if ( rulestruct[rule_position].xbit_direction[i] == 2 &&
                            !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) )
                        {

                            counter++;

                            if ( rulestruct[rule_position].xbit_count_gt_lt[i] == 0 )
                                {

                                    if ( counter > rulestruct[rule_position].xbit_count_counter[i] )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Xbit count 'by_src' threshold reached for xbit '%s'.", __FILE__, __LINE__, xbit_ipc[a].flexbit_name);
                                                }


                                            return(true);
                                        }
                                }
                        }

                    else if ( rulestruct[rule_position].xbit_direction[i] == 3 &&
                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) )
                        {

                            counter++;

                            if ( rulestruct[rule_position].xbit_count_gt_lt[i] == 0 )
                                {

                                    if ( counter > rulestruct[rule_position].xbit_count_counter[i] )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Xbit count 'by_dst' threshold reached for xbit '%s'.", __FILE__, __LINE__, xbit_ipc[a].flexbit_name);
                                                }

                                            return(true);
                                        }
                                }
                        }
                }
        }

    if ( debug->debugflexbit)
        {
            Sagan_Log(DEBUG, "[%s, line %d] Xbit count threshold NOT reached for xbit.", __FILE__, __LINE__);
        }

    return(false);
}


/*****************************************************************************
 * Flexbit_Set - Used to "set" & "unset" xbit.  All rule "set" and
 * "unset" happen here.
 *****************************************************************************/

void Flexbit_Set_MMAP(int rule_position, char *ip_src, char *ip_dst, int src_port, int dst_port, char *selector, char *syslog_message )
{

    int i = 0;
    int a = 0;

    time_t t;
    struct tm *now;
    char  timet[20];

    bool xbit_match = false;
    bool xbit_unset_match = 0;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    struct _Sagan_Flexbit_Track *xbit_track;

    xbit_track = malloc(sizeof(_Sagan_Flexbit_Track));

    if ( xbit_track  == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for xbit_track. Abort!", __FILE__, __LINE__);
        }

    memset(xbit_track, 0, sizeof(_Sagan_Flexbit_Track));

    int xbit_track_count = 0;

    Flexbit_Cleanup_MMAP();

    for (i = 0; i < rulestruct[rule_position].xbit_count; i++)
        {

            /*******************
             *      UNSET      *
             *******************/

            if ( rulestruct[rule_position].xbit_type[i] == 2 )
                {

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {
                            /* Short circuit if no selector match */

                            if (
                                ( selector == NULL && xbit_ipc[a].selector[0] != '\0') ||
                                ( selector != NULL && strcmp(selector, xbit_ipc[a].selector) != 0 )
                            )
                                {

                                    continue;
                                }


                            if ( !strcmp(xbit_ipc[a].flexbit_name, rulestruct[rule_position].xbit_name[i] ))
                                {

                                    /* direction: none */

                                    if ( rulestruct[rule_position].xbit_direction[i] == 0 )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"none\"). (any -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name);
                                                }


                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }


                                    /* direction: both */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 1 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src, ip_dst);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: by_src */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 2 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"by_src\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }


                                    /* direction: by_dst */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 3 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: reverse */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 4 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"reverse\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst, ip_src);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = false;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: src_xbitdst */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 5 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"src_xbitdst\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: dst_xbitsrc */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 6 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"dst_xbitsrc\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: both_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 7 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                              xbit_ipc[a].src_port == src_port &&
                                              xbit_ipc[a].dst_port == dst_port )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"both_p\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src, ip_dst);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: by_src_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 8 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                              xbit_ipc[a].src_port == src_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"by_src_p\"). (%s -> any)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }


                                    /* direction: by_dst_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 9 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                              xbit_ipc[a].dst_port == dst_port )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"by_dst\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: reverse_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 10 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) &&
                                              xbit_ipc[a].src_port == dst_port &&
                                              xbit_ipc[a].dst_port == src_port )

                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"reverse_p\"). (%s -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst, ip_src);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: src_xbitdst_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 11 &&
                                              !memcmp(xbit_ipc[a].ip_dst, ip_src, sizeof(xbit_ipc[a].ip_dst)) &&
                                              xbit_ipc[a].dst_port == src_port )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"src_xbitdst_p\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_src);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                    /* direction: dst_xbitsrc_p */

                                    else if ( rulestruct[rule_position].xbit_direction[i] == 12 &&
                                              !memcmp(xbit_ipc[a].ip_src, ip_dst, sizeof(xbit_ipc[a].ip_src)) &&
                                              xbit_ipc[a].src_port == dst_port )
                                        {

                                            if ( debug->debugflexbit)
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] \"unset\" xbit \"%s\" (direction: \"dst_xbitsrc_p\"). (any -> %s)", __FILE__, __LINE__, xbit_ipc[a].flexbit_name, ip_dst);
                                                }

                                            File_Lock(config->shm_xbit);
                                            pthread_mutex_lock(&Flexbit_Mutex);

                                            xbit_ipc[a].flexbit_state = 0;

                                            pthread_mutex_unlock(&Flexbit_Mutex);
                                            File_Unlock(config->shm_xbit);

                                            xbit_unset_match = 1;

                                        }

                                }
                        }

                    if ( debug->debugflexbit && xbit_unset_match == 0 )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] No xbit found to \"unset\" for %s.", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[i]);
                        }

                } /* if ( rulestruct[rule_position].xbit_type[i] == 2 ) */

            /*******************
             *      SET        *
            *******************/

            else if ( rulestruct[rule_position].xbit_type[i] == 1 )
                {

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {
                            /* Short circuit if no selector match */

                            if (
                                ( selector == NULL && xbit_ipc[a].selector[0] != '\0') ||
                                ( selector != NULL && 0 != strcmp(selector, xbit_ipc[a].selector ))
                            )
                                {

                                    continue;
                                }

                            /* Do we have the xbit already in memory?  If so,  update the information */

                            if (!strcmp(xbit_ipc[a].flexbit_name, rulestruct[rule_position].xbit_name[i]) &&
                                    !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                    !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                    xbit_ipc[a].src_port == config->sagan_port &&
                                    xbit_ipc[a].dst_port == config->sagan_port )
                                {


                                    File_Lock(config->shm_xbit);
                                    pthread_mutex_lock(&Flexbit_Mutex);

                                    xbit_ipc[a].flexbit_date = atol(timet);
                                    xbit_ipc[a].flexbit_expire = atol(timet) + rulestruct[rule_position].xbit_timeout[i];
                                    xbit_ipc[a].flexbit_state = true;
                                    strlcpy(xbit_ipc[a].syslog_message, syslog_message, sizeof(xbit_ipc[a].syslog_message));
                                    strlcpy(xbit_ipc[a].signature_msg, rulestruct[rule_position].s_msg, sizeof(xbit_ipc[a].signature_msg));
                                    xbit_ipc[a].sid = rulestruct[rule_position].s_sid;


                                    if ( debug->debugflexbit)
                                        {

                                            Sagan_Log(DEBUG,"[%s, line %d] [%d] Updated via \"set\" for xbit \"%s\". Nex expire time is %d (%d) [ %s:%d -> %s:%d ]", __FILE__, __LINE__, a, rulestruct[rule_position].xbit_name[i], xbit_ipc[i].flexbit_expire, rulestruct[rule_position].xbit_timeout[i], xbit_ipc[a].ip_src, xbit_ipc[a].src_port, xbit_ipc[a].ip_dst, xbit_ipc[a].dst_port);

                                        }

                                    pthread_mutex_unlock(&Flexbit_Mutex);
                                    File_Unlock(config->shm_xbit);

                                    xbit_match = true;
                                }

                        }


                    /* If the xbit isn't in memory,  store it to be created later */

                    if ( xbit_match == false )
                        {

                            xbit_track = ( _Sagan_Flexbit_Track * ) realloc(xbit_track, (xbit_track_count+1) * sizeof(_Sagan_Flexbit_Track));

                            if ( xbit_track == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for xbit_track. Abort!", __FILE__, __LINE__);
                                }

                            memset(&xbit_track[xbit_track_count], 0, sizeof(_Sagan_Flexbit_Track));

                            strlcpy(xbit_track[xbit_track_count].flexbit_name, rulestruct[rule_position].xbit_name[i], sizeof(xbit_track[xbit_track_count].flexbit_name));
                            strlcpy(xbit_ipc[xbit_track_count].syslog_message, syslog_message, sizeof(xbit_ipc[xbit_track_count].syslog_message));
                            strlcpy(xbit_ipc[xbit_track_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(xbit_ipc[xbit_track_count].signature_msg));
                            xbit_ipc[xbit_track_count].sid = rulestruct[rule_position].s_sid;

                            xbit_track[xbit_track_count].flexbit_timeout = rulestruct[rule_position].xbit_timeout[i];
                            xbit_track[xbit_track_count].flexbit_srcport = config->sagan_port;
                            xbit_track[xbit_track_count].flexbit_dstport = config->sagan_port;
                            xbit_track_count++;

                        }

                } /* if xbit_type == 1 */

            /***************************
             *      SET_SRCPORT        *
            ****************************/

            else if ( rulestruct[rule_position].xbit_type[i] == 5 )
                {

                    xbit_match = false;

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {
                            /* Short circuit if no selector match */

                            if (
                                ( selector == NULL && xbit_ipc[a].selector[0] != '\0') ||
                                ( selector != NULL && 0 != strcmp(selector, xbit_ipc[a].selector ))
                            )
                                {

                                    continue;
                                }

                            /* Do we have the xbit already in memory?  If so,  update the information */

                            if (!strcmp(xbit_ipc[a].flexbit_name, rulestruct[rule_position].xbit_name[i]) &&
                                    !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                    !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                    xbit_ipc[a].src_port == src_port &&
                                    xbit_ipc[a].dst_port == config->sagan_port )
                                {

                                    File_Lock(config->shm_xbit);
                                    pthread_mutex_lock(&Flexbit_Mutex);

                                    xbit_ipc[a].flexbit_date = atol(timet);
                                    xbit_ipc[a].flexbit_expire = atol(timet) + rulestruct[rule_position].xbit_timeout[i];
                                    xbit_ipc[a].flexbit_state = true;
                                    strlcpy(xbit_ipc[a].syslog_message, syslog_message, sizeof(xbit_ipc[a].syslog_message));

                                    if ( debug->debugflexbit)
                                        {

                                            Sagan_Log(DEBUG,"[%s, line %d] [%d] Updated via \"set_srcport\" for xbit \"%s\". Nex expire time is %d (%d) [ %s:%d -> %s:%d ]", __FILE__, __LINE__, a, rulestruct[rule_position].xbit_name[i], xbit_ipc[i].flexbit_expire, rulestruct[rule_position].xbit_timeout[i], xbit_ipc[a].ip_src, xbit_ipc[a].src_port, xbit_ipc[a].ip_dst, xbit_ipc[a].dst_port);

                                        }

                                    pthread_mutex_unlock(&Flexbit_Mutex);
                                    File_Unlock(config->shm_xbit);

                                    xbit_match = true;
                                }

                        }


                    /* If the xbit isn't in memory,  store it to be created later */

                    if ( xbit_match == false )
                        {

                            xbit_track = ( _Sagan_Flexbit_Track * ) realloc(xbit_track, (xbit_track_count+1) * sizeof(_Sagan_Flexbit_Track));

                            if ( xbit_track == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for xbit_track. Abort!", __FILE__, __LINE__);
                                }

                            memset(&xbit_track[xbit_track_count], 0, sizeof(_Sagan_Flexbit_Track));

                            strlcpy(xbit_track[xbit_track_count].flexbit_name, rulestruct[rule_position].xbit_name[i], sizeof(xbit_track[xbit_track_count].flexbit_name));
                            strlcpy(xbit_ipc[xbit_track_count].syslog_message, syslog_message, sizeof(xbit_ipc[xbit_track_count].syslog_message));
                            xbit_track[xbit_track_count].flexbit_timeout = rulestruct[rule_position].xbit_timeout[i];
                            xbit_track[xbit_track_count].flexbit_srcport = src_port;
                            xbit_track[xbit_track_count].flexbit_dstport = config->sagan_port;
                            xbit_track_count++;

                        }

                } /* if xbit_type == 5 */

            /***************************
             *      SET_DSTPORT        *
            ****************************/

            else if ( rulestruct[rule_position].xbit_type[i] == 6 )
                {

                    xbit_match = false;

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {
                            /* Short circuit if no selector match */

                            if (
                                ( selector == NULL && xbit_ipc[a].selector[0] != '\0') ||
                                ( selector != NULL && 0 != strcmp(selector, xbit_ipc[a].selector))
                            )
                                {

                                    continue;
                                }

                            /* Do we have the xbit already in memory?  If so,  update the information */

                            if (!strcmp(xbit_ipc[a].flexbit_name, rulestruct[rule_position].xbit_name[i]) &&
                                    !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                    !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                    xbit_ipc[a].src_port == config->sagan_port &&
                                    xbit_ipc[a].dst_port == dst_port )
                                {

                                    File_Lock(config->shm_xbit);
                                    pthread_mutex_lock(&Flexbit_Mutex);

                                    xbit_ipc[a].flexbit_date = atol(timet);
                                    xbit_ipc[a].flexbit_expire = atol(timet) + rulestruct[rule_position].xbit_timeout[i];
                                    xbit_ipc[a].flexbit_state = true;
                                    strlcpy(xbit_ipc[a].syslog_message, syslog_message, sizeof(xbit_ipc[a].syslog_message));

                                    if ( debug->debugflexbit)
                                        {

                                            Sagan_Log(DEBUG,"[%s, line %d] [%d] Updated via \"set_dstport\" for xbit \"%s\". Nex expire time is %d (%d) [ %s:%d -> %s:%d ]", __FILE__, __LINE__, a, rulestruct[rule_position].xbit_name[i], xbit_ipc[i].flexbit_expire, rulestruct[rule_position].xbit_timeout[i], xbit_ipc[a].ip_src, xbit_ipc[a].src_port, xbit_ipc[a].ip_dst, xbit_ipc[a].dst_port);

                                        }

                                    pthread_mutex_unlock(&Flexbit_Mutex);
                                    File_Unlock(config->shm_xbit);

                                    xbit_match = true;
                                }

                        }


                    /* If the xbit isn't in memory,  store it to be created later */

                    if ( xbit_match == false )
                        {

                            xbit_track = ( _Sagan_Flexbit_Track * ) realloc(xbit_track, (xbit_track_count+1) * sizeof(_Sagan_Flexbit_Track));

                            if ( xbit_track == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for xbit_track. Abort!", __FILE__, __LINE__);
                                }

                            memset(&xbit_track[xbit_track_count], 0, sizeof(_Sagan_Flexbit_Track));

                            strlcpy(xbit_track[xbit_track_count].flexbit_name, rulestruct[rule_position].xbit_name[i], sizeof(xbit_track[xbit_track_count].flexbit_name));
                            strlcpy(xbit_ipc[xbit_track_count].syslog_message, syslog_message, sizeof(xbit_ipc[xbit_track_count].syslog_message));
                            xbit_track[xbit_track_count].flexbit_timeout = rulestruct[rule_position].xbit_timeout[i];
                            xbit_track[xbit_track_count].flexbit_srcport = config->sagan_port;
                            xbit_track[xbit_track_count].flexbit_dstport = dst_port;
                            xbit_track_count++;

                        }

                } /* if xbit_type == 6 */

            /*************************
             *      SET_PORTS        *
            **************************/

            else if ( rulestruct[rule_position].xbit_type[i] == 7 )
                {

                    xbit_match = false;

                    for (a = 0; a < counters_ipc->flexbit_count; a++)
                        {
                            /* Short circuit if no selector match */

                            if (
                                ( selector == NULL && xbit_ipc[a].selector[0] != '\0') ||
                                ( selector != NULL && 0 != strcmp(selector, xbit_ipc[a].selector))
                            )
                                {

                                    continue;
                                }

                            /* Do we have the xbit already in memory?  If so,  update the information */

                            if (!strcmp(xbit_ipc[a].flexbit_name, rulestruct[rule_position].xbit_name[i]) &&
                                    !memcmp(xbit_ipc[a].ip_src, ip_src, sizeof(xbit_ipc[a].ip_src)) &&
                                    !memcmp(xbit_ipc[a].ip_dst, ip_dst, sizeof(xbit_ipc[a].ip_dst)) &&
                                    xbit_ipc[a].src_port == src_port &&
                                    xbit_ipc[a].dst_port == dst_port )
                                {

                                    File_Lock(config->shm_xbit);
                                    pthread_mutex_lock(&Flexbit_Mutex);

                                    xbit_ipc[a].flexbit_date = atol(timet);
                                    xbit_ipc[a].flexbit_expire = atol(timet) + rulestruct[rule_position].xbit_timeout[i];
                                    xbit_ipc[a].flexbit_state = true;
                                    strlcpy(xbit_ipc[a].syslog_message, syslog_message, sizeof(xbit_ipc[a].syslog_message));

                                    if ( debug->debugflexbit)
                                        {

                                            Sagan_Log(DEBUG,"[%s, line %d] [%d] Updated via \"set_ports\" for xbit \"%s\". Nex expire time is %d (%d) [ %s:%d -> %s:%d ]", __FILE__, __LINE__, a, rulestruct[rule_position].xbit_name[i], xbit_ipc[i].flexbit_expire, rulestruct[rule_position].xbit_timeout[i], xbit_ipc[a].ip_src, xbit_ipc[a].src_port, xbit_ipc[a].ip_dst, xbit_ipc[a].dst_port);

                                        }

                                    pthread_mutex_unlock(&Flexbit_Mutex);
                                    File_Unlock(config->shm_xbit);

                                    xbit_match = true;
                                }

                        }


                    /* If the xbit isn't in memory,  store it to be created later */

                    if ( xbit_match == false )
                        {

                            xbit_track = ( _Sagan_Flexbit_Track * ) realloc(xbit_track, (xbit_track_count+1) * sizeof(_Sagan_Flexbit_Track));

                            if ( xbit_track == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for xbit_track. Abort!", __FILE__, __LINE__);
                                }

                            memset(&xbit_track[xbit_track_count], 0, sizeof(_Sagan_Flexbit_Track));

                            strlcpy(xbit_track[xbit_track_count].flexbit_name, rulestruct[rule_position].xbit_name[i], sizeof(xbit_track[xbit_track_count].flexbit_name));
                            strlcpy(xbit_ipc[xbit_track_count].syslog_message, syslog_message, sizeof(xbit_ipc[xbit_track_count].syslog_message));
                            strlcpy(xbit_ipc[xbit_track_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(xbit_ipc[xbit_track_count].signature_msg));
                            xbit_ipc[xbit_track_count].sid = rulestruct[rule_position].s_sid;

                            xbit_track[xbit_track_count].flexbit_timeout = rulestruct[rule_position].xbit_timeout[i];
                            xbit_track[xbit_track_count].flexbit_srcport = src_port;
                            xbit_track[xbit_track_count].flexbit_dstport = dst_port;
                            xbit_track_count++;

                        }

                } /* if xbit_type == 7 */

        } /* Out of for i loop */

    /* Do we have any xbits in memory that need to be created?  */

    if ( xbit_track_count != 0 )
        {

            for (i = 0; i < xbit_track_count; i++)
                {

                    if ( Clean_IPC_Object(XBIT) == 0 )
                        {

                            File_Lock(config->shm_xbit);
                            pthread_mutex_lock(&Flexbit_Mutex);

                            memcpy(xbit_ipc[counters_ipc->flexbit_count].ip_src, ip_src, sizeof(xbit_ipc[counters_ipc->flexbit_count].ip_src));
                            memcpy(xbit_ipc[counters_ipc->flexbit_count].ip_dst, ip_dst, sizeof(xbit_ipc[counters_ipc->flexbit_count].ip_dst));

                            selector == NULL ? xbit_ipc[counters_ipc->flexbit_count].selector[0] = '\0' : strlcpy(xbit_ipc[counters_ipc->flexbit_count].selector, selector, MAXSELECTOR);

                            xbit_ipc[counters_ipc->flexbit_count].src_port = xbit_track[i].flexbit_srcport;
                            xbit_ipc[counters_ipc->flexbit_count].dst_port = xbit_track[i].flexbit_dstport;
                            xbit_ipc[counters_ipc->flexbit_count].flexbit_date = atol(timet);
                            xbit_ipc[counters_ipc->flexbit_count].flexbit_expire = atol(timet) + xbit_track[i].flexbit_timeout;
                            xbit_ipc[counters_ipc->flexbit_count].flexbit_state = true;
                            xbit_ipc[counters_ipc->flexbit_count].expire = xbit_track[i].flexbit_timeout;

                            strlcpy(xbit_ipc[counters_ipc->flexbit_count].flexbit_name, xbit_track[i].flexbit_name, sizeof(xbit_ipc[counters_ipc->flexbit_count].flexbit_name));
                            strlcpy(xbit_ipc[counters_ipc->flexbit_count].signature_msg, rulestruct[rule_position].s_msg, sizeof(xbit_ipc[counters_ipc->flexbit_count].signature_msg));
                            strlcpy(xbit_ipc[counters_ipc->flexbit_count].syslog_message, syslog_message, sizeof(xbit_ipc[counters_ipc->flexbit_count].syslog_message));
                            xbit_ipc[counters_ipc->flexbit_count].sid = rulestruct[rule_position].s_sid;


                            if ( debug->debugflexbit)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] [%d] Created xbit \"%s\" via \"set, set_srcport, set_dstport, or set_ports\" [%s:%d -> %s:%d]", __FILE__, __LINE__, counters_ipc->flexbit_count, xbit_ipc[counters_ipc->flexbit_count].flexbit_name, ip_src, xbit_track[i].flexbit_srcport, ip_dst, xbit_track[i].flexbit_dstport);
                                }

                            File_Lock(config->shm_counters);

                            counters_ipc->flexbit_count++;

                            File_Unlock(config->shm_counters);
                            File_Unlock(config->shm_xbit);

                            pthread_mutex_unlock(&Flexbit_Mutex);

                        }
                }
        }

    free(xbit_track);

} /* End of Xbit_Set */

/*****************************************************************************
 * Xbit_Cleanup - Find "expired" xbits and toggle the "state"
 * to "off"
 *****************************************************************************/

void Flexbit_Cleanup_MMAP(void)
{

    int i = 0;

    time_t t;
    struct tm *now;
    char  timet[20];

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    for (i=0; i<counters_ipc->flexbit_count; i++)
        {

            if (  xbit_ipc[i].flexbit_state == true && atol(timet) >= xbit_ipc[i].flexbit_expire )
                {
                    if (debug->debugflexbit)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Setting xbit %s to \"expired\" state.", __FILE__, __LINE__, xbit_ipc[i].flexbit_name);
                        }
                    xbit_ipc[i].flexbit_state = false;
                }
        }

}
