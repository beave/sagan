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

/* blacklist.c
*
* This searches log lines for IP addresses/networks that are loaded
* from a "blacklist" file.  For example,  you might search log lines for
* known bad IP/Networks.  This processor uses the CIDR format:
* 192.168.1.1/32 (single ip) or 192.168.1.0./24.
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

#include "processors/blacklist.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _Sagan_Blacklist *SaganBlacklist;


/****************************************************************************
 * Sagan_Blacklist_Init - Init any global memory structures we might need
 ****************************************************************************/

void Sagan_Blacklist_Init ( void )
{

    __atomic_store_n(&counters->blacklist_count, 0, __ATOMIC_SEQ_CST);

}

/****************************************************************************
 * Sagan_Blacklist_Load - Loads 32 bit IP addresses into memory so that they
 * can be queried later
 ****************************************************************************/

void Sagan_Blacklist_Load ( void )
{

    FILE *blacklist;
    char *tok = NULL;
    char *tmpmask = NULL;
    char tmp[1024] = { 0 };
    int mask = 0;
    char *iprange=NULL;
    char blacklistbuf[1024] = { 0 };
    char *blacklist_filename = NULL;
    char *ptmp = NULL;

    unsigned char ipbits[MAXIPBIT] = { 0 };
    unsigned char maskbits[MAXIPBIT]= { 0 };

    int line_count;
    int item_count;
    int i;

    bool found = 0;

    __atomic_store_n(&counters->blacklist_count, 0, __ATOMIC_SEQ_CST);

    blacklist_filename = strtok_r(config->blacklist_files, ",", &ptmp);

    Sagan_Log(NORMAL, "");

    while ( blacklist_filename != NULL )
        {

            if (( blacklist = fopen(blacklist_filename, "r" )) == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Could not load blacklist file! (%s - %s)", __FILE__, __LINE__, blacklist_filename, strerror(errno));
                }


            line_count = 0;
            item_count = 0;

            while(fgets(blacklistbuf, 1024, blacklist) != NULL)
                {

                    /* Skip comments and blank linkes */

                    if (blacklistbuf[0] == '#' || blacklistbuf[0] == 10 || blacklistbuf[0] == ';' || blacklistbuf[0] == 32)
                        {
                            line_count++;
                            continue;

                        }
                    else
                        {

                            /* Allocate memory for Blacklists,  not comments */

                            line_count++;

                            SaganBlacklist = (_Sagan_Blacklist *) realloc(SaganBlacklist, (counters->blacklist_count+1) * sizeof(_Sagan_Blacklist));

                            if ( SaganBlacklist == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBlacklist. Abort!", __FILE__, __LINE__);
                                }

                            memset(&SaganBlacklist[counters->blacklist_count], 0, sizeof(_Sagan_Blacklist));

                            Remove_Return(blacklistbuf);

                            iprange = NULL;
                            tmpmask = NULL;

                            iprange = strtok_r(blacklistbuf, "/", &tok);
                            tmpmask = strtok_r(NULL, "/", &tok);

                            if ( tmpmask == NULL )
                                {

                                    /* If there is no CIDR,  then assume it's a /32 */

                                    strlcpy(tmp, iprange, sizeof(tmp));
                                    iprange = tmp;
                                    mask = 32;
                                    tmpmask = "32";
                                }
                            else
                                {
                                    mask = atoi(tmpmask);
                                }

                            /* Should do better error checking? */

                            found = 0;

                            if ( iprange == NULL )
                                {

                                    Sagan_Log(ERROR, "[%s, line %d] Invalid range in %s at line %d, skipping....", __FILE__, __LINE__, blacklist_filename, line_count);
                                    found = 1;
                                }

                            if ( mask == 0 || !Mask2Bit(mask, maskbits))
                                {

                                    Sagan_Log(ERROR, "[%s, line %d] Invalid mask in %s at line %d, skipping....", __FILE__, __LINE__, blacklist_filename, line_count);
                                    found = 1;

                                }

                            /* Record lower and upper range based on the /CIDR.  We then use IP2Bit(ipaddr) to determine
                             * if it's within the blacklist range.
                             *
                             * Idea came from "ashitpro"
                             * http://bytes.com/topic/c/answers/765104-determining-whether-given-ip-exist-cidr-ip-range
                             *
                             */


                            if ( found == 0 )
                                {

                                    if (!IP2Bit(iprange, ipbits))
                                        {

                                            Sagan_Log(WARN, "[%s, line %d] Got invalid blacklist address %s/%s in %s on line %d, skipping....", __FILE__, __LINE__, iprange, tmpmask, blacklist_filename, line_count);
                                            found = 1;

                                        }
                                    else
                                        {
                                            for ( i = 0; i < counters->blacklist_count; i++ )
                                                {

                                                    if ( !memcmp(SaganBlacklist[i].range.ipbits, ipbits, MAXIPBIT ) &&
                                                            !memcmp(SaganBlacklist[i].range.maskbits, maskbits, MAXIPBIT ) )
                                                        {
                                                            Sagan_Log(WARN, "[%s, line %d] Got duplicate blacklist address %s/%s in %s on line %d, skipping....", __FILE__, __LINE__, iprange, tmpmask, blacklist_filename, line_count);
                                                            found = 1;
                                                        }
                                                }
                                        }
                                }

                            if ( found == 0 )
                                {

                                    memcpy(SaganBlacklist[counters->blacklist_count].range.ipbits, ipbits, sizeof(ipbits));
                                    memcpy(SaganBlacklist[counters->blacklist_count].range.maskbits, maskbits, sizeof(maskbits));

                                    item_count++;

                                    __atomic_add_fetch(&counters->blacklist_count, 1, __ATOMIC_SEQ_CST);


                                }
                        }
                }

            fclose(blacklist);

            Sagan_Log(NORMAL, "Blacklist Processor Loaded File: %s (File: %d, Total: %d)", blacklist_filename, item_count, counters->blacklist_count++);

            blacklist_filename = strtok_r(NULL, ",", &ptmp);

        }

}


/***************************************************************************
 * Sagan_Blacklist_IPADDR - Looks up the IP address in the Blacklist
 * array.  If found,  returns TRUE.
 ***************************************************************************/

bool Sagan_Blacklist_IPADDR ( unsigned char *ipaddr )
{

    int i = 0;

    counters->blacklist_lookup_count++;

    for ( i = 0; i < counters->blacklist_count; i++)
        {

            if ( is_inrange(ipaddr, (unsigned char *)&SaganBlacklist[i].range, 1) )
                {

                    __atomic_add_fetch(&counters->blacklist_hit_count, 1, __ATOMIC_SEQ_CST);

                    return(true);
                }
        }

    return(false);

}

/***************************************************************************
 * Sagan_Blacklist_IPADDR_All - Check all IPv4 addresses against the
 * blacklist IP's in memory!
 ***************************************************************************/

bool Sagan_Blacklist_IPADDR_All ( char *syslog_message, _Sagan_Lookup_Cache_Entry *lookup_cache, int lookup_cache_size )
{

    int i;
    int b;

    for (i = 0; i < lookup_cache_size; i++)
        {

            for ( b = 0; b < counters->blacklist_count; b++ )
                {

                    if ( is_inrange(lookup_cache[i].ip_bits, (unsigned char *)&SaganBlacklist[b].range, 1) )
                        {

                            __atomic_add_fetch(&counters->blacklist_hit_count, 1, __ATOMIC_SEQ_CST);

                            return(true);
                        }
                }

        }

    return(false);
}

