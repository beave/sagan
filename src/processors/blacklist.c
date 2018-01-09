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

#include "processors/blacklist.h"

#include "parsers/parsers.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _Sagan_Blacklist *SaganBlacklist;

pthread_mutex_t    CounterBlacklistGenericMutex=PTHREAD_MUTEX_INITIALIZER;

/****************************************************************************
 * Sagan_Blacklist_Init - Init any global memory structures we might need
 ****************************************************************************/

void Sagan_Blacklist_Init ( void )
{

    pthread_mutex_lock(&CounterBlacklistGenericMutex);
    counters->blacklist_count=0;
    pthread_mutex_unlock(&CounterBlacklistGenericMutex);

    SaganBlacklist = malloc(sizeof(_Sagan_Blacklist));

    if ( SaganBlacklist == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBlacklist. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBlacklist, 0, sizeof(_Sagan_Blacklist));

}

/****************************************************************************
 * Sagan_Blacklist_Load - Loads 32 bit IP addresses into memory so that they
 * can be queried later
 ****************************************************************************/

void Sagan_Blacklist_Load ( void )
{

    FILE *blacklist;
    char *tok=NULL;
    char *tmpmask=NULL;
    char tmp[1024] = { 0 };
    int mask = 0;
    char *iprange=NULL;
    char blacklistbuf[1024] = { 0 };
    char *blacklist_filename = NULL;
    char *ptmp = NULL;

    unsigned char ipbits[MAXIPBIT] = { 0 };
    unsigned char maskbits[MAXIPBIT]= { 0 };

    int line_count;
    int i;

    sbool found = 0;

    pthread_mutex_lock(&CounterBlacklistGenericMutex);
    counters->blacklist_count=0;
    pthread_mutex_unlock(&CounterBlacklistGenericMutex);

    blacklist_filename = strtok_r(config->blacklist_files, ",", &ptmp);

    while ( blacklist_filename != NULL )
        {

            Sagan_Log(S_NORMAL, "Blacklist Processor Loading File: %s.", blacklist_filename);


            if (( blacklist = fopen(blacklist_filename, "r" )) == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Could not load blacklist file! (%s - %s)", __FILE__, __LINE__, blacklist_filename, strerror(errno));
                }


            line_count = 0;

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
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBlacklist. Abort!", __FILE__, __LINE__);
                                }

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
                                }
                            else
                                {
                                    mask = atoi(tmpmask);
                                }

                            /* Should do better error checking? */

                            found = 0;

                            if ( iprange == NULL )
                                {

                                    Sagan_Log(S_ERROR, "[%s, line %d] Invalid range in %s at line %d, skipping....", __FILE__, __LINE__, blacklist_filename, line_count);
                                    found = 1;
                                }

                            if ( mask == 0 || !Mask2Bit(mask, maskbits))
                                {

                                    Sagan_Log(S_ERROR, "[%s, line %d] Invalid mask in %s at line %d, skipping....", __FILE__, __LINE__, blacklist_filename, line_count);
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
                                            Sagan_Log(S_WARN, "[%s, line %d] Got invalid blacklist address %s/%s in %s on line %d, skipping....", __FILE__, __LINE__, iprange, tmpmask, blacklist_filename, line_count);
                                            found = 1;
                                        }
                                    else
                                        {
                                            for ( i = 0; i < counters->blacklist_count; i++ )
                                                {

                                                    if ( !memcmp(SaganBlacklist[i].range.ipbits, ipbits, sizeof(ipbits)) &&
                                                            !memcmp(SaganBlacklist[i].range.maskbits, maskbits, sizeof(maskbits)))
                                                        {
                                                            Sagan_Log(S_WARN, "[%s, line %d] Got duplicate blacklist address %s/%s in %s on line %d, skipping....", __FILE__, __LINE__, iprange, tmpmask, blacklist_filename, line_count);
                                                            found = 1;
                                                        }
                                                }
                                        }
                                }

                            if ( found == 0 )
                                {

                                    memcpy(SaganBlacklist[counters->blacklist_count].range.ipbits, ipbits, sizeof(ipbits));
                                    memcpy(SaganBlacklist[counters->blacklist_count].range.maskbits, maskbits, sizeof(maskbits));

                                    pthread_mutex_lock(&CounterBlacklistGenericMutex);
                                    counters->blacklist_count++;
                                    pthread_mutex_unlock(&CounterBlacklistGenericMutex);

                                }
                        }
                }

            fclose(blacklist);
            blacklist_filename = strtok_r(NULL, ",", &ptmp);

        }

}


/***************************************************************************
 * Sagan_Blacklist_IPADDR - Looks up the IP address in the Blacklist
 * array.  If found,  returns TRUE.
 ***************************************************************************/

sbool Sagan_Blacklist_IPADDR ( unsigned char *ipaddr )
{

    int i;

    counters->blacklist_lookup_count++;

    for ( i = 0; i < counters->blacklist_count; i++)
        {

            if ( is_inrange(ipaddr, (unsigned char *)&SaganBlacklist[i].range, 1) )
                {

                    pthread_mutex_lock(&CounterBlacklistGenericMutex);
                    counters->blacklist_hit_count++;
                    pthread_mutex_unlock(&CounterBlacklistGenericMutex);

                    return(true);
                }
        }

    return(false);

}

/***************************************************************************
 * Sagan_Blacklist_IPADDR_All - Check all IPv4 addresses against the
 * blacklist IP's in memory!
 ***************************************************************************/

sbool Sagan_Blacklist_IPADDR_All ( char *syslog_message, _Sagan_Lookup_Cache_Entry *lookup_cache, size_t cache_size)
{

    int i;
    int b;

    unsigned char ip[MAXIPBIT] = { 0 };

    for (i = 0; i < cache_size; i++)
        {

            /* Failed to find next IP,  short circuit the process */
            if (( lookup_cache[i].searched && lookup_cache[i].offset == 0 ) || !Parse_IP(syslog_message, i+1, NULL, sizeof(lookup_cache[i].ip), lookup_cache, cache_size))
                {
                    return(false);
                }

            if (!IP2Bit(lookup_cache[i].ip, ip))
                {
                    continue;
                }

            pthread_mutex_lock(&CounterBlacklistGenericMutex);
            counters->blacklist_lookup_count++;
            pthread_mutex_unlock(&CounterBlacklistGenericMutex);

            for ( b = 0; b < counters->blacklist_count; b++ )
                {
                    if ( is_inrange(ip, (unsigned char *)&SaganBlacklist[b].range, 1) )

                        {

                            pthread_mutex_lock(&CounterBlacklistGenericMutex);
                            counters->blacklist_hit_count++;
                            pthread_mutex_unlock(&CounterBlacklistGenericMutex);

                            return(true);
                        }
                }

        }

    return(false);
}

