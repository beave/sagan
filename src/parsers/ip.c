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
** but WITHOUT ANY WARRANTY; withstr even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* ip.c
 *
 * Simple method of "finding" the "real" IP address from a syslog message.  This
 * works with OpenSSH and messages of that nature.  An example message might be:
 * "Invalid login from 12.145.241.50".  This will pull the 12.145.241.50.  This
 * is part of the "parse_ip" Sagan rules flag.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "version.h"
#include "parsers/parsers.h"

struct _SaganConfig *config;

sbool Parse_IP( char *syslogmessage, int pos, char *str, size_t size, _Sagan_Lookup_Cache_Entry *lookup_cache, size_t cache_size)
{

    struct addrinfo hints = {0};
    char toparse[MAX_SYSLOGMSG];
    struct addrinfo *result = NULL;

    int i;
    sbool ret = 0;
    int num_dots = 0;
    int real_pos = pos;
    int num_colons = 0;
    int current_pos = 0;
    sbool valid = false;

    char *tok=NULL;
    char *stmp=NULL;
    char *etmp=NULL;
    char *ptmp=NULL;
    char *pstmp=NULL;
    char *petmp=NULL;

    char ctmp = '\0';

    ptrdiff_t offset = 0;

    if (NULL != lookup_cache && pos <= cache_size) {
        lookup_cache[pos-1].searched = true;
    }

    if (NULL != lookup_cache && pos > 1 && pos <= cache_size && lookup_cache[pos-2].searched) {
        offset = lookup_cache[pos-2].offset;
        strlcpy(toparse, syslogmessage+offset, MAX_SYSLOGMSG);
        pos = 1;
    } else {
        strlcpy(toparse, syslogmessage, MAX_SYSLOGMSG);
    }

    str[0] = '\0';

    // Just use the existing message, if no space use the whole message
    stmp = strtok_r(toparse, " ", &tok);
    if (stmp == NULL) {
        stmp = toparse;
    }

    // Use getaddrinfo so we can get ipv4 or 6
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE|AI_NUMERICHOST;

    // Can't start after the the last ':' or '.'
    pstmp = strrpbrk(stmp, ":.");
    while (stmp != NULL) {
        // If we have no '.' or ':' can't be an address.
        // The next token will be skipped to at the end
        if (NULL == pstmp || stmp[0] == '\0' || stmp > pstmp) {
            // Move to next token
            stmp = strtok_r(NULL, " ", &tok);
            if(stmp) {
                // Can't start after the the last ':' or '.'
                pstmp = strrpbrk(stmp, ":.");
            }
        } else {
            // Can't start with a '.', skip ahead to first possible starting char
            stmp += strcspn(stmp, ":ABCDEFabcdef0123456789");

            // If we ended with a NULL or past what could be valid, then we are done with this token
            if (stmp[0] == '\0' || stmp > pstmp) {
                continue;
            }
            // Get Max length
            etmp = stmp + strspn(stmp, ":ABCDEFabcdef0123456789.");  

            // Compute the last place we could end at and still have at least 2 ':' or 3 '.'
            ptmp = stmp;
            num_dots = 0;
            petmp = NULL;
            num_colons = 0;
            while(ptmp < etmp && num_colons < 2 && num_dots < 3) {
                if ((ptmp[0] == ':' && ++num_colons >= 2) || (ptmp[0] == '.' && ++num_dots >= 3)) {
                    petmp = ptmp;
                } 
                ptmp++;
            }

            // If it's not possible to have at least 2 ':' or 3 '.' then move the start of the token to 
            //   the end of our span 
            if (NULL == petmp) {
                stmp=etmp-1;
                valid = false;
            } else {
                // Keep trying the longest string in the span until we match or move past ending in a viable spot
                do {
                    ctmp = etmp[0];
                    etmp[0] = '\0';
                    valid = 0 == getaddrinfo(stmp, NULL, &hints, &result) && (
                            ((struct sockaddr_storage *)result->ai_addr)->ss_family == AF_INET6 ||
                            ((struct sockaddr_storage *)result->ai_addr)->ss_family == AF_INET);
                    etmp[0] = ctmp;
                    if (NULL != result) {
                        freeaddrinfo(result);
                        result = NULL;
                    }
                } while(!valid && --etmp >= petmp);
            }

            if (valid) {
                ctmp = etmp[0];
                etmp[0] = '\0';

                if (lookup_cache) {
                    lookup_cache[current_pos+(real_pos-pos)].searched = true;
                    if (0 == strcmp(stmp, "127.0.0.1") ||
                        0 == strcmp(stmp, "::1") ||
                        0 == strcmp(stmp, "::ffff:127.0.0.1")) { 
                        strlcpy(lookup_cache[current_pos+(real_pos-pos)].ip, config->sagan_host, size);
                    } else{
                        strlcpy(lookup_cache[current_pos+(real_pos-pos)].ip, stmp, size);
                    }
                    lookup_cache[current_pos+(real_pos-pos)].offset = (ptrdiff_t)(etmp - &toparse[0]) + offset;
                }

                if (++current_pos == pos) {
                    ret = true;
                    if (NULL != str) {
                        strlcpy(str, lookup_cache[current_pos+(real_pos-pos)].ip, size);
                    }
                    break;
                }

                // Since this is a longest string valid match, just skip past it
                stmp += strlen(stmp);

                // We only have to put it back if we are not done
                etmp[0] = ctmp;

            } else {
                // Otherwise, start at next char in token and go again
                stmp++;
            }

        }

    }

    if (NULL != result) {
        freeaddrinfo(result);
        result = NULL;
    }

    if (false == ret && NULL != lookup_cache) {
        for(i=pos-1; i < cache_size;i++) {
            lookup_cache[i].searched = true;
        }
    }

    return ret;
}

