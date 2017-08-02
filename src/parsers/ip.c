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

sbool Parse_IP( char *syslogmessage, int pos, char *str, size_t size )
{

    sbool last_is_host = false;
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;

    int rc = -1;
    sbool ret = 0;
    int current_pos = 0;

    char ctmp = '\0';

    char *tok=NULL;
    char *ptmp=NULL;
    char *stmp=NULL;
    char *etmp=NULL;
    char *letmp=NULL;

    // Just use the existing message, if no space use the whole message
    ptmp = strtok_r(syslogmessage, " ", &tok);
    if (ptmp == NULL) {
        ptmp = syslogmessage;
    }

    stmp = ptmp;
    while (ptmp != NULL) {
        // If we have no '.' or ':' can't be an address.
        // The next token will be skipped to at the end
        if ((strstr(ptmp, ".") || strstr(ptmp, ":"))) {
            // Can't start with a '.', let's get to possible starting chars
            while (
                    stmp[0] != '\0' &&
                    stmp[0] != ':' &&
                    (stmp[0] < '0' || stmp[0] > '9') &&
                    (stmp[0] < 'A' || stmp[0] > 'F') &&
                    (stmp[0] < 'a' || stmp[0] > 'f')
            ) {
                stmp++;
                continue;
            }

            // If we ended with a NULL then we are done with this token
            if (stmp[0] == '\0') {
                break;
            }

            // Store the last match so we can get the longest match
            letmp = NULL;
            etmp = stmp;
            // Try each char until we get a non-match
            while (
                     etmp[0] == ':' ||
                     etmp[0] == '.' ||
                    (etmp[0] >= '0' && etmp[0] <= '9') ||
                    (etmp[0] >= 'A' && etmp[0] <= 'F') ||
                    (etmp[0] >= 'a' && etmp[0] <= 'f')
            ) {
                etmp++;

                if (Starts_With(stmp, "127.0.0.1") || Starts_With(stmp, "::1")) {
                    letmp = NULL;
                    last_is_host = true;
                    break;
                }

                // Just re-use the string to save a copy, put a NULL byte then put back the previous byte
                ctmp = etmp[0];
                etmp[0] = '\0';

                // Use getaddrinfo so we can get ipv4 or 6
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_flags = AI_PASSIVE|AI_NUMERICHOST;

                rc = getaddrinfo(stmp, NULL, &hints, &result);
                etmp[0] = ctmp;

                // If it was a match and ipv4 or ipv6, save it as the longest match
                if (0 == rc && (
                            ((struct sockaddr_storage *)result->ai_addr)->ss_family == AF_INET6 ||
                            ((struct sockaddr_storage *)result->ai_addr)->ss_family == AF_INET)
                    
                   ) {
                    letmp = etmp;
                }
            }
            // If we finished matching in the token and have a match, check the position
            if ((last_is_host || NULL != letmp) && ++current_pos == pos) {
                ret = true;
                if (last_is_host) {
                    strncpy(str, config->sagan_host, size);
                } else {
                    ctmp = letmp[0];
                    letmp[0] = '\0';
                    strncpy(str, stmp, size);
                    letmp[0] = ctmp;
                }
                break;
            } else if (NULL != letmp) {
                last_is_host = false;
            }
            // Otherwise, start and next char in token and go again
            stmp++;
            etmp=stmp;
            continue;
        }

        // Move to next token
        ptmp = strtok_r(NULL, " ", &tok);
        stmp = ptmp;
    }

    return ret;
}

