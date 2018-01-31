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

//    struct addrinfo hints = {0};
//    struct addrinfo *result = NULL;
    struct sockaddr_in sa;

    char toparse[MAX_SYSLOGMSG];

    int i;
    sbool ret = 0;
    int num_dots = 0;
    int real_pos = pos;
    int num_colons = 0;
    int current_pos = 0;
    sbool valid = false;
    sbool is_host = false;

    char *tok=NULL;
    char *stmp=NULL;
    char *etmp=NULL;
    char *ptmp=NULL;
    char *pstmp=NULL;
    char *petmp=NULL;

    char ctmp = '\0';

    ptrdiff_t offset = 0;

    if (lookup_cache != NULL && pos <= cache_size)
        {
            lookup_cache[pos-1].searched = true;
        }

    if (lookup_cache != NULL && pos > 1 && pos <= cache_size && lookup_cache[pos-2].searched)
        {
            offset = lookup_cache[pos-2].offset;
            strlcpy(toparse, syslogmessage+offset, MAX_SYSLOGMSG);
            pos = 1;
        }
    else
        {
            strlcpy(toparse, syslogmessage, MAX_SYSLOGMSG);
        }

    if (str != NULL)
        {
            str[0] = '\0';
        }

    /* Just use the existing message, if no space use the whole message */

    stmp = strtok_r(toparse, " ", &tok);
    if (stmp == NULL)
        {
            stmp = toparse;
        }

    /* Use getaddrinfo so we can get ipv4 or 6 */

//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_DGRAM;
//    hints.ai_flags = AI_PASSIVE|AI_NUMERICHOST;

    /* Can't start after the the last ':' or '.' */

    pstmp = strrpbrk(stmp, ":.");
    while (stmp != NULL)
        {
            /* If we have no '.' or ':' can't be an address.
               The next token will be skipped to at the end */

            if (pstmp == NULL || stmp[0] == '\0' || stmp > pstmp)
                {
                    /* Move to next token */

                    stmp = strtok_r(NULL, " ", &tok);
                    if(stmp)
                        {
                            /* Can't start after the the last ':' or '.' */

                            pstmp = strrpbrk(stmp, ":.");
                        }
                }
            else
                {
                    /* Can't start with a '.', skip ahead to first possible starting char */

                    stmp += strcspn(stmp, ":ABCDEFabcdef0123456789");

                    /* If we ended with a NULL or past what could be valid, then we are done with this token */

                    if (stmp[0] == '\0' || stmp > pstmp)
                        {
                            continue;
                        }

                    /* Get Max length */

                    etmp = stmp + strspn(stmp, ":ABCDEFabcdef0123456789.");

                    /* Compute the last place we could end at and still have at least 2 ':' or 3 '.' */

                    ptmp = stmp;
                    num_dots = 0;
                    petmp = NULL;
                    num_colons = 0;
                    while(ptmp < etmp && num_colons < 2 && num_dots < 3)
                        {
                            if ((ptmp[0] == ':' && ++num_colons >= 2) || (ptmp[0] == '.' && ++num_dots >= 3))
                                {
                                    petmp = ptmp;
                                }
                            ptmp++;
                        }

                    /* If it's not possible to have at least 2 ':' or 3 '.' then move the start of the token to
                       the end of our span */

                    if (petmp == NULL)
                        {
                            stmp=etmp-1;
                            valid = false;
                        }
                    else
                        {
                            /* Keep trying the longest string in the span until we match or move past ending in a viable spot */

                            do
                                {
                                    ctmp = etmp[0];
                                    etmp[0] = '\0';

				    /* Kenneth Shelton @netwatcher had this using getaddrinfo.   We kept getting invalid/bad 
                                       results in production. We reverted back to inet_pton and have much better results.  We
				       aren't the only ones:

				       'So, as of 2014, we consider getaddrinfo() to be avoided for IPv6 address conversions under any 
					except the least demanding, single threaded, applications. Within PowerDNS, we have reverted to
					using inet_pton() whenever we can get away with it – which is almost always, except in the
					 case of scoped addresses.'

					See https://blog.powerdns.com/2014/05/21/a-surprising-discovery-on-converting-ipv6-addresses-we-no-longer-prefer-getaddrinfo/

				    */

				    valid =  inet_pton(AF_INET, stmp,  &(sa.sin_addr)) || inet_pton(AF_INET6, stmp,  &(sa.sin_addr));

                                    etmp[0] = ctmp;

                                }
                            while(!valid && --etmp >= petmp);
                        }

                    if (valid)
                        {
                            ctmp = etmp[0];
                            etmp[0] = '\0';

                            is_host = false;

                            /* current_pos is 0 based here and real_pos-pos will give us the delta between
                               what position was requested and where we are starting */

                            if (lookup_cache)
                                {
                                    lookup_cache[current_pos+(real_pos-pos)].searched = true;
                                    if (!strcmp(stmp, "127.0.0.1") ||
                                            !strcmp(stmp, "::1") ||
                                            !strcmp(stmp, "::ffff:127.0.0.1"))
                                        {
                                            is_host = true;
                                            strlcpy(lookup_cache[current_pos+(real_pos-pos)].ip, config->sagan_host, size);
                                        }
                                    else
                                        {
                                            strlcpy(lookup_cache[current_pos+(real_pos-pos)].ip, stmp, size);
                                        }
                                    lookup_cache[current_pos+(real_pos-pos)].offset = (ptrdiff_t)(etmp - &toparse[0]) + offset;
                                }

                            if (++current_pos == pos)
                                {
                                    ret = true;
                                    if (str != NULL)
                                        {
                                            strlcpy(str, is_host ? config->sagan_host : stmp, size);
                                        }
                                    break;
                                }

                            /* Since this is a longest string valid match, just skip past it */

                            stmp += strlen(stmp);

                            /* We only have to put it back if we are not done */

                            etmp[0] = ctmp;

                        }
                    else
                        {
                            /* Otherwise, start at next char in token and go again */

                            stmp++;
                        }

                }

        }

/*
    if (result != NULL)
        {
            freeaddrinfo(result);
            result = NULL;
        }
*/

    if (false == ret && lookup_cache != NULL)
        {
            for(i=pos-1; i < cache_size; i++)
                {
                    lookup_cache[i].searched = true;
                }
        }

    return ret;
}

