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
 * is part of the "parse_src_ip/parse_src_dst" Sagan rules flag.
 *
 * 2018/05/17 - Added a new "cache" system so Sagan doesn't have to repeatedly
 * parse logs.  Support IPv6 and will attempt to pull the port and protocol
 *  if avaliable.
 *
 * What this detects:
 *
 * IPv4
 * -----------------------------------------------------------------------
 *
 * 192.168.2.1				# Stand alone IP
 * 192.168.2.1. 			# Trailing period.
 * [192.168.2.1]			# Or anything like "192.168.2.1", etc
 * 192.168.2.1:1234
 * 192.168.2.1#1234
 * 192.168.2.1 port 1234
 * 192.168.2.1 source port 1234
 * 192.168.2.1 source port: 1234	# Windows style.
 * 192.168.2.1 destination port 1234
 * 192.168.2.1 desitnation port: 1234	# Windows style.
 * 192.168.2.1 client port: 1234        # Windows style
 * 192.168.2.1 client port 1234
 * inet#192.168.2.1
 *
 * IPv6
 * -----------------------------------------------------------------------
 *
 * fe80::b614:89ff:fe11:5e24		# Stand alone IPv6
 * fe80::b614:89ff:fe11:5e24.		# Trailing period.
 * fe80::b614:89ff:fe11:5e24#1234
 * inet#fe80::b614:89ff:fe11:5e24
 * [fe80::b614:89ff:fe11:5e24]:80	# Traditional style.
 * fe80::b614:89ff:fe11:5e24 Client Port: 1234	# Windows
 * fe80::b614:89ff:fe11:5e24 client port 1234
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
#include <pthread.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "version.h"
#include "parsers/parsers.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;

int Parse_IP( char *syslog_message, struct _Sagan_Lookup_Cache_Entry *lookup_cache )
{

    if ( debug->debugparse_ip )
        {
            Sagan_Log(DEBUG, "[%s:%lu] Start Function.", __FUNCTION__, pthread_self() );
        }

    struct sockaddr_in sa;

    int current_position = 0;

    char mod_string[MAX_SYSLOGMSG] = { 0 };

    char tmp_token[64] = { 0 };

    char *ptr1 = NULL;
    char *ptr2 = NULL;

    char *ptr3 = NULL;
    char *ptr4 = NULL;


    char *ip_1 = NULL;
    char *ip_2 = NULL;

    char port_test[6] = { 0 };
    int  port_test_int = 0;

    bool valid = false ;

    int i=0;
    int b=0;

    int num_colons = 0;
    int num_dots = 0;
    int num_hashes = 0;

    int port = config->sagan_port;

    for (i=0; i<strlen(syslog_message); i++)
        {

            /* Remove any ", (, ), etc. In case the IP is enclosed like this:
               "192.168.1.1" or (192.168.1.1) */

            if ( syslog_message[i] != '"' && syslog_message[i] != '(' && syslog_message[i] != ')' &&
                    syslog_message[i] != '[' && syslog_message[i] != ']' && syslog_message[i] != '<' &&
                    syslog_message[i] != '>' && syslog_message[i] != '{' && syslog_message[i] != '}' &&
                    syslog_message[i] != ',' && syslog_message[i] != '/' && syslog_message[i] != '@' &&
                    syslog_message[i] != '=' && syslog_message[i] != '-' && syslog_message[i] != '!' &&
                    syslog_message[i] != '|' && syslog_message[i] != '_' && syslog_message[i] != '+' &&
                    syslog_message[i] != '&' && syslog_message[i] != '%' && syslog_message[i] != '$' &&
                    syslog_message[i] != '~' && syslog_message[i] != '^' && syslog_message[i] != '\'' )
                {

                    mod_string[i] = syslog_message[i];
                    mod_string[i+1] = '\0';

                }
            else
                {

                    mod_string[i] = ' ';
                    mod_string[i+1] = '\0';

                }

        }


    if ( debug->debugparse_ip )
        {
            Sagan_Log(DEBUG, "[%s:%lu] Modified string: %s", __FUNCTION__, pthread_self(), mod_string);
        }

    ptr1 = strtok_r(mod_string, " ", &ptr2);

    while ( ptr1 != NULL )
        {

            num_colons = 0;
            num_dots = 0;
            num_hashes = 0;

            if ( debug->debugparse_ip )
                {
                    Sagan_Log(DEBUG, "[%s:%lu] Token: '%s'", __FUNCTION__, pthread_self(), ptr1 );
                }

            /* Get counts of colons, hashes, dots.  */

            for (i=0; i<strlen(ptr1); i++)
                {

                    switch(ptr1[i])
                        {

                        case(':'):
                            num_colons++;
                            break;

                        case('#'):
                            num_hashes++;
                            break;

                        case('.'):
                            num_dots++;
                            break;

                        }

                }

            valid = false;		/* Reset to not valid */

            if ( debug->debugparse_ip )
                {
                    Sagan_Log(DEBUG, "[%s:%lu] Colons: %d, Dots: %d, Hashes: %d", __FUNCTION__, pthread_self(), num_colons, num_dots, num_hashes );
                }

            if ( !strcasecmp(ptr1, "tcp" ) )
                {

                    if ( debug->debugparse_ip )
                        {
                            Sagan_Log(DEBUG, "[%s:%lu] Protocal TCP detected.", __FUNCTION__, pthread_self() );
                        }

                    lookup_cache[0].proto = 6;
                }

            else if ( !strcasecmp(ptr1, "udp" ) )
                {

                    if ( debug->debugparse_ip )
                        {
                            Sagan_Log(DEBUG, "[%s:%lu] Protocal UDP detected.", __FUNCTION__, pthread_self() );
                        }

                    lookup_cache[0].proto = 17;

                }

            else if ( !strcasecmp(ptr1, "icmp" ) )
                {

                    if ( debug->debugparse_ip )
                        {
                            Sagan_Log(DEBUG, "[%s:%lu] Protocal ICMP detected.", __FUNCTION__, pthread_self() );
                        }

                    lookup_cache[0].proto = 1;

                }


            /* Needs to have proper IPv6 or IPv4 encoding. num_dots > 4 is for IP with trailing
            period. */

            if ( ( num_colons < 2 && num_dots < 3 ) || ( num_dots > 4 ) )
                {

                    if ( debug->debugparse_ip )
                        {
                            Sagan_Log(DEBUG, "[%s:%lu] '%s' can't be an IPv4 or IPv6.", __FUNCTION__, pthread_self(), ptr1 );
                        }

                    ptr1 = strtok_r(NULL, " ", &ptr2);		/* move to next token */
                    continue;
                }


            /* Stand alone IPv4 address */

            if ( num_dots == 3 && num_colons == 0 )
                {

                    valid = inet_pton(AF_INET, ptr1,  &(sa.sin_addr));

                    if ( valid == 1 )
                        {

                            if ( debug->debugparse_ip )
                                {
                                    Sagan_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv4 address '%s' position %d **", __FUNCTION__, pthread_self(), ptr1, current_position );
                                }

                            /* Grab the IP */

                            memcpy(lookup_cache[current_position].ip, ptr1, MAXIP);
                            memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                            IP2Bit(ptr1, lookup_cache[current_position].ip_bits);

                            /* Preserve the array */

                            memcpy(tmp_token, ptr2, sizeof(tmp_token));

                            ptr4 = tmp_token;
                            ptr3 = strtok_r(NULL, " ", &ptr4);

                            /* Look for "192.168.1.1 port 1234" */

                            if ( ptr3 != NULL && strcasestr(ptr3, "port") )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%d] Identified the word 'port'", __FUNCTION__, pthread_self() );
                                        }

                                    ptr3 = strtok_r(NULL, " ", &ptr4);

                                    if ( ptr3 != NULL )
                                        {
                                            port = atoi(ptr3);

                                            if ( port == 0 )
                                                {
                                                    lookup_cache[current_position].port = config->sagan_port;

                                                }
                                            else
                                                {

                                                    lookup_cache[current_position].port = port;

                                                }
                                        }

                                }

                            /* Look for "192.168.1.1 source port: 1234" or
                            "192.168.1.1 source port 1234" */

                            else if ( ptr3 != NULL && ( strcasestr(ptr3, "source") ||
                                                        strcasestr(ptr3, "destination" ) ) )

                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Identified 'source' or 'destination'", __FUNCTION__, pthread_self() );
                                        }

                                    ptr3 = strtok_r(NULL, " ", &ptr4);

                                    if ( ptr3 != NULL && strcasestr(ptr3, "port" ) )
                                        {

                                            if ( debug->debugparse_ip )
                                                {
                                                    Sagan_Log(DEBUG, "[%s:%lu] Identified 'port'.", __FUNCTION__, pthread_self() );
                                                }

                                            ptr3 = strtok_r(NULL, " ", &ptr4);

                                            if ( ptr3 != NULL )
                                                {

                                                    port = atoi(ptr3);

                                                    if ( port == 0 )
                                                        {

                                                            lookup_cache[current_position].port = config->sagan_port;

                                                        }
                                                    else
                                                        {

                                                            lookup_cache[current_position].port = port;
                                                        }


                                                }

                                        }

                                }

                            /* Look's for 192.168.1.1 client port 1234 */

                            else if ( ptr3 != NULL && strcasestr(ptr3, "client") )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Identified 'client'", __FUNCTION__, pthread_self() );
                                        }

                                    ptr3 = strtok_r(NULL, " ", &ptr4);

                                    if ( ptr3 != NULL && strcasestr(ptr3, "port" ) )
                                        {

                                            if ( debug->debugparse_ip )
                                                {
                                                    Sagan_Log(DEBUG, "[%s:%lu] Identified 'port'.", __FUNCTION__, pthread_self() );
                                                }

                                            ptr3 = strtok_r(NULL, " ", &ptr4);

                                            if ( ptr3 != NULL )
                                                {

                                                    port = atoi(ptr3);

                                                    if ( port == 0 )
                                                        {

                                                            lookup_cache[current_position].port = config->sagan_port;

                                                        }
                                                    else
                                                        {

                                                            lookup_cache[current_position].port = port;
                                                        }


                                                }

                                        }

                                }


                            lookup_cache[current_position].status = 1;
                            current_position++;

                            /* If we've run to the end, we're done */

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }

                        }

                }

            /* Stand alone IPv4 with trailing period */

            if ( num_dots == 4 && ptr1[ strlen(ptr1)-1 ] == '.' )
                {

                    /* Erase the period */

                    ptr1[ strlen(ptr1)-1 ] = '\0';

                    valid = inet_pton(AF_INET, ptr1,  &(sa.sin_addr));

                    if ( valid == 1 )
                        {

                            if ( debug->debugparse_ip )
                                {
                                    Sagan_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv4 address '%s' with trailing period. **", __FUNCTION__, pthread_self(), ptr1 );
                                }

                            memcpy(lookup_cache[current_position].ip, ptr1, MAXIP);
                            memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                            IP2Bit(ptr1, lookup_cache[current_position].ip_bits);
                            lookup_cache[current_position].port = config->sagan_port;
                            lookup_cache[current_position].status = 1;

                            current_position++;

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }


                        }

                }

            /* IPv4 with 192.168.2.1:12345 or inet:192.168.2.1 */

            if ( num_colons == 1 && num_dots == 3)
                {

                    /* test both sides */

                    ip_1 = strtok_r(ptr1, ":", &ip_2);

                    if ( ip_1 != NULL )
                        {
                            valid = inet_pton(AF_INET, ip_1,  &(sa.sin_addr));
                        }

                    if ( valid == 1 )
                        {

                            if ( debug->debugparse_ip )
                                {
                                    Sagan_Log(DEBUG, "[%s:%lu] ** Identified IPv4:PORT address. **", __FUNCTION__, pthread_self() );
                                }

                            memcpy(lookup_cache[current_position].ip, ip_1, MAXIP);
                            memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                            IP2Bit(ip_1, lookup_cache[current_position].ip_bits);

                            /* In many cases, the port is after the : */

                            port = atoi(ip_2);

                            if ( port == 0 )
                                {
                                    lookup_cache[current_position].port = config->sagan_port;
                                }
                            else
                                {
                                    lookup_cache[current_position].port = port;
                                }

                            lookup_cache[current_position].status = 1;
                            current_position++;

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }

                        }

                    if ( ip_2 != NULL )
                        {
                            valid = inet_pton(AF_INET, ip_2,  &(sa.sin_addr));
                        }

                    if ( valid == 1 )

                        {

                            if ( debug->debugparse_ip )
                                {
                                    Sagan_Log(DEBUG, "[%s:%lu] ** Identified INTERFACE:IPv4 **", __FUNCTION__, pthread_self() );
                                }

                            memcpy(lookup_cache[current_position].ip, ip_2, MAXIP);
                            memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                            IP2Bit(ip_2, lookup_cache[current_position].ip_bits);
                            lookup_cache[current_position].port = config->sagan_port;
                            lookup_cache[current_position].status = 1;

                            current_position++;

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }

                        }

                }

            /* Handle 192.168.2.1#12345 or inet#192.168.2.1 */

            if ( num_hashes == 1 && num_dots == 3)
                {

                    /* test both sides */

                    ip_1 = strtok_r(ptr1, "#", &ip_2);

                    if ( ip_1 != NULL )
                        {
                            valid = inet_pton(AF_INET, ip_1,  &(sa.sin_addr));
                        }

                    if ( valid == 1 )
                        {

                            if ( debug->debugparse_ip )
                                {
                                    Sagan_Log(DEBUG, "[%s:%lu] ** Identified IPv4#PORT **", __FUNCTION__, pthread_self() );
                                }


                            memcpy(lookup_cache[current_position].ip, ip_1, MAXIP);
                            memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                            IP2Bit(ip_1, lookup_cache[current_position].ip_bits);

                            /* In many cases, the port is after the : */

                            port = atoi(ip_2);

                            if ( port == 0 )
                                {
                                    lookup_cache[current_position].port = config->sagan_port;
                                }
                            else
                                {
                                    lookup_cache[current_position].port = port;
                                }

                            lookup_cache[current_position].status = 1;
                            current_position++;

                            /* If we've run to the end, we're done */

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }

                        }

                    if ( ip_2 != NULL )
                        {
                            valid = inet_pton(AF_INET, ip_2,  &(sa.sin_addr));
                        }

                    if ( valid == 1 )

                        {

                            if ( debug->debugparse_ip )
                                {
                                    Sagan_Log(DEBUG, "[%s:%lu] ** Identified INTERFACE#PORT **", __FUNCTION__, pthread_self() );
                                }

                            memcpy(lookup_cache[current_position].ip, ip_2, MAXIP);
                            memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                            IP2Bit(ip_2, lookup_cache[current_position].ip_bits);
                            lookup_cache[current_position].port = config->sagan_port;
                            lookup_cache[current_position].status = 1;

                            current_position++;

                            /* If we've run to the end, we're done */

                            if ( current_position > MAX_PARSE_IP )
                                {
                                    break;
                                }

                        }

                }


            /* Do we even want to part IPv6? */

            if ( config->parse_ip_ipv6 == true )
                {

                    /* Stand alone IPv6 */

                    if ( num_colons > 2 )
                        {

                            valid = inet_pton(AF_INET6, ptr1,  &(sa.sin_addr));

                            if ( valid == 1 )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv6 address '%s' **", __FUNCTION__, pthread_self(), ptr1 );
                                        }

                                    memcpy(lookup_cache[current_position].ip, ptr1, MAXIP);
                                    memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                                    IP2Bit(ptr1, lookup_cache[current_position].ip_bits);

                                    /* This converts ::ffff:192.168.1.1 to regular IPv4 (192.168.1.1) */

                                    if ( config->parse_ip_ipv4_mapped_ipv6 == false )
                                        {

                                            if ( ptr1[0] == ':' && ptr1[1] == ':' && ( ptr1[2] == 'f' || ptr1[2] == 'F' ) &&
                                                    ( ptr1[3] == 'f' || ptr1[3] == 'F' ) && ( ptr1[4] == 'f' || ptr1[4] == 'F' ) &&
                                                    ( ptr1[5] == 'f' || ptr1[5] == 'F' ) && ptr1[6] == ':' )
                                                {

                                                    b = strlen(ptr1);

                                                    for (i = 7; b > i; i++)
                                                        {
                                                            lookup_cache[current_position].ip[i-7] = ptr1[i];
                                                            lookup_cache[current_position].ip[i-6] = '\0';
                                                        }

                                                    memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                                                    IP2Bit(ptr1, lookup_cache[current_position].ip_bits);

                                                }

                                        }

                                    /* Look for "fe80::b614:89ff:fe11:5e24 port 1234" */

                                    memcpy(tmp_token, ptr2, sizeof(tmp_token));

                                    ptr4 = tmp_token;
                                    ptr3 = strtok_r(NULL, " ", &ptr4);

                                    if ( ptr3 != NULL && strcasestr(ptr3, "port") )
                                        {

                                            if ( debug->debugparse_ip )
                                                {
                                                    Sagan_Log(DEBUG, "[%s:%lu] Identified the word 'port'", __FUNCTION__, pthread_self() );
                                                }


                                            ptr3 = strtok_r(NULL, " ", &ptr4);

                                            if ( ptr3 != NULL )
                                                {
                                                    port = atoi(ptr3);

                                                    if ( port == 0 )
                                                        {
                                                            lookup_cache[current_position].port = port;
                                                        }
                                                    else
                                                        {
                                                            lookup_cache[current_position].port = config->sagan_port;
                                                        }

                                                }

                                        }

                                    /* Look for "fe80::b614:89ff:fe11:5e24 source port: 1234" or
                                    "fe80::b614:89ff:fe11:5e24 source port 1234" */

                                    else if ( ptr3 != NULL && ( strcasestr(ptr3, "source") ||
                                                                strcasestr(ptr3, "destination" ) ) )

                                        {

                                            if ( debug->debugparse_ip )
                                                {
                                                    Sagan_Log(DEBUG, "[%s:%lu] Identified the word 'source' or 'destination'", __FUNCTION__, pthread_self() );
                                                }


                                            ptr3 = strtok_r(NULL, " ", &ptr4);

                                            if ( ptr3 != NULL && strcasestr(ptr3, "port" ) )
                                                {

                                                    if ( debug->debugparse_ip )
                                                        {
                                                            Sagan_Log(DEBUG, "[%s:%lu] Identified the word 'port'", __FUNCTION__, pthread_self() );
                                                        }


                                                    ptr3 = strtok_r(NULL, " ", &ptr4);

                                                    if ( ptr3 != NULL )
                                                        {

                                                            port = atoi(ptr3);

                                                            if ( port == 0 )
                                                                {
                                                                    lookup_cache[current_position].port = config->sagan_port;
                                                                }
                                                            else
                                                                {
                                                                    lookup_cache[current_position].port = port;
                                                                }

                                                        }

                                                }

                                        }

                                    /* IPv6 [fe80::b614:89ff:fe11:5e24]:443 */

                                    else if ( ptr3 != NULL && ptr3[0] == ':' )
                                        {

                                            if ( debug->debugparse_ip )
                                                {
                                                    Sagan_Log(DEBUG, "[%s:%lu] Identified possible [IPv6]:PORT", __FUNCTION__, pthread_self() );
                                                }

                                            for ( i = 1; i < strlen(ptr3); i++ )
                                                {
                                                    port_test[i-1] = ptr3[i];
                                                }

                                            port_test_int = atoi(port_test);

                                            if ( port_test_int == 0 )
                                                {
                                                    lookup_cache[current_position].port = config->sagan_port;
                                                }
                                            else
                                                {
                                                    lookup_cache[current_position].port = port_test_int;
                                                }

                                        }

                                    lookup_cache[current_position].status = 1;

                                    current_position++;

                                    if ( current_position > MAX_PARSE_IP )
                                        {
                                            break;
                                        }

                                }

                        }


                    /* Stand alone IPv6 with trailing period */

                    if ( num_colons > 2 && ptr1[ strlen(ptr1)-1 ] == '.' )
                        {

                            /* Erase the period */

                            ptr1[ strlen(ptr1)-1 ] = '\0';

                            valid = inet_pton(AF_INET6, ptr1,  &(sa.sin_addr));

                            if ( valid == 1 )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv6 '%s' with trailing period. **", __FUNCTION__, pthread_self(), ptr1 );
                                        }

                                    memcpy(lookup_cache[current_position].ip, ptr1, MAXIP);
                                    memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                                    IP2Bit(ptr1, lookup_cache[current_position].ip_bits);

                                    /* This converts ::ffff:192.168.1.1 to regular IPv4 (192.168.1.1) */

                                    if ( config->parse_ip_ipv4_mapped_ipv6 == false )
                                        {

                                            if ( ptr1[0] == ':' && ptr1[1] == ':' && ( ptr1[2] == 'f' || ptr1[2] == 'F' ) &&
                                                    ( ptr1[3] == 'f' || ptr1[3] == 'F' ) && ( ptr1[4] == 'f' || ptr1[4] == 'F' ) &&
                                                    ( ptr1[5] == 'f' || ptr1[5] == 'F' ) && ptr1[6] == ':' )
                                                {

                                                    b = strlen(ptr1);

                                                    for (i = 7; b > i; i++)
                                                        {
                                                            lookup_cache[current_position].ip[i-7] = ptr1[i];
                                                            lookup_cache[current_position].ip[i-6] = '\0';
                                                        }

                                                    memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                                                    IP2Bit(ptr1, lookup_cache[current_position].ip_bits);

                                                }

                                        }

                                    lookup_cache[current_position].port = config->sagan_port;
                                    lookup_cache[current_position].status = 1;

                                    current_position++;

                                    if ( current_position > MAX_PARSE_IP )
                                        {
                                            break;
                                        }

                                }

                        }

                    /* Handle IPv6 fe80::b614:89ff:fe11:5e24#12345 or inet#fe80::b614:89ff:fe11:5e24 */

                    if ( num_hashes == 1 && num_colons > 2 )
                        {

                            /* test both sides */

                            ip_1 = strtok_r(ptr1, "#", &ip_2);

                            if ( ip_1 != NULL )
                                {
                                    valid = inet_pton(AF_INET6, ip_1,  &(sa.sin_addr));
                                }

                            if ( valid == 1 )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] ** Identified IPv6#PORT **", __FUNCTION__, pthread_self() );
                                        }


                                    memcpy(lookup_cache[current_position].ip, ip_1, MAXIP);
                                    memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                                    IP2Bit(ip_1, lookup_cache[current_position].ip_bits);

                                    /* In many cases, the port is after the : */

                                    port = atoi(ip_2);

                                    if ( port == 0 )
                                        {
                                            lookup_cache[current_position].port = config->sagan_port;

                                        }
                                    else
                                        {

                                            lookup_cache[current_position].port = port;
                                        }

                                    lookup_cache[current_position].status = 1;
                                    current_position++;

                                    /* If we've run to the end, we're done */

                                    if ( current_position > MAX_PARSE_IP )
                                        {
                                            break;
                                        }

                                }

                            if ( ip_2 != NULL )
                                {
                                    valid = inet_pton(AF_INET6, ip_2,  &(sa.sin_addr));
                                }

                            if ( valid == 1 )

                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] ** Identified INTERFACE#IPv6 **", __FUNCTION__, pthread_self() );
                                        }


                                    memcpy(lookup_cache[current_position].ip, ip_2, MAXIP);
                                    memset(lookup_cache[current_position].ip_bits, 0, MAXIPBIT);
                                    IP2Bit(ip_2, lookup_cache[current_position].ip_bits);
                                    lookup_cache[current_position].port = config->sagan_port;
                                    lookup_cache[current_position].status = 1;

                                    current_position++;

                                    /* If we've run to the end, we're done */

                                    if ( current_position > MAX_PARSE_IP )
                                        {
                                            break;
                                        }


                                }

                        }

                } /* If config->parse_ip_ipv6 */

            ptr1 = strtok_r(NULL, " ", &ptr2);

        }

    for ( i = 0; i < current_position; i++)
        {
            lookup_cache[current_position].status = 0;
        }

    if ( debug->debugparse_ip )
        {


            if ( current_position > 0 )
                {

                    Sagan_Log(DEBUG, "[%lld:%d] --[Lookup Cache Array]----", pthread_self(), current_position );


                    for (i = 0; i < current_position; i++)
                        {

                            Sagan_Log(DEBUG, "-- ARRAY: Position: %d, Status: %d, IP: %s, Port: %d", i, lookup_cache[i].status, lookup_cache[i].ip, lookup_cache[i].port);
                        }

                }


        }


    return(current_position);
}

