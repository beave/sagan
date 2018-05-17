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
 * is part of the "parse_src_ip/parse_src_dst" Sagan rules flag.
 *
 * 2018/05 - Added a new "cache" system so Sagan doesn't have to repeatedly 
 * parse logs.  Support IPv6 and will attempt to pull the port if avaliable.
 *
 * TODO: PROTO? If we have it?
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

    char *ipaddr = NULL;
    char *ptr1 = NULL;
    char *ptr2 = NULL;

    char *ptr3 = NULL;
    char *ptr4 = NULL;


    char *ip_1 = NULL;
    char *ip_2 = NULL;

    char port_test[6] = { 0 };
    int  port_test_int = 0;


    sbool valid = false ;
    sbool pass_all = false;


    int i=0;

    int num_colons = 0;
    int num_dots = 0;
    int num_hashes = 0;

    int port = config->sagan_port;

    /* We do seek_position-1 to use the entire array.  There is no
       parse_src_ip: 0 */
/*
    if ( lookup_cache[seek_position-1].status == true )
        {

            if ( debug->debugparse_ip )
                {
                    Sagan_Log(DEBUG, "[%s:%lu] Pulled %s:%d from cache. Position %d", __FUNCTION__, pthread_self(), lookup_cache[seek_position-1].ip, lookup_cache[seek_position-1].port, seek_position );
                }

            snprintf(str, size, "%s", lookup_cache[seek_position-1].ip);
            return(lookup_cache[seek_position-1].port);
        }
	*/

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

//	    strlcpy(lookup_cache[current_position].ip, config->sagan_host, sizeof(lookup_cache[current_position].ip));

//	    lookup_cache[current_position].port = config->sagan_port;
//	    lookup_cache[current_position].status = 0;

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
            pass_all = false;

            if ( debug->debugparse_ip )
                {
                    Sagan_Log(DEBUG, "[%s:%lu] Colons: %d, Dots: %d, Hashes: %d", __FUNCTION__, pthread_self(), num_colons, num_dots, num_hashes );
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

//                            current_position++;

//                            if ( current_position == seek_position )
//                                {

//                                    if ( debug->debugparse_ip )
//                                        {
//                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self() );
//                                        }

//                                    pass_all = true;
//
   			            strlcpy(lookup_cache[current_position].ip, ptr1, MAXIP);
//                                    ipaddr = ptr1;

				    strlcpy(tmp_token, ptr2, sizeof(tmp_token));

				    ptr4 = tmp_token; 
                                    ptr3 = strtok_r(NULL, " ", &ptr4);

				    printf("tmp_token: |%s|\n", ptr4);

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
//                                                            port = config->sagan_port;
//
                                                        } else {

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

                                                    ptr3 = strtok_r(NULL, " ", &ptr2);

                                                    if ( ptr3 != NULL )
                                                        {

                                                            port = atoi(ptr3);

                                                            if ( port == 0 )
                                                                {
 //                                                                   port = config->sagan_port;
                                                             lookup_cache[current_position].port = config->sagan_port;
                                                                } else {
										
							     lookup_cache[current_position].port = port;
								}


                                                        }

                                                }

                                        }

//                                   break;

//                                }
//
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

                            {
                                Sagan_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv4 address '%s' with trailing period. **", __FUNCTION__, pthread_self(), ptr1 );
                            }

                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self() );
                                        }

                                    pass_all = true;
                                    ipaddr = ptr1;
                                    break;
                                }

                        }

                }


            /* Stand alone IPv6 */

            if ( num_colons > 2 )
                {

                    valid = inet_pton(AF_INET6, ptr1,  &(sa.sin_addr));

                    if ( valid == 1 )
                        {

                            {
                                Sagan_Log(DEBUG, "[%s:%lu] ** Identified stand alone IPv6 address '%s' **", __FUNCTION__, pthread_self(), ptr1 );
                            }

                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    {
                                        Sagan_Log(DEBUG, "[%s:%lu] Good position", __FUNCTION__, pthread_self() );
                                    }

                                    pass_all = true;
                                    ipaddr = ptr1;

                                    /* Look for "fe80::b614:89ff:fe11:5e24 port 1234" */

                                    ptr1 = strtok_r(NULL, " ", &ptr2);

                                    if ( ptr1 != NULL && strcasestr(ptr1, "port") )
                                        {

                                            if ( debug->debugparse_ip )
                                                {
                                                    Sagan_Log(DEBUG, "[%s:%lu] Identified the word 'port'", __FUNCTION__, pthread_self() );
                                                }


                                            ptr1 = strtok_r(NULL, " ", &ptr2);

                                            if ( ptr1 != NULL )
                                                {
                                                    port = atoi(ptr1);

                                                    if ( port == 0 )
                                                        {
                                                            port = config->sagan_port;
                                                        }

                                                }

                                        }

                                    /* Look for "fe80::b614:89ff:fe11:5e24 source port: 1234" or
                                    "fe80::b614:89ff:fe11:5e24 source port 1234" */

                                    else if ( ptr1 != NULL && ( strcasestr(ptr1, "source") ||
                                                                strcasestr(ptr1, "destination" ) ) )

                                        {

                                            if ( debug->debugparse_ip )
                                                {
                                                    Sagan_Log(DEBUG, "[%s:%lu] Identified the word 'source' or 'destination'", __FUNCTION__, pthread_self() );
                                                }


                                            ptr1 = strtok_r(NULL, " ", &ptr2);

                                            if ( ptr1 != NULL && strcasestr(ptr1, "port" ) )
                                                {

                                                    if ( debug->debugparse_ip )
                                                        {
                                                            Sagan_Log(DEBUG, "[%s:%lu] Identified the word 'port'", __FUNCTION__, pthread_self() );
                                                        }


                                                    ptr1 = strtok_r(NULL, " ", &ptr2);

                                                    if ( ptr1 != NULL )
                                                        {

                                                            port = atoi(ptr1);

                                                            if ( port == 0 )
                                                                {
                                                                    port = config->sagan_port;
                                                                }

                                                        }

                                                }

                                        }

                                    /* IPv6 [fe80::b614:89ff:fe11:5e24]:443 */

                                    else if ( ptr1 != NULL && ptr1[0] == ':' )
                                        {

                                            if ( debug->debugparse_ip )
                                                {
                                                    Sagan_Log(DEBUG, "[%s:%lu] Identified possible [IPv6]:PORT", __FUNCTION__, pthread_self() );
                                                }

                                            for ( i = 1; i < strlen(ptr1); i++ )
                                                {
                                                    port_test[i-1] = ptr1[i];
                                                }

                                            port_test_int = atoi(port_test);

                                            if ( port_test_int != 0 )
                                                {
                                                    port = port_test_int;
                                                }
                                            else
                                                {
                                                    port = config->sagan_port;
                                                }

                                        }

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


                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self() );
                                        }

                                    pass_all = true;
                                    ipaddr = ptr1;
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


                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self() );
                                        }

                                    pass_all = true;
                                    ipaddr = ip_1;

                                    /* In many cases, the port is after the : */

                                    port = atoi(ip_2);

                                    if ( port == 0 )
                                        {
                                            port = config->sagan_port;
                                        }

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


                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self() );
                                        }

                                    pass_all = true;
                                    ipaddr = ip_2;
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

                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self() );
                                        }

                                    pass_all = true;
                                    ipaddr = ip_1;

                                    /* In many cases, the port is after the : */

                                    port = atoi(ip_2);

                                    if ( port == 0 )
                                        {
                                            port = config->sagan_port;
                                        }

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

                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self() );
                                        }

                                    pass_all = true;
                                    ipaddr = ip_2;
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

                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self()  );
                                        }

                                    pass_all = true;
                                    ipaddr = ip_1;

                                    /* In many cases, the port is after the : */

                                    port = atoi(ip_2);

                                    if ( port == 0 )
                                        {
                                            port = config->sagan_port;
                                        }

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

                            current_position++;

                            if ( current_position == seek_position )
                                {

                                    if ( debug->debugparse_ip )
                                        {
                                            Sagan_Log(DEBUG, "[%s:%lu] Position is good.", __FUNCTION__, pthread_self() );
                                        }

                                    pass_all = true;
                                    ipaddr = ip_2;
                                    break;
                                }
                        }

                }

            ptr1 = strtok_r(NULL, " ", &ptr2);

        }

    /*

    if ( pass_all == true )
        {

            if ( debug->debugparse_ip )
                {
                    Sagan_Log(DEBUG, "[%s:%lu] Final: %s:%d", __FUNCTION__, pthread_self(), ipaddr, port );
                }

            if (ipaddr == NULL ||
                    !strcmp(ipaddr, "127.0.0.1") ||
                    !strcmp(ipaddr, "::1") ||
                    !strcmp(ipaddr, "::ffff:127.0.0.1"))
                {

                    if ( debug->debugparse_ip )
                        {
                            Sagan_Log(DEBUG, "[%s:%lu] Inserting %s:%d into cache.", __FUNCTION__, pthread_self(), config->sagan_host, config->sagan_port );
                        }

                    strlcpy(lookup_cache[seek_position-1].ip, config->sagan_host, MAXIP);
                    lookup_cache[seek_position-1].port = config->sagan_port;
                    lookup_cache[seek_position-1].status = true;
                    snprintf(str, size, "%s", config->sagan_host);

                }
            else
                {

                    if ( debug->debugparse_ip )
                        {
                            Sagan_Log(DEBUG, "[%s:%lu] Inserting %s:%d into cache.", __FUNCTION__, pthread_self(), ipaddr, port  );
                        }

                    strlcpy(lookup_cache[seek_position-1].ip, ipaddr, MAXIP);
                    lookup_cache[seek_position-1].port = port;
                    lookup_cache[seek_position-1].status = true;
                    snprintf(str, size, "%s", ipaddr);

                }

        }
    else
        {

            snprintf(str, size, "%s", config->sagan_host);

        }
	*/


    if ( debug->debugparse_ip )
        {
            Sagan_Log(DEBUG, "[%s:%lu] Function complete.", __FUNCTION__, pthread_self() );
        }

    return(port);
}

