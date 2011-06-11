/*
** Copyright (C) 2009-2011 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2011 Champ Clark III <cclark@quadrantsec.com>
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

/* parse-ip-simple.c
 *
 * Simple method of "finding" the "real" IP address from a syslog message.  This
 * works with OpenSSH and messages of that nature.  An example message might be:
 * "Invalid login from 12.145.241.50".  It'll pull the 12.145.241.50.  This
 * is part of the "parse_ip_simple" Sagan rules flag.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>

#include "sagan-defs.h"
#include "sagan.h"

#include "version.h"


char *parse_ip_simple ( char *syslogmessage ) {

struct sockaddr_in sa;
int result, i, b;
int flag=0;

char lastgood[33];
char *retbuf = NULL;

char ctmp[2];
char msg[MAX_SYSLOGMSG];


for (b=0; b < strlen(syslogmessage); b++)
    {

    for (i = b; i < strlen(syslogmessage); i++)
        {
        snprintf(ctmp, sizeof(ctmp), "%c", syslogmessage[i]);
        strlcat(msg, ctmp, MAX_SYSLOGMSG);

        result = inet_pton(AF_INET, msg,  &(sa.sin_addr));

           if ( result != 0 )
              {
              flag=1;
              strlcpy(lastgood, msg, sizeof(lastgood)); /* Store the last "good" value */
              }

        /* If we had a good value,  now bad - we use the last known "good" value */

        if ( flag == 1 && result == 0 )
            {

            /* If the "good" value is 127.0.0.1,  that won't do us much good.  If
             * that is the case,  we revert back to the original IP address */

            if (!strcmp(lastgood, "127.0.0.1")) {
               return("0");
               }

//               }

            retbuf=lastgood;
            return(retbuf);
            }
        }
     strlcpy(msg, "", 1);       /* Reset */
    }
return("0");
}


