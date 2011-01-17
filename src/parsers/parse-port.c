/*
** Copyright (C) 2009-2011 Softwink, Inc. 
** Copyright (C) 2009-2011 Champ Clark III <champ@softwink.com>
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

/* parse-port-simple.c
 *
 * A simple method of finding a port in a syslog message.  An example message
 * might be "Invalid connection from 12.145.241.50 on port 22".  This code
 * would pull the port "22".   This is part of the "parse_port_simple" 
 * Sagan rules flag.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>
#include "sagan.h"
#include "version.h"


char sagan_port[6];

int parse_port_simple (char *msg) {

char *portstring=NULL;
char *saveptr1=NULL;
char *saveptr2=NULL;
char *str=NULL;
char *token=NULL;
char *tmpport=NULL;
int port;
int i;
struct sockaddr_in sa;
int result;

port = atoi(sagan_port);

char tmpmsg[MAX_SYSLOGMSG];
snprintf(tmpmsg, sizeof(tmpmsg), "%s", msg);
toupperc(tmpmsg);

/* See if the work " port" is in the string */

if ( strstr(tmpmsg, " PORT ")) {

   portstring = strtok_r(tmpmsg, " ", &saveptr1);
   for ( i = 0, str = portstring; ; i++, str == NULL )  {

      token = strtok_r(NULL, " ", &saveptr1);
      if ( token == NULL ) break;

      /* tokenize by " ",  grab string after "port".  */

      if (!strcmp(token, "PORT")) {
         tmpport = strtok_r(NULL, " ", &saveptr1);
         if (tmpport == NULL) break;
         /* if it's a number, set it.  If not,  default */
         if (isnumeric(tmpport)) {
             port=atoi(tmpport);
             } else {
             /* drop last char.  Sometimes port ends in port "#." */
             tmpport[strlen(tmpport) - 1] = '\0';
             if (isnumeric(tmpport)) port=atoi(tmpport);
             }

         }
     }
}

snprintf(tmpmsg, sizeof(tmpmsg), "%s", msg);
toupperc(tmpmsg);

if ( strstr(tmpmsg, ":")) {

   portstring = strtok_r(tmpmsg, ":", &saveptr1);
   token = strtok_r(portstring, " ", &saveptr2);
   for ( i = 0, str = portstring; ; i++, str == NULL )  {
   token = strtok_r(NULL, " ", &saveptr2);
   if ( token == NULL ) break;

   result = inet_pton(AF_INET, token,  &(sa.sin_addr));

      /* Found IP,  get the port */
      if ( result != 0 ) {
         /* IP:PORT */
         portstring = strtok_r(NULL, ":", &saveptr1);
         if (isnumeric(portstring)) {
             port=atoi(portstring);
             } else {
             /* IP:PORT string or IP::PORT */
             token = strtok_r(portstring, " ", &saveptr1);
             if (isnumeric(token)) port=atoi(portstring);
             }
         }
   }
}

snprintf(tmpmsg, sizeof(tmpmsg), "%s", msg);
toupperc(tmpmsg);

if ( strstr(tmpmsg, "#")) {

   portstring = strtok_r(tmpmsg, "#", &saveptr1);
   token = strtok_r(portstring, " ", &saveptr2);
   for ( i = 0, str = portstring; ; i++, str == NULL )  {
   token = strtok_r(NULL, " ", &saveptr2);
   if ( token == NULL ) break;

   result = inet_pton(AF_INET, token,  &(sa.sin_addr));

      /* Found IP,  get the port */
      if ( result != 0 ) {
         /* IP#PORT */
         portstring = strtok_r(NULL, "#", &saveptr1);
         if (isnumeric(portstring)) {
             port=atoi(portstring);
             } else {
             /* IP:PORT string or IP##PORT */
             token = strtok_r(portstring, " ", &saveptr1);
             if (isnumeric(token)) {
                port=atoi(token);
                } else {
                token[strlen(token) - 1] = '\0';
                if (isnumeric(token)) port=atoi(token);
                }
             }
         }
   }
}

return(port);
}

