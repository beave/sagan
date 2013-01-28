/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
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

/* parse-ip.c
 *
 * Simple method of "finding" the "real" IP address from a syslog message.  This
 * works with OpenSSH and messages of that nature.  An example message might be:
 * "Invalid login from 12.145.241.50".  It'll pull the 12.145.241.50.  This
 * is part of the "parse_ip" Sagan rules flag.
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

char *parse_ip( char *syslogmessage, int pos ) {

int result_space, result_nonspace, i, b;

int flag=0;
int current_pos=0; 
int notfound=0;

char ctmp[2] = { 0 };
char lastgood[16] = { 0 };
char msg[MAX_SYSLOGMSG] = { 0 };
char tmpmsg[MAX_SYSLOGMSG] = { 0 }; 

char *retbuf = NULL;
char *tok=NULL; 
char *ptmp=NULL; 

struct sockaddr_in sa;

snprintf(tmpmsg, sizeof(tmpmsg), "%s", syslogmessage); 

ptmp = strtok_r(tmpmsg, " ", &tok);

while (ptmp != NULL ) {

	if (strstr(ptmp, ".")) {

	   result_space = inet_pton(AF_INET, ptmp,  &(sa.sin_addr));

	   /* If we already have a good IP,  return it.  We can sometimes skips
	    * the next steps */

	   if ( result_space != 0 && strcmp(ptmp, "127.0.0.1")) {   
	      
	      current_pos++; 

	      if ( current_pos == pos ) { 
	         return(ptmp); 
	      } 
	   } else { 
	   notfound = 1; 
	   }

	   /* Start tearing apart the substring */

           if ( notfound == 1 ) { 

	   for (b=0; b < strlen(ptmp); b++) {
	       for (i = b; i < strlen(ptmp); i++) {

/*
	           if ( current_pos == pos ) {
		      if (!strcmp(lastgood, "127.0.0.1")) return("0");
		      retbuf=lastgood;
		      return(retbuf); 
		      }
*/
		   snprintf(ctmp, sizeof(ctmp), "%c", ptmp[i]);
		   strlcat(msg, ctmp, sizeof(msg));

		   result_nonspace = inet_pton(AF_INET, msg,  &(sa.sin_addr));

		   if ( result_nonspace != 0 ) {
		      strlcpy(lastgood, msg, sizeof(lastgood));
		      flag=1; 
		      }

		   if ( flag == 1 && result_nonspace == 0 ) { 

//		      flag=0; 
		      current_pos++;

		      if ( current_pos == pos ) { 
		         if (!strcmp(lastgood, "127.0.0.1")) return("0");
			 retbuf=lastgood;
			 return(retbuf);
			 }

		      flag = 0; 
		      i=i+strlen(lastgood);
		      b=b+strlen(lastgood);
		      break;
		      }
		   }
  	       strlcpy(msg, "", sizeof(msg)); 
	       }
	       }
	       notfound = 0; 
	 }
	 ptmp = strtok_r(NULL, " ", &tok);
     }

return("0");
}

