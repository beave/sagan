/*
** Copyright (C) 2009-2010 Softwink, Inc. 
** Copyright (C) 2009-2010 Champ Clark III <champ@softwink.com>
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

/* sagan-util.c 
 *
 * Various re-usable functions. 
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBMYSQLCLIENT_R
#include <mysql/mysql.h>
MYSQL    *mysql, *mysql_logzilla;
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

char sagan_path[MAXPATH];

char *findipinmsg ( char * );
char sagan_port[6];
int daemonize;
int programmode;
int dochroot;

/************************************************
 * Drop priv's so we aren't running as "root".  *
 ************************************************/

void droppriv(const char *username)
{

        struct passwd *pw = NULL;

        pw = getpwnam(username);
        
	if (pw) {
	        
		if (pw->pw_dir) snprintf(sagan_path, sizeof(sagan_path), "%s", pw->pw_dir);
		 
		if ( dochroot == 1) {
                if (pw->pw_dir) {
                        if (chroot(pw->pw_dir) != 0 || chdir ("/") != 0) {
			        sagan_log(1, "Could not chroot/chdir to '%.64s'.",  pw->pw_dir);
        		}
          	    }
		}
	

                if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
                    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
		        sagan_log(1, "Could not change to '%.32s' uid=%lu gid=%lu. [%s line %d]", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid, pw->pw_dir, __FILE__, __LINE__);
                }
        }
        else {
	        sagan_log(1, "User %.32s cannot be found. [%s line %d]", username, __FILE__, __LINE__);
        }

	sagan_log(0, "Dropping privileges [UID: %lu GID: %lu]", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);
}

/***************************************************************/
/* Convert syslog data to hex for input into the payload table */
/***************************************************************/

char *fasthex(char *xdata, int length)
{
    char conv[] = "0123456789ABCDEF";
    char *retbuf = NULL;
    char *index;
    char *end;
    char *ridx;

    index = xdata;
    end = xdata + length;
    retbuf = (char *) calloc((length*2)+1, sizeof(char));
    ridx = retbuf;

    while(index < end)
    {
        *ridx++ = conv[((*index & 0xFF)>>4)];
        *ridx++ = conv[((*index & 0xFF)&0x0F)];
        index++;
    }

    return(retbuf);
}

/* Removes quotes from msg, pcre, etc */

char  *remquotes(char *s) {
       char *s1, *s2;
       for(s1 = s2 = s;*s1;*s1++ = *s2++ )
       while( *s2 == '"' )s2++;
       return s;
}

char  *remrt(char *s) {
       char *s1, *s2;
       for(s1 = s2 = s;*s1;*s1++ = *s2++ )
       while( *s2 == '\n' )s2++;
      return s;
}
			    


/* Removes spaces from certain rule fields, etc */

char *remspaces(char *s) {
       char *s1, *s2;
       for(s1 = s2 = s;*s1;*s1++ = *s2++ )
       while( *s2 == ' ')s2++;
       return s;
}

char *toupperc(char* const s) {
        char* cur = s;
          while (*cur) {
          *cur = toupper(*cur);
          ++cur;
          }
  return s;
}


void sagan_log (int type, const char *format,... ) {

   FILE *log; 

   char buf[1024];
   va_list ap;
   va_start(ap, format);
   char *chr="*";
   char curtime[64];
   char tmplog[64];
   time_t t;
   struct tm *now;
   t = time(NULL);
   now=localtime(&t);
   strftime(curtime, sizeof(curtime), "%m/%d/%Y %H:%M:%S",  now);
   snprintf(tmplog, sizeof(tmplog), "%s", SAGANLOG);

   if ( type == 1 ) chr="E";

     if ((log = fopen(tmplog, "a")) == NULL) {
       fprintf(stderr, "[E] Cannot open %s! [%s line %d]\n", SAGANLOG, __FILE__, __LINE__);
       exit(1);
       }

     vsnprintf(buf, sizeof(buf), format, ap);
     fprintf(log, "[%s] [%s] - %s\n", chr, curtime, buf);
     fflush(log);
     fclose(log);
     if ( programmode == 0 && daemonize == 0) printf("[%s] %s\n", chr, buf);
     if ( type == 1 ) exit(1);
}

int checkendian() {
   int i = 1;
   char *p = (char *) &i;
        if (p[0] == 1) // Lowest address contains the least significant byte
        return 0; // Little endian
        else
        return 1; // Big endian
}


/* Converts IP address.  For IPv4,  we convert the quad IP string to a 32 bit
 * value.  We return the unsigned long value as a pointer to a string because
 * that's the way IPv6 is done.  Basically,  we'll probably want IPv6 when 
 * snort supports DB IPv6.
 */

char *ip2bit (char *ipaddr,  int endian) { 

struct sockaddr_in ipv4;
unsigned long ip;
char *retbuf = NULL;
char tmpbuf[MAXHOST];


if (!inet_pton(AF_INET, ipaddr, &ipv4.sin_addr)) {
sagan_log(0, "Warning: inet_pton() error,  but continuing...");
}

if ( endian == 0 ) {
   ip = htonl(ipv4.sin_addr.s_addr);
   } else {
   ip = ipv4.sin_addr.s_addr;
   }

snprintf(tmpbuf, sizeof(tmpbuf), "%lu", ip);
retbuf=tmpbuf;

return(retbuf);
}

/* Simple search routine to find IP addresses within a message */

char *findipinmsg ( char *syslogmessage ) { 

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

	    retbuf=lastgood;
	    return(retbuf);
	    }
	}
     strlcpy(msg, "", 1);	/* Reset */

    }
return("0");
}

/* Check string to see if it's numeric or now */

int isnumeric (char *str) {

if(strlen(str) == strspn(str, "0123456789")) {
	return(1);
	 } else {
	return(0);
	}
}

int getport(char *msg) { 

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

/* Escape SQL.   This was taken from Prelude.  */

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
char *sql_escape(const char *string, int from )
{
        size_t len;
        char *escaped=NULL;
	char *escapedre=NULL;
	char tmpescaped[MAX_SYSLOGMSG];


        if ( ! string )
                return strdup("NULL");
        /*
         * MySQL documentation say :
         * The string pointed to by from must be length bytes long. You must
         * allocate the to buffer to be at least length*2+1 bytes long. (In the
         * worse case, each character may need to be encoded as using two bytes,
         * and you need room for the terminating null byte.)
         */
        len = strlen(string);

        escaped = malloc(len * 2 + 3);
        
	if (! escaped) {
                sagan_log(1, "[%s, line %d] memory exhausted.", __FILE__, __LINE__ );
                return NULL;
        }

        escaped[0] = '\'';

/* Snort */
if ( from == 0 ) { 
#ifdef HAVE_LIBMYSQLCLIENT_R
#if MYSQL_VERSION_ID >= 32200
        len = mysql_real_escape_string(mysql, escaped + 1, string, len);
#else
        len = mysql_escape_string(escaped + 1, string, len);
#endif
#endif

        escaped[len + 1] = '\'';
        escaped[len + 2] = '\0';
}

/* Logzilla */

if ( from == 1 ) {
#ifdef HAVE_LIBMYSQLCLIENT_R
#if MYSQL_VERSION_ID >= 32200
        len = mysql_real_escape_string(mysql_logzilla, escaped + 1, string, len);
#else   
        len = mysql_escape_string(escaped + 1, string, len);
#endif  
#endif
        escaped[len + 1] = '\'';
        escaped[len + 2] = '\0';
}

	/* Temp. copy value,  and free(escaped) to prevent mem. leak */

	snprintf(tmpescaped, sizeof(tmpescaped), "%s", escaped);
	escapedre=tmpescaped;
	free(escaped);

	return(escapedre);
}
#endif

