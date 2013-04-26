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

/* sagan-util.c 
 *
 * Various re-usable functions. 
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
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>

#include "sagan.h"

#include "version.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _SaganVar *var; 
struct _Sagan_Processor_Generator *generator;

sbool daemonize;


/*****************************************************************************
 * This force Sagan to chroot.                                               *
 *                                                                           *
 * Note: printf/fprints are used,  because we actually chroot before the log *
 * it initalized                                                             *
 *****************************************************************************/

void Chroot(const char *username, const char *chrootdir ) { 

struct passwd *pw = NULL;

pw = getpwnam(username);

printf("[*] Chroot to %s\n", chrootdir);

if (chroot(chrootdir) != 0 || chdir ("/") != 0) {
    fprintf(stderr, "[E] Could not chroot to '%s'.\n",  chrootdir);
    exit(1);		/* sagan.log isn't open yet */
   }
}

/************************************************
 * Drop priv's so we aren't running as "root".  *
 ************************************************/

void sagan_droppriv(const char *username)
{

	struct stat fifocheck;
        struct passwd *pw = NULL;
	int ret;

        pw = getpwnam(username);

	if (!pw) Sagan_Log(1, "Couldn't locate user '%s'. Aborting...", username);
        
	if ( getuid() == 0 ) {
	Sagan_Log(0, "Dropping privileges [UID: %lu GID: %lu]", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);
	ret = chown(config->sagan_fifo, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

	        if (stat(config->sagan_fifo, &fifocheck) != 0 ) Sagan_Log(1, "Cannot open %s FIFO!", config->sagan_fifo);

		if ( ret < 0 ) Sagan_Log(1, "[%s, line %d] Cannot change ownership of %s to username %s", __FILE__, __LINE__, config->sagan_fifo, username);

                if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
                    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
		    Sagan_Log(1, "Could not drop privileges to uid: %lu gid: %lu!", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);
	       } 
	       
	       } else { 
	       Sagan_Log(0, "Not dropping privileges.  Already running as a non-privileged user");
	       }
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

/* Remove new-lines */

char  *Remove_Return(char *s) {
       char *s1, *s2;
       for(s1 = s2 = s;*s1;*s1++ = *s2++ )
       while( *s2 == '\n' )s2++;
      return s;
}

/* Removes spaces from certain rule fields, etc */

char *Remove_Spaces(char *s) {
       char *s1, *s2;
       for(s1 = s2 = s;*s1;*s1++ = *s2++ )
       while( *s2 == ' ')s2++;
       return s;
}

/* Shift a string to all uppercase */ 

char *To_UpperC(char* const s) {
        char* cur = s;
          while (*cur) {
          *cur = toupper(*cur);
          ++cur;
          }
  return s;
}

/* SQL strip. 

no longer needed,  but might be useful in the future? 

char *SQL_Strip(char *s) {
       char *s1, *s2;
       for(s1 = s2 = s;*s1;*s1++ = *s2++ )
       while ( *s2 == '<'  || 
               *s2 == '>'  || 
	       *s2 == '&'  || 
	       *s2 == '%'  || 
	       *s2 == ';'  || 
	       *s2 == '"'  || 
	       *s2 == '\'' || 
	       *s2 == '/'  || 
	       *s2 == '#'  || 
	       *s2 == '`'  || 
	       *s2 == '|'  ||
	       *s2 == ','  || 
	       *s2 == '@'  || 
	       *s2 == '$'  || 
	       *s2 == '^'  ||
	       *s2 == '['  || 
	       *s2 == ']'  || 
	       *s2 == '('  || 
	       *s2 == ')'  || 
	       *s2 == '='  || 
	       *s2 == '\r' || 
	       *s2 == '\n' 
	       ) s2++;
       return s;
}
*/

void Sagan_Log (int type, const char *format,... ) {

   char buf[1024];
   va_list ap;
   va_start(ap, format);
   char *chr="*";
   char curtime[64];
   time_t t;
   struct tm *now;
   t = time(NULL);
   now=localtime(&t);
   strftime(curtime, sizeof(curtime), "%m/%d/%Y %H:%M:%S",  now);

   if ( type == 1 ) chr="E";
   if ( type == 2 ) chr="W"; 
   if ( type == 3 ) chr="D"; 

     vsnprintf(buf, sizeof(buf), format, ap);
     fprintf(config->sagan_log_stream, "[%s] [%s] - %s\n", chr, curtime, buf);
     fflush(config->sagan_log_stream);

     if ( daemonize == 0) printf("[%s] %s\n", chr, buf);
     if ( type == 1 ) exit(1);
}

int Check_Endian() {
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

int IP2Bit (char *ipaddr ) { 

struct sockaddr_in ipv4;
uint32_t ip;

/* Change to AF_UNSPEC for future ipv6 */
/* Champ Clark III - 01/18/2011 */

if (!inet_pton(AF_INET, ipaddr, &ipv4.sin_addr)) {
Sagan_Log(0, "Warning: inet_pton() error,  but continuing...");
}

if ( config->endian == 0 ) {
   ip = htonl(ipv4.sin_addr.s_addr);
   } else {
   ip = ipv4.sin_addr.s_addr;
   }

return(ip);
}

int Is_Numeric (char *str) {

if(strlen(str) == strspn(str, "0123456789")) {
	return(TRUE);
	 } else {
	return(FALSE);
	}
}

/* Grab's information between "quotes" and returns it.  Use for things like
 * parsing msg: and pcre */

char *Between_Quotes(char *instring)
{
sbool flag=0;
int i;
char tmp1[2];

/* quick and dirty fix added by drforbin....this function really should be reworked 
fix added to make tmp2 presistent (non-automatic) so once the function returns it is presistent */

static char tmp2[512];
memset(tmp2,0,sizeof(tmp2));
char *ret;

for ( i=0; i<strlen(instring); i++) { 

if ( flag == 1 && instring[i] == '\"' ) flag = 0;
if ( flag == 1 ) { 
   snprintf(tmp1, sizeof(tmp1), "%c", instring[i]); 
   strlcat(tmp2, tmp1, sizeof(tmp2));
   }

if ( instring[i] == '\"' ) flag++;

}

ret=tmp2;
return(ret);
}

/* CalcPct (Taken from Snort) */

double CalcPct(uint64_t cnt, uint64_t total)
{
    double pct = 0.0;

    if (total == 0.0)
    {
        pct = (double)cnt;
    }
    else
    {
        pct = (double)cnt / (double)total;
    }

    pct *= 100.0;

    return pct;
}

/* DNS lookup of hostnames.  Wired for IPv4 and IPv6.  Code largely
 * based on Beej's showip.c */

char *DNS_Lookup( char *host ) 
{
    struct addrinfo hints, *res; //,// *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    char *ret;
    void *addr;

       if ( config->disable_dns_warnings == 0 ) { 
       Sagan_Log(2, "--------------------------------------------------------------------------");
       Sagan_Log(2, "Sagan DNS lookup need for %s.", host); 
       Sagan_Log(2, "This can affect performance.  Please see:" );
       Sagan_Log(2, "https://wiki.quadrantsec.com/bin/view/Main/SaganDNS");
       Sagan_Log(2, "--------------------------------------------------------------------------");
       }

       memset(&hints, 0, sizeof hints);
       hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
       hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0) {
	Sagan_Log(2, "%s: %s", gai_strerror(status), host);
        return "0";
    }

        if (res->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
     
    inet_ntop(res->ai_family, addr, ipstr, sizeof ipstr);
    free(res);
    ret=ipstr;
    return ret;
}


/* String replacement function.  Used for things like $RULE_PATH */

char *Replace_String(char *str, char *orig, char *rep)
{

  static char buffer[4096];
  char *p;

  if(!(p = strstr(str, orig)))  return str;

  strlcpy(buffer, str, p-str); 
  buffer[p-str] = '\0';
  sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));
  return(buffer);
}


/* Get the filename from a path */

char *Get_Filename(char *file) {

    char *pfile;
    pfile = file + strlen(file);
    for (; pfile > file; pfile--)
    {
        if ((*pfile == '\\') || (*pfile == '/'))	/* *nix/Windows */
        {
            pfile++;
            break;
        }
    }

return(pfile);

}

/****************************************************************************/
/* int is_rfc1918                                                           */
/*                                                                          */
/* Checks to see if an ip address is RFC1918 or not                         */
/****************************************************************************/

sbool is_rfc1918 ( char *ipaddr ) {

uint32_t ipint=0;

ipint = IP2Bit(ipaddr);

if ( ipint > 167772160 && ipint < 184549375 ) return(TRUE); 	 // 10.X.X.X
if ( ipint > 3232235520 && ipint < 3232301055 ) return(TRUE);    // 192.168.X.X 
if ( ipint > 2886729728 && ipint < 2887778303 ) return(TRUE);    // 172.16/31.X.X
if ( ipint == 2130706433 ) return(TRUE);			 // 127.0.0.1

/* Invalid IP addresses */

if ( ipint < 16777216 ) return(FALSE); 				 // Larger than 1.0.0.0

return(FALSE);

}

/****************************************************************************/
/* Sagan_Var_To_Value - Changes a variable in a configuration file (for     */
/* example - $RULE_PATH into it's true value.                               */
/****************************************************************************/

char *Sagan_Var_To_Value(char *instring) {

char *ptmp = NULL;
char *tok = NULL;
char tmp[256] = { 0 };
char tmp2[256] = { 0 };
char tmp3[254] = { 0 };
char tmp_result[256] = { 0 };
char *tmpbuf = NULL;
int i=0;

snprintf(tmp, sizeof(tmp), "%s", instring);
tmpbuf = tmp;

for (i=0; i<counters->var_count; i++) {

    ptmp = strtok_r(tmp, " ", &tok);

        while (ptmp != NULL ) {
             strlcpy(tmp2, Replace_String(ptmp, var[i].var_name, var[i].var_value), sizeof(tmp2));
             snprintf(tmp3, sizeof(tmp3), "%s ", tmp2);
             strlcat(tmp_result, tmp3, sizeof(tmp_result));
             ptmp = strtok_r(NULL, " ", &tok);
             }

snprintf(tmp, sizeof(tmp), "%s", tmp_result);
tmpbuf = tmp;
strlcpy(tmp_result, "", sizeof(tmp_result));
}

return(tmpbuf);
}

/****************************************************************************/
/* Sagan_Generator_Lookup - Looks up the "generator" ID (see the            */
/* "gen-msg.map") of a processor				            */
/****************************************************************************/

char *Sagan_Generator_Lookup(int processor_id, int alert_id) { 

int z=0; 
char *msg=NULL;

for (z=0; z<counters->genmapcount; z++) { 
if ( generator[z].generatorid == processor_id && generator[z].alertid == alert_id) msg=generator[z].generator_msg;
}

return(msg);
}
