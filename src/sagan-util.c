/*
** Copyright (C) 2009-2014 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2014 Champ Clark III <cclark@quadrantsec.com>
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
#include "sagan-defs.h"
#include "sagan-config.h"

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

void Chroot(const char *username, const char *chrootdir )
{

//    struct passwd *pw = NULL;
//    pw = getpwnam(username);

    printf("[*] Chroot to %s\n", chrootdir);

    if (chroot(chrootdir) != 0 || chdir ("/") != 0)
        {
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

    if (!pw) Sagan_Log(S_ERROR, "Couldn't locate user '%s'. Aborting...", username);

    if ( getuid() == 0 )
        {
            Sagan_Log(S_NORMAL, "Dropping privileges [UID: %lu GID: %lu]", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);
            ret = chown(config->sagan_fifo, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

            if (stat(config->sagan_fifo, &fifocheck) != 0 ) Sagan_Log(S_ERROR, "[%s, line %d] Cannot open %s FIFO!",  __FILE__, __LINE__, config->sagan_fifo);

            if ( ret < 0 ) Sagan_Log(S_ERROR, "[%s, line %d] Cannot change ownership of %s to username %s", __FILE__, __LINE__, config->sagan_fifo, username);

            if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
                    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Could not drop privileges to uid: %lu gid: %lu!", __FILE__, __LINE__, (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);
                }

        }
    else
        {
            Sagan_Log(S_NORMAL, "Not dropping privileges.  Already running as a non-privileged user");
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

char  *Remove_Return(char *s)
{
    char *s1, *s2;
    for(s1 = s2 = s; *s1; *s1++ = *s2++ )
        while( *s2 == '\n' )s2++;
    return s;
}

/* Removes spaces from certain rule fields, etc */

char *Remove_Spaces(char *s)
{
    char *s1, *s2;
    for(s1 = s2 = s; *s1; *s1++ = *s2++ )
        while( *s2 == ' ')s2++;
    return s;
}

/* Shift a string to all uppercase */

char *To_UpperC(char *const s)
{
    char* cur = s;
    while (*cur)
        {
            *cur = toupper(*cur);
            ++cur;
        }
    return s;
}

/* Shift a string to all lowercase */

char *To_LowerC(char *const s)
{
    char* cur = s;
    while (*cur)
        {   
            *cur = tolower(*cur);
            ++cur;
        }
    return s;
}


void Sagan_Log (int type, const char *format,... )
{

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

int Check_Endian()
{
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

uint32_t IP2Bit (char *ipaddr)
{

    struct sockaddr_in ipv4;
    uint32_t ip;

    /* Change to AF_UNSPEC for future ipv6 */
    /* Champ Clark III - 01/18/2011 */

    if (!inet_pton(AF_INET, ipaddr, &ipv4.sin_addr))
        {
            Sagan_Log(S_WARN, "Warning: Got a inet_pton() error for \"%s\" but continuing...", ipaddr);
        }

    if ( config->endian == 0 )
        {
            ip = htonl(ipv4.sin_addr.s_addr);
        }
    else
        {
            ip = ipv4.sin_addr.s_addr;
        }

    return(ip);

}

int Is_Numeric (char *str)
{

    if(strlen(str) == strspn(str, "0123456789"))
        {
            return(TRUE);
        }
    else
        {
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

    for ( i=0; i<strlen(instring); i++)
        {

            if ( flag == 1 && instring[i] == '\"' ) flag = 0;
            if ( flag == 1 )
                {
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

    if ( config->disable_dns_warnings == 0 )
        {
            Sagan_Log(S_WARN, "--------------------------------------------------------------------------");
            Sagan_Log(S_WARN, "Sagan DNS lookup need for %s.", host);
            Sagan_Log(S_WARN, "This can affect performance.  Please see:" );
            Sagan_Log(S_WARN, "https://wiki.quadrantsec.com/bin/view/Main/SaganDNS");
            Sagan_Log(S_WARN, "--------------------------------------------------------------------------");
        }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0)
        {
            Sagan_Log(S_WARN, "%s: %s", gai_strerror(status), host);
            return "0";
        }

    if (res->ai_family == AF_INET)   // IPv4
        {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            addr = &(ipv4->sin_addr);
        }
    else     // IPv6
        {
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

char *Get_Filename(char *file)
{

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

sbool is_rfc1918 ( char *ipaddr )
{

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

char *Sagan_Var_To_Value(char *instring)
{

    char *ptmp = NULL;
    char *tok = NULL;
    char tmp[256] = { 0 };
    char tmp2[256] = { 0 };
    char tmp3[254] = { 0 };
    char tmp_result[256] = { 0 };
    char *tmpbuf = NULL;
    int i=0;

    snprintf(tmp, sizeof(tmp), "%s", instring);		// Segfault with strlcpy
    tmpbuf = tmp;

    for (i=0; i<counters->var_count; i++)
        {

            ptmp = strtok_r(tmp, " ", &tok);

            while (ptmp != NULL )
                {
                    strlcpy(tmp2, Replace_String(ptmp, var[i].var_name, var[i].var_value), sizeof(tmp2));
                    snprintf(tmp3, sizeof(tmp3), "%s ", tmp2);
                    strlcat(tmp_result, tmp3, sizeof(tmp_result));
                    ptmp = strtok_r(NULL, " ", &tok);
                }

            strlcpy(tmp, tmp_result, sizeof(tmp));
            tmpbuf = tmp;
            strlcpy(tmp_result, "", sizeof(tmp_result));
        }

    return(tmpbuf);
}

/****************************************************************************/
/* Sagan_Validate_HEX - Makes sure a string is valid hex.                   */
/****************************************************************************/

int Sagan_Validate_HEX (const char *string)
{

    const char *curr = string;
    while (*curr != 0)
        {
            if (('A' <= *curr && *curr <= 'F') || ('a' <= *curr && *curr <= 'f') || ('0' <= *curr && *curr <= '9'))
                {
                    ++curr;
                }
            else
                {
                    return(FALSE);
                }
        }
    return(TRUE);
}

/****************************************************************************/
/* Sagan_Check_Var - Checks to make sure a "var" is present in memory       */
/****************************************************************************/

int Sagan_Check_Var(const char *string)
{

    int i;
    int flag = 0;

    for (i=0; i<counters->var_count; i++)
        {

            if (!strcmp(string, var[i].var_name))
                {
                    flag = 1;
                    break;
                }
        }

    return(flag);
}


/************************************************************************************************
* This is for |HEX| support (like in Snort).  From example: content: "User |3a 3c 53| and such";
* If the content has no pipes,  we leave it unaltered.  If it has pipes,  we insert the ASCII
* values of the Hex within the content (keeping formating correct - Champ Clark - 12/04/2013
* Move to this function 05/05/2014 - Champ Clark
*************************************************************************************************/


char *Sagan_Content_Pipe(char *in_string, int linecount, const char *ruleset)
{

    int pipe_flag = 0;
    char final_content[512] = { 0 };
    char final_content_tmp[512] = { 0 };
    char *ret_buf = NULL;
    char tmp2[512];
    int i;
    int x;
    char tmp[2];


    strlcpy(tmp2, in_string, sizeof(tmp2));

    pipe_flag = 0;

    for ( i=0; i<strlen(tmp2); i++)
        {


            if ( tmp2[i] == '|' && pipe_flag == 0 ) pipe_flag = 1;              /* First | has been found */

            /* If we haven't found any |'s,  just copy the content verbatium */

            if ( pipe_flag == 0 )
                {
                    snprintf(final_content_tmp, sizeof(final_content_tmp), "%c", tmp2[i]);
                    strncat(final_content, final_content_tmp, 1);
                }

            /* If | has been found,  start the conversion */

            if ( pipe_flag == 1 )
                {

                    if ( tmp2[i+1] == ' ' || tmp2[i+2] == ' ' ) Sagan_Log(S_ERROR, "The 'content' option with hex formatting (|HEX|) appears to be incorrect. at line %d in %s", linecount, ruleset);

                    snprintf(final_content_tmp, sizeof(final_content_tmp), "%c%c", tmp2[i+1], tmp2[i+2]);       /* Copy the hex value - ie 3a, 1B, etc */

                    if (!Sagan_Validate_HEX(final_content_tmp)) Sagan_Log(S_ERROR, "Invalid '%s' Hex detected at line %d in %s", final_content_tmp, linecount, ruleset);

                    sscanf(final_content_tmp, "%x", &x);                                                        /* Convert hex to dec */
                    snprintf(tmp, sizeof(tmp), "%c", x);                                                        /* Convert dec to ASCII */
                    strncat(final_content, tmp, 1);                                                     /* Append value */

                    /* Last | found,  but continue processing rest of content as normal */

                    if ( tmp2[i+3] == '|' )
                        {
                            pipe_flag = 0;
                            i=i+3;
                        }
                    else
                        {
                            i = i+2;
                        }
                }

        }

    ret_buf = final_content;
    return(ret_buf);
}

/****************************************************************************
 * Sagan_Replace_Sagan() - Take the %sagan% out of a string and replaces it
 * with *replace
 ****************************************************************************/

char *Sagan_Replace_Sagan( char *string_in, char *replace)
{

    char string[1024] = { 0 };
    char new_string[1024] = { 0 };
    char tmp[2] = { 0 };

    char *buf = NULL;

    int i;

    strlcpy(string, string_in, sizeof(string));

    for (i = 0; i < strlen(string); i++)
        {

            if ( string[i] == '%' )
                {

                    if ( string[i+1] == 's' && string[i+2] == 'a' && string[i+3] == 'g' &&
                            string[i+4] == 'a' && string[i+5] == 'n' && string[i+6] == '%' )
                        {

                            strlcat(new_string, replace, sizeof(new_string));
                            i = i + 6;  /* Skip to end of %sagan% */

                        }
                    else
                        {

                            strlcat(new_string, "%", sizeof(new_string));
                        }
                }
            else
                {

                    snprintf(tmp, sizeof(tmp), "%c", string[i]);
                    strlcat(new_string, tmp, sizeof(new_string));
                }
        }

    buf = new_string;
    return(buf);
}


/****************************************************************************
 * Sagan_Character_Count - Simple routine that "counts" the number of
 * time "char_to_count" (single character) occurs.   Returns the int
 * value of what it found
 ****************************************************************************/

int Sagan_Character_Count ( char *string_in, char *char_to_count)
{

    char str_to_count[128] = { 0 };
    char tmp[2] = { 0 };

    int i = 0;
    int to_count = 0;
    int return_count = 0;

    /* Convert to usable types */
    strlcpy(tmp, char_to_count, 2);
    strlcpy(str_to_count, string_in, sizeof(str_to_count));

    to_count = (int)tmp[0];

    for (i = 0; i < strlen(str_to_count); i++)
        {
            /* Search for and count int char[i] */
            if ( (int)str_to_count[i] == to_count )
                {
                    return_count++;
                }
        }

    return(return_count);
}


