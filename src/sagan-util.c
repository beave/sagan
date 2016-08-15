/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "sagan-lockfile.h"

#include "parsers/sagan-strstr/sagan-strstr-hook.h"

#include "version.h"

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _SaganVar *var;
struct _Sagan_Processor_Generator *generator;

sbool daemonize;
sbool quiet;

/*****************************************************************************
 * This force Sagan to chroot.                                               *
 *                                                                           *
 * Note: printf/fprints are used,  because we actually chroot before the log *
 * it initalized                                                             *
 *****************************************************************************/

void Sagan_Chroot(const char *chrootdir )
{

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

void Sagan_Droppriv(void)
{

    struct stat fifocheck;
    struct passwd *pw = NULL;
    int ret;

    pw = getpwnam(config->sagan_runas);

    if (!pw)
        {
            Sagan_Log(S_ERROR, "Couldn't locate user '%s'. Aborting...", config->sagan_runas);
        }

    if ( getuid() == 0 )
        {
            Sagan_Log(S_NORMAL, "Dropping privileges [UID: %lu GID: %lu]", (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid);

            /*
             * We chown certain log files to our Sagan user.  This is done so no files are "owned"
             * by "root".  This prevents problems in the future when doing things like handling
                 * SIGHUP's and what not.
                 *
                 * Champ Clark (04/14/2015)
                 */

            if ( config->sagan_is_file == 0 )	/* Don't change ownsership/etc if we're processing a file */
                {

                    ret = chown(config->sagan_fifo, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

                    if ( ret < 0 )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Cannot change ownership of %s to username %s - %s", __FILE__, __LINE__, config->sagan_fifo, config->sagan_runas, strerror(errno));
                        }

                    if (stat(config->sagan_fifo, &fifocheck) != 0 )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Cannot open %s FIFO - %s!",  __FILE__, __LINE__, config->sagan_fifo, strerror(errno));
                        }

                }

            if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
                    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Could not drop privileges to uid: %lu gid: %lu - %s!", __FILE__, __LINE__, (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid, strerror(errno));
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

    if ( retbuf == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for retbuf. Abort!", __FILE__, __LINE__);
        }

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

    char buf[5128];
    va_list ap;
    va_start(ap, format);
    char *chr="*";
    char curtime[64];
    time_t t;
    struct tm *now;
    t = time(NULL);
    now=localtime(&t);
    strftime(curtime, sizeof(curtime), "%m/%d/%Y %H:%M:%S",  now);

    if ( type == 1 )
        {
            chr="E";
        }

    if ( type == 2 )
        {
            chr="W";
        }

    if ( type == 3 )
        {
            chr="D";
        }

    vsnprintf(buf, sizeof(buf), format, ap);
    fprintf(config->sagan_log_stream, "[%s] [%s] - %s\n", chr, curtime, buf);
    fflush(config->sagan_log_stream);

    if ( config->daemonize == 0 && config->quiet == 0 )
        {
            printf("[%s] %s\n", chr, buf);
        }

    if ( type == 1 )
        {
            exit(1);
        }

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
    static __thread uint32_t ip;

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

/* Check if string contains only numbers */

int Is_Numeric (char *str)
{

    if(strlen(str) == strspn(str, "0123456789"))
        {
            return(true);
        }
    else
        {
            return(false);
        }

}

/* Grab's information between "quotes" and returns it.  Use for things like
 * parsing msg: and pcre */

char *Between_Quotes(char *instring)
{
    sbool flag=0;
    int i;
    char tmp1[2];

    static __thread char tmp2[512];
    memset(tmp2,0,sizeof(tmp2));

    for ( i=0; i<strlen(instring); i++)
        {

            if ( flag == 1 && instring[i] == '\"' )
                {
                    flag = 0;
                }

            if ( flag == 1 )
                {
                    snprintf(tmp1, sizeof(tmp1), "%c", instring[i]);
                    strlcat(tmp2, tmp1, sizeof(tmp2));
                }

            if ( instring[i] == '\"' ) flag++;

        }

    return(tmp2);
}

/* CalcPct (Taken from Snort) */

double CalcPct(uintmax_t cnt, uintmax_t total)
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

    static __thread char ipstr[INET6_ADDRSTRLEN];
    memset(ipstr,0,sizeof(ipstr));

    struct addrinfo hints, *res;
    int status;
    void *addr;

    /* Short circuit if it's a "localhost" lookup */

    if ( !strcmp(host, "localhost" ) )
        {
            return(config->sagan_host);
        }

    if ( config->disable_dns_warnings == 0 )
        {
            Sagan_Log(S_WARN, "--------------------------------------------------------------------------");
            Sagan_Log(S_WARN, "Sagan DNS lookup need for '%s'.", host);
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

    return(ipstr);
}


/* String replacement function.  Used for things like $RULE_PATH */

char *Replace_String(char *str, char *orig, char *rep)
{

    static __thread char buffer[4096];
    memset(buffer,0,sizeof(buffer));

    char *p;

    if(!(p = strstr(str, orig)))
        {
            return str;
        }

    strlcpy(buffer, str, p-str);
    buffer[p-str] = '\0';
    sprintf(buffer+(p-str), "%s%s", rep, p+strlen(orig));
    return(buffer);
}


/* Get the filename from a path */

char *Get_Filename(char *file)
{

    char *pfile = NULL;

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
/* s_rfc1918                                                                */
/*                                                                          */
/* Checks to see if an ip address is RFC1918 or not                         */
/****************************************************************************/

sbool is_rfc1918 ( uint32_t ipint )
{

    if ( ipint > 167772160 && ipint < 184549375 ) 	/* 10.X.X.X */
        {
            return(true);
        }

    if ( ipint > 3232235520 && ipint < 3232301055 )   	/* 192.168.X.X */
        {
            return(true);
        }

    if ( ipint > 2886729728 && ipint < 2887778303 )    	/* 172.16/31.X.X */
        {
            return(true);
        }

    if ( ipint > 2851995648 && ipint < 2852061183 )	/* 169.254.X.X Link Local */
        {
            return(true);
        }

    if ( ipint == 2130706433 ) 			 	/* 127.0.0.1 */
        {
            return(true);
        }

    /* Invalid IP addresses */

    if ( ipint < 16777216 )  				/* Must be larger than than 1.0.0.0 */
        {
            return(false);
        }

    return(false);

}

/****************************************************************************/
/* Sagan_Var_To_Value - Changes a variable in a configuration file (for     */
/* example - $RULE_PATH into it's true value.                               */
/****************************************************************************/

char *Sagan_Var_To_Value(char *instring)
{

    char *ptmp = NULL;
    char *tok = NULL;
    char tmp2[MAX_VAR_VALUE_SIZE] = { 0 };
    char tmp3[MAX_VAR_VALUE_SIZE] = { 0 };
    char tmp_result[MAX_VAR_VALUE_SIZE] = { 0 };

    static __thread char tmp[MAX_VAR_VALUE_SIZE] = { 0 };

    char *tmpbuf = (char*)malloc(MAX_VAR_VALUE_SIZE);
    memset(tmpbuf,0,(sizeof((char*)tmpbuf)));

    int i=0;

    snprintf(tmp, sizeof(tmp), "%s", instring);		// Segfault with strlcpy

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
            tmpbuf = (char*)&tmp;
            memset(tmp_result, 0, sizeof(tmp_result));
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
                    return(false);
                }
        }
    return(true);
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

    static char final_content[512] = { 0 };
    memset(final_content,0,sizeof(final_content));

    char final_content_tmp[512] = { 0 };
    char tmp2[512];
    int i;
    int x;
    char tmp[2];

    strlcpy(tmp2, in_string, sizeof(tmp2));

    pipe_flag = 0;

    for ( i=0; i<strlen(tmp2); i++)
        {

            if ( tmp2[i] == '|' && pipe_flag == 0 )
                {
                    pipe_flag = 1;              /* First | has been found */
                }

            /* If we haven't found any |'s,  just copy the content verbatium */

            if ( pipe_flag == 0 )
                {
                    snprintf(final_content_tmp, sizeof(final_content_tmp), "%c", tmp2[i]);
                    strncat(final_content, final_content_tmp, 1);
                }

            /* If | has been found,  start the conversion */

            if ( pipe_flag == 1 )
                {

                    if ( tmp2[i+1] == ' ' || tmp2[i+2] == ' ' )
                        {
                            Sagan_Log(S_ERROR, "The 'content' option with hex formatting (|HEX|) appears to be incorrect. at line %d in %s", linecount, ruleset);
                        }

                    snprintf(final_content_tmp, sizeof(final_content_tmp), "%c%c", tmp2[i+1], tmp2[i+2]);       /* Copy the hex value - ie 3a, 1B, etc */

                    if (!Sagan_Validate_HEX(final_content_tmp))
                        {
                            Sagan_Log(S_ERROR, "Invalid '%s' Hex detected at line %d in %s", final_content_tmp, linecount, ruleset);
                        }

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

    return(final_content);
}

/****************************************************************************
 * Sagan_Replace_Sagan() - Take the %sagan% out of a string and replaces it
 * with *replace
 ****************************************************************************/

char *Sagan_Replace_Sagan( char *string_in, char *replace)
{

    char string[1024] = { 0 };
    char tmp[2] = { 0 };

    char *buf;

    static __thread char new_string[1024];
    memset(&new_string, 0, sizeof(new_string));

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

    buf = (char*)&new_string;
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

/****************************************************************************
 * Sagan_Wildcard - Used for comparing strings with wildcard support.  This
 * function was taken from:
 *
 * http://www.geeksforgeeks.org/wildcard-character-matching/
 *
 * They had a much better solution than mine!
 ****************************************************************************/

sbool Sagan_Wildcard( char *first, char *second )
{
    if (*first == '\0' && *second == '\0')
        {
            return true;
        }

    if (*first == '*' && *(first+1) != '\0' && *second == '\0')
        {
            return false;
        }

    if (*first == '?' || *first == *second)
        {
            return Sagan_Wildcard(first+1, second+1);
        }

    if (*first == '*')
        {
            return Sagan_Wildcard(first+1, second) || Sagan_Wildcard(first, second+1);
        }

    return false;
}

/****************************************************************************
 * Sagan_Open_Log_File - This controls the opening and/or re-opening of log
 * files.  This is useful for situation like SIGHUP,  where we want to
 * close a file handle and start a new one.  Think of 'logrotate'.
 ****************************************************************************/

void Sagan_Open_Log_File( sbool state, int type )
{

    struct passwd *pw = NULL;
    int ret;

    pw = getpwnam(config->sagan_runas);

    if( pw == NULL)
        {
            fprintf(stderr, "[E] [%s, line %d] Invalid user %s (use -u option to set a user)\n", __FILE__, __LINE__, config->sagan_runas);
            exit(1);
        }

    if ( type == SAGAN_LOG || type == ALL_LOGS )
        {

            /* For SIGHUP */

            if ( state == REOPEN )
                {
                    fclose(config->sagan_log_stream);
                }

            if ((config->sagan_log_stream = fopen(config->sagan_log_filepath, "a")) == NULL)
                {
                    fprintf(stderr, "[E] [%s, line %d] Cannot open %s - %s!\n", __FILE__, __LINE__, config->sagan_log_filepath, strerror(errno));
                    exit(1);
                }

            /* Chown the log files in case we get a SIGHUP or whatnot later (due to Sagan_Chroot()) */

            ret = chown(config->sagan_log_filepath, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

            if ( ret < 0 )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Cannot change ownership of %s to username %s - %s", __FILE__, __LINE__, config->sagan_log_filepath, config->sagan_runas, strerror(errno));
                }

        }


    if ( type == ALERT_LOG || type == ALL_LOGS )
        {

            /* For SIGHUP */

            if ( state == REOPEN )
                {
                    fclose(config->sagan_alert_stream);
                }

            if (( config->sagan_alert_stream = fopen(config->sagan_alert_filepath, "a" )) == NULL )
                {
                    Remove_Lock_File();
                    Sagan_Log(S_ERROR, "[%s, line %d] Can't open %s - %s!", __FILE__, __LINE__, config->sagan_alert_filepath, strerror(errno));
                }

            /* Chown the log files in case we get a SIGHUP or whatnot later (due to Sagan_Chroot()) */

            ret = chown(config->sagan_alert_filepath, (unsigned long)pw->pw_uid,(unsigned long)pw->pw_gid);

            if ( ret < 0 )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Cannot change ownership of %s to username %s - %s", __FILE__, __LINE__, config->sagan_alert_filepath, config->sagan_runas, strerror(errno));
                }

        }

}

/****************************************************************************
 * Sagan_Set_Pipe_Size - Changes the capacity of the pipe/FIFO.
 ****************************************************************************/

#if defined(F_GETPIPE_SZ) && defined(F_SETPIPE_SZ)

void Sagan_Set_Pipe_Size ( FILE *fd )
{

    int fd_int;
    int current_fifo_size;
    int fd_results;


    if ( config->sagan_fifo_size != 0 )
        {

            fd_int = fileno(fd);
            current_fifo_size = fcntl(fd_int, F_GETPIPE_SZ);

            if ( current_fifo_size == config->sagan_fifo_size )
                {

                    Sagan_Log(S_NORMAL, "FIFO capacity already set to %d bytes.", config->sagan_fifo_size);

                }
            else
                {

                    Sagan_Log(S_NORMAL, "FIFO capacity is %d bytes.  Changing to %d bytes.", current_fifo_size, config->sagan_fifo_size);

                    fd_results = fcntl(fd_int, F_SETPIPE_SZ, config->sagan_fifo_size );

                    if ( fd_results == -1 )
                        {
                            Sagan_Log(S_WARN, "FIFO capacity could not be changed.  Continuing anyways...");
                        }

                    if ( fd_results > config->sagan_fifo_size )
                        {
                            Sagan_Log(S_WARN, "FIFO capacity was rounded up to the next page size of %d bytes.", fd_results);
                        }
                }
        }
}

#endif

char *Sagan_Return_Date( uintmax_t utime )
{

    struct tm tm;
    static __thread char time_buf[80];
    char tmp[80];

    char *return_date = NULL;

    memset(&tm, 0, sizeof(struct tm));
    snprintf(tmp, sizeof(tmp) - 1, "%lu", utime);

    strptime(tmp, "%s", &tm);
    strftime(time_buf, sizeof(time_buf), "%F", &tm);

    return_date = (char*)&time_buf;
    return(return_date);

}

char *Sagan_Return_Time( uintmax_t utime )
{

    struct tm tm;
    static __thread char time_buf[80];
    char tmp[80];

    char *return_date = NULL;

    memset(&tm, 0, sizeof(struct tm));
    snprintf(tmp, sizeof(tmp) - 1, "%lu", utime);

    strptime(tmp, "%s", &tm);
    strftime(time_buf, sizeof(time_buf), "%T", &tm);

    return_date = (char*)&time_buf;
    return(return_date);

}


/****************************************************************************
 * Sagan_u32_Time_To_Human - Converts a 32/64 bit epoch time into a human
 * "readable" format.
 ****************************************************************************/

char *Sagan_u32_Time_To_Human ( uintmax_t utime )
{
    struct tm tm;
    static __thread char time_buf[80];
    char tmp[80];

    char *return_time = NULL;

    memset(&tm, 0, sizeof(struct tm));
    snprintf(tmp, sizeof(tmp) - 1, "%lu", utime);

    strptime(tmp, "%s", &tm);
    strftime(time_buf, sizeof(time_buf), "%b %d %H:%M:%S %Y", &tm);

    return_time = (char*)&time_buf;

    return(return_time);
}

/****************************************************************************
 * Sagan_File_Lock - Takes in a file descriptor and "locks" the file.  Used
 * with IPC/memory mapped files.
 ****************************************************************************/

sbool Sagan_File_Lock ( int fd )
{

    struct flock fl;

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = getpid();

    if (fcntl(fd, F_SETLKW, &fl) == -1)
        {
            Sagan_Log(S_WARN, "[%s, line %d] Unable to get LOCK on file. (%s)", __FILE__, __LINE__, strerror(errno));
        }

    return(0);
}

/****************************************************************************
 * Sagan_File_Unlock - Takes in a file descriptor and "unlocks" the file.
 * Used with IPC/memory mapped files.
 ****************************************************************************/

sbool Sagan_File_Unlock( int fd )
{

    struct flock fl;

    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = getpid();

    if (fcntl(fd, F_SETLK, &fl) == -1)
        {
            Sagan_Log(S_WARN, "[%s, line %d] Unable to get UNLOCK on file. (%s)", __FILE__, __LINE__, strerror(errno));
        }

    return(0);
}

/****************************************************************************
 * Bit2IP - Takes a 32 bit IP address and returns an octet notation
 ****************************************************************************/

char *Bit2IP(uint32_t ip_u32)
{

    char *return_ip = NULL;

    struct in_addr ip_addr_convert;

    static __thread char retbuf[20];
    memset(retbuf,0,sizeof(retbuf));

    ip_addr_convert.s_addr = htonl(ip_u32);
    strlcpy(retbuf, inet_ntoa(ip_addr_convert), sizeof(retbuf));

    return_ip = (char*)&retbuf;

    return(return_ip);
}

/****************************************/
/* Compute netmask address given prefix */
/****************************************/
in_addr_t Netmask( int prefix )
{

    if ( prefix == 0 || prefix == 32 )
        return( ~((in_addr_t) -1) );
    else
        return( ~((1 << (32 - prefix)) - 1) );

} /* netmask() */


/******************************************************/
/* Compute broadcast address given address and prefix */
/******************************************************/
in_addr_t Broadcast( in_addr_t addr, int prefix )
{

    return( addr | ~Netmask(prefix) );

} /* broadcast() */


/****************************************************/
/* Compute network address given address and prefix */
/****************************************************/
in_addr_t Network( in_addr_t addr, int prefix )
{

    return( addr & Netmask(prefix) );

} /* network() */

/*************************************************************/
/* Convert an A.B.C.D address into a 32-bit host-order value */
/*************************************************************/
in_addr_t A_To_Hl( char *ipstr )
{

    struct in_addr in;

    if ( !inet_aton(ipstr, &in) )
        {
            Sagan_Log(S_ERROR, "[E] Invalid address %s!\n", ipstr );
        }

    return( ntohl(in.s_addr) );

} /* a_to_hl() */

/*******************************************************************/
/* convert a network address char string into a host-order network */
/* address and an integer prefix value                             */
/*******************************************************************/
network_addr_t Str_To_Netaddr( char *ipstr )
{

    long int prefix = 32;
    char *prefixstr;
    network_addr_t netaddr;

    if ( (prefixstr = strchr(ipstr, '/')) )
        {
            *prefixstr = '\0';
            prefixstr++;
            prefix = strtol( prefixstr, (char **) NULL, 10 );
            if ( errno || (*prefixstr == '\0') || (prefix < 1) || (prefix > 32) )
                {
                    Sagan_Log(S_ERROR, "[E]: Invalid IP %s/%s in your config file var declaration!\n", ipstr, prefixstr );
                }
            if ( (prefix < 8) )
                {
                    Sagan_Log(S_WARN, "[W]: Your wildcard for '%s' is less than 8, is this really what you want?", ipstr );
                }
        }

    netaddr.pfx = (int) prefix;
    netaddr.addr = Network( A_To_Hl(ipstr), prefix );

    return( netaddr );

} /* str_to_netaddr() */

/***************************************************************************/
/* Convert an IP or IP/CIDR into 32bit decimal single IP or 32bit decimal  */
/* IP low and high range                                                   */
/***************************************************************************/
char *Netaddr_To_Range( char ipstr[21] )
{

    network_addr_t *netaddrs = NULL;
    uint32_t lo, hi;
    char *t;
    char my_str[50];
    char my_str2[101];
    static __thread char result[101];
    char tmp[512];
    char tmp2[512];

    if ( ( t = strchr(ipstr, '/') ) )
        {
            netaddrs = realloc( netaddrs, 2 * sizeof(network_addr_t) );
            netaddrs[0] = Str_To_Netaddr( ipstr );

            lo = netaddrs[0].addr;
            hi = Broadcast( netaddrs[0].addr, netaddrs[0].pfx );

            if(lo != hi)
                {

                    snprintf(tmp , sizeof(tmp), "%lu-", (unsigned long)lo);
                    snprintf(tmp2 , sizeof(tmp2), "%lu", (unsigned long)hi);
                    strlcpy(my_str, tmp, sizeof(my_str));
                    strlcpy(my_str2, tmp2, sizeof(my_str2));
                    strcat(my_str, my_str2);
                    sprintf( result, "%s", my_str);

                    return(result);
                }
            else
                {
                    snprintf( result, sizeof(result), "%lu", (unsigned long)lo);
                    return(result);
                }
        }
    else
        {
            snprintf( result, sizeof(result), "%lu", (unsigned long)IP2Bit(ipstr));
            return(result);
        }
} /* netaddr_to_range() */

/**********************************/
/* Strip characters from a string */
/**********************************/

char *Strip_Chars(const char *string, const char *chars)
{
    char * newstr = malloc(strlen(string) + 1);
    int counter = 0;

    for ( ; *string; string++)
        {
            if (!strchr(chars, *string))
                {
                    newstr[ counter ] = *string;
                    ++ counter;
                }
        }

    newstr[counter] = 0;
    return newstr;
}

/***************************************************/
/* Check if str is valid IP from decimal or dotted */
/* quad ( 167772160, 1.1.1.1, 192.168.192.168/28 ) */
/***************************************************/

sbool Is_IP (char *str)
{

    char *tmp;
    char *ip;
    int prefix;
    struct in_addr addr;

    if(strlen(str) == strspn(str, "0123456789./"))
        {

            if(strspn(str, "./") == 0)
                {
                    if ( inet_aton(Bit2IP(atol(str)), &addr) == 0 )
                        {
                            return(false);
                        }
                }

            if ( strchr(str, '/') )
                {
                    ip = strtok_r(str, "/", &tmp);
                    prefix = atoi(strtok_r(NULL, "/", &tmp));
                    if(inet_aton(ip, &addr) == 0 || prefix < 1 || prefix > 32)
                        {
                            return(false);
                        }
                }
            else
                {
                    if ( inet_aton(str, &addr) == 0 )
                        {
                            return(false);
                        }
                }

            return(true);

        }
    else
        {

            return(false);
        }

}

/*************************************************************/
/* Returns the numbers of seconds.  For example, "1 hour" == */
/* 3600                                                      */
/*************************************************************/

uintmax_t Sagan_Value_To_Seconds(char *type, uintmax_t number)
{

    /* Covers both plural and non-plural (ie - minute/minutes) */

    if (Sagan_strstr(type, "second"))
        {
            return(number);
        }

    if (Sagan_strstr(type, "minute"))
        {
            return(number * 60);
        }

    if (Sagan_strstr(type, "hour"))
        {
            return(number * 60 * 60);
        }

    if (Sagan_strstr(type, "day"))
        {
            return(number * 60 * 60 * 24);
        }

    if (Sagan_strstr(type, "week"))
        {
            return(number * 60 * 60 * 24 * 7);
        }

    if (Sagan_strstr(type, "month"))
        {
            return(number * 60 * 60 * 24 * 7 * 4);
        }

    if (Sagan_strstr(type, "year"))
        {
            return(number * 60 * 60 * 24 * 365);
        }

    Sagan_Log(S_WARN, "'%s' type is unknown!", type);
    return(0);

}
