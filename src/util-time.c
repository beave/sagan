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
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* util-time.c
 *
 * Time functions.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>

#include "sagan.h"
#include "util-time.h"
#include "parsers/strstr-asm/strstr-hook.h"

struct tm *Sagan_LocalTime(time_t timep, struct tm *result)
{
    return localtime_r(&timep, result);
}

/***************************************************************************/
/* CreateTimeString - Used in fast.log, etc.  Based off Suricata source.   */
/***************************************************************************/

void CreateTimeString (const struct timeval *ts, char *str, size_t size, bool type)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm*)Sagan_LocalTime(time, &local_tm);

    if ( type == 0 )
        {

            /* Suricata / Snort "fast.log" type */

            snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
                     t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
                     t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);

        }
    else
        {

            /* Old "alert log" type */

            snprintf(str, size, "%02d-%02d-%02d %02d:%02d:%02d.%06u",
                     t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
                     t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);

        }

}

/***************************************************************************
 * CreateIsoTimeString - Used in EVE & alert output.  Based off Suricata
 * source.
 ***************************************************************************/

void CreateIsoTimeString (const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm*)Sagan_LocalTime(time, &local_tm);
    char time_fmt[64] = { 0 };

    strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%S.%%06u%z", t);
    snprintf(str, size, time_fmt, ts->tv_usec);
}


/************************************************
 * Returns current epoch time in uint64_t format
 ************************************************/

uint64_t Return_Epoch( void )
{

    time_t t;
    struct tm *now;
    char timet[20] = { 0 };


    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    return(atol(timet));

}


/************************************************
 * This function should be removed and replaced
 ************************************************/

void Return_Date( uint32_t utime, char *str, size_t size )
{

    struct tm tm;
    char tmp[80];
    char time_buf[80];

    memset(&tm, 0, sizeof(struct tm));
    snprintf(tmp, sizeof(tmp) - 1, "%lu", (unsigned long)utime);

    strptime(tmp, "%s", &tm);
    strftime(time_buf, sizeof(time_buf), "%F", &tm);

    snprintf(str, size, "%s", time_buf);

}

/********************************************************************************
 * Return the "old" (non ISO) time - This function should be removed || replaced
 ********************************************************************************/

void Return_Time( uint32_t utime, char *str, size_t size )
{

    struct tm tm;

    char time_buf[80];
    char tmp[80];

    memset(&tm, 0, sizeof(struct tm));
    snprintf(tmp, sizeof(tmp) - 1, "%lu", (unsigned long)utime);

    strptime(tmp, "%s", &tm);
    strftime(time_buf, sizeof(time_buf), "%T", &tm);

    snprintf(str, size, "%s", time_buf);

}


/****************************************************************************
 * u32_Time_To_Human - Converts a 32/64 bit epoch time into a human
 * "readable" format.
 ****************************************************************************/

void u32_Time_To_Human ( uint32_t utime, char *str, size_t size )
{

    struct tm tm;
    char time_buf[80];
    char tmp[80];

    memset(&tm, 0, sizeof(struct tm));
    snprintf(tmp, sizeof(tmp) - 1, "%lu", (unsigned long)utime);

    strptime(tmp, "%s", &tm);
    strftime(time_buf, sizeof(time_buf), "%b %d %H:%M:%S %Y", &tm);

    snprintf(str, size, "%s", time_buf);

}


/*************************************************************
 * Returns the numbers of seconds.  For example, "1 hour" ==
 * 3600
 *************************************************************/

uint64_t Value_To_Seconds(char *type, uint64_t number)
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

    Sagan_Log(WARN, "'%s' type is unknown!", type);
    return(0);

}

