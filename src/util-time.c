/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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

#include "sagan.h"
#include "util-time.h"

struct tm *Sagan_LocalTime(time_t timep, struct tm *result)
{
    return localtime_r(&timep, result);
}


void CreateTimeString (const struct timeval *ts, char *str, size_t size, sbool type)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm*)Sagan_LocalTime(time, &local_tm);

    if ( type == 0 ) {

        /* Suricata / Snort "fast.log" type */

        snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
                 t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
                 t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);

    } else {

        /* Old "alert log" type */

        snprintf(str, size, "%02d-%02d-%02d %02d:%02d:%02d.%06u",
                 t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
                 t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);

    }

}


void CreateIsoTimeString (const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm*)Sagan_LocalTime(time, &local_tm);
    char time_fmt[64] = { 0 };

    strftime(time_fmt, sizeof(time_fmt), "%Y-%m-%dT%H:%M:%S.%%06u%z", t);
    snprintf(str, size, time_fmt, ts->tv_usec);
}
