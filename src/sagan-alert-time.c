/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-alert-time.c
 *
 * This is for time based alerting.  This allows rules to have specific
 * times/days to trigger or otherwise be ignored.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-alert-time.h"
#include "sagan-rules.h"

struct _Rule_Struct *rulestruct;

int Sagan_Check_Time(rule_number)
{

    char ct[64] = { 0 };
    char buf[80] = { 0 };

    uint64_t utime_current;
    int day_current;

    uint64_t utime_start;
    uint64_t utime_end;

    /* For current mktime */
    time_t     now;
    struct     tm  ts;

    /* For current utime */
    time_t t;
    struct tm *now_utime;

    /* For mktime */

    struct     tm t_start;
    time_t     start_time_t;

    struct     tm t_end;
    time_t     end_time_t;

    int        sagan_year;
    int        sagan_month;
    int        sagan_day;
    int	   sagan_day_end;  /* Used for times that run overs day changes */

    /* Get current utime / and day of the week */

    t = time(NULL);
    now_utime=localtime(&t);
    strftime(ct, sizeof(ct), "%s",  now_utime);
    utime_current = atol(ct);
    day_current = localtime(&t)->tm_wday;

    time(&now);
    ts = *localtime(&now);

    strftime(buf, sizeof(buf), "%Y", &ts);
    sagan_year = atoi(buf);

    strftime(buf, sizeof(buf), "%m", &ts);
    sagan_month = atoi(buf) - 1;

    strftime(buf, sizeof(buf), "%d", &ts);
    sagan_day = atoi(buf);

    /* Construct start date/time */

    t_start.tm_year = sagan_year-1900;
    t_start.tm_mon = sagan_month;           // Month, 0 - jan
    t_start.tm_mday = sagan_day;            // Day of the month
    t_start.tm_hour = rulestruct[rule_number].alert_start_hour;
    t_start.tm_min = rulestruct[rule_number].alert_start_minute;
    t_start.tm_sec = 0;
    t_start.tm_isdst = -1;        // Is DST on? 1 = yes, 0 = no, -1 = unknown - Test this?
    start_time_t = mktime(&t_start);
    utime_start = (long) start_time_t;


    /* mktime takes into account sagan_day = 32, 33, etc.  No need for conversion as
       mktime will take care of it for us */


    if ( rulestruct[rule_number].alert_start_hour > rulestruct[rule_number].alert_end_hour )
        {
            sagan_day_end = sagan_day +1;
        }
    else
        {
            sagan_day_end = sagan_day;
        }


    /* Construct end date/time */

    t_end.tm_year = sagan_year-1900;
    t_end.tm_mon = sagan_month;           // Month, 0 - jan
    t_end.tm_mday = sagan_day_end;        // Day of the week
    t_end.tm_hour = rulestruct[rule_number].alert_end_hour;
    t_end.tm_min = rulestruct[rule_number].alert_end_minute;
    t_end.tm_sec = 0;
    t_end.tm_isdst = -1;        // Is DST on? 1 = yes, 0 = no, -1 = unknown - Test this?
    end_time_t = mktime(&t_end);
    utime_end = (long) end_time_t;

    /* Is this a valid day to trigger? */
    if (Sagan_Check_Day(rulestruct[rule_number].alert_days, day_current))
        {

            /* If day is valid,  check the time */
            if ( utime_current >= utime_start && utime_current <= utime_end ) return(true);
        }


    return(false);
}


/****************************************************************************/
/* Sagan_Check_Day - Returns days if found in the "day" bitmask             */
/****************************************************************************/

int Sagan_Check_Day(unsigned char day, int day_current)
{

    if ( day_current == 0 )
        {
            if (( day & SUNDAY ) == SUNDAY ) return(true);
        }

    if ( day_current == 1 )
        {
            if (( day & MONDAY ) == MONDAY ) return(true);
        }

    if ( day_current == 2 )
        {
            if (( day & TUESDAY ) == TUESDAY ) return(true);
        }

    if ( day_current == 3 )
        {
            if (( day & WEDNESDAY ) == WEDNESDAY ) return(true);
        }

    if ( day_current == 4 )
        {
            if (( day & THURSDAY ) == THURSDAY ) return(true);
        }

    if ( day_current == 5 )
        {
            if (( day & FRIDAY ) == FRIDAY ) return(true);
        }

    if ( day_current == 6 )
        {
            if (( day & SATURDAY ) == SATURDAY ) return(true);
        }

    return(false);

}


