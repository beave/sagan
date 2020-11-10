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

/* key.c
 *
 * This runs as a thread for stdin.  This allows users,  when running
 * in the foreground,  to hit "enter" to see statistics of sagan.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_SYSLOG

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>


#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif


#include "version.h"

#include "sagan.h"
#include "sagan-config.h"
#include "sagan-defs.h"
#include "rules.h"
#include "tracking-syslog.h"

extern struct _SaganConfig *config;
extern struct _SaganCounters *counters;
extern struct _Sagan_Ruleset_Track *Ruleset_Track;


void RuleTracking_Syslog( void )
{

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("SaganRuleTrack");
#endif

    int i = 0;
    bool flag = 0;


    time_t t;
    char timet[20];
    struct tm *now;
    int seconds = 0;



    int uptime_days;
    int uptime_abovedays;
    int uptime_hours;
    int uptime_abovehours;
    int uptime_minutes;
    int uptime_seconds;

    while(1)
        {

            sleep(config->rule_tracking_time);

            t = time(NULL);
            now=localtime(&t);
            strftime(timet, sizeof(timet), "%s",  now);
            seconds = atol(timet) - atol(config->sagan_startutime);

            uptime_days = seconds / 86400;
            uptime_abovedays = seconds % 86400;
            uptime_hours = uptime_abovedays / 3600;
            uptime_abovehours = uptime_abovedays % 3600;
            uptime_minutes = uptime_abovehours / 60;
            uptime_seconds = uptime_abovehours % 60;

            openlog("sagan", LOG_PID, LOG_DAEMON);

            syslog(LOG_INFO, "---[Sagan]----------------------------");
            syslog(LOG_INFO, "Uptime: %d days, %d hours, %d minutes, %d seconds.", uptime_days, uptime_hours, uptime_minutes, uptime_seconds);

            for ( i = 0; i < counters->ruleset_track_count; i++ )
                {
                    if ( Ruleset_Track[i].trigger == true )
                        {
                            syslog(LOG_INFO, "Fired ruleset: %s", Ruleset_Track[i].ruleset);
                            flag = true;
                        }
                }

            if ( flag == false )
                {
                    syslog(LOG_INFO, "Fired rulesets: No rulesets have fired.");
                }


            for ( i = 0; i < counters->ruleset_track_count; i++ )
                {
                    if ( Ruleset_Track[i].trigger == false )
                        {
                            syslog(LOG_INFO, "Non-fired ruleset: %s", Ruleset_Track[i].ruleset);
                            flag = true;
                        }
                }

            if ( flag == false )
                {
                    syslog(LOG_INFO, "Non-fired rulesets: All rules fired");
                }


            closelog();

        }

}

#endif
