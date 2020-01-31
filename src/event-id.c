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

/* event-id.c
 *
 * This work in conjunction with the "event_id" rule option.
 *
 * This searches for a event id based off the type of data it has received.  Think
 * of Microsoft Windows logs that have "event id". However,  this function is not
 * restricted to Microsoft logs! If the event ID has already been parsed via
 * JSON or liblognorm,  that value is used.  If the log has no "parsed" values,
 * we treat it like a traditional Windows logs.  Most programs (NXlog, Evtsys, etc),
 * place the event ID at the front of the log line.  For example.
 *
 * 1234: log message here
 *
 * In that case,  we do the equivalant the following:
 *
 * content: " 1234|3a| "; offset: 0; depth: 8;
 *
 * Event ID's are stored as "strings".  This allows for greater flexibility with
 * event IDs.  For example,  0001234 doesn't get translated to 1234.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "event-id.h"

#include "parsers/parsers.h"


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;

bool Event_ID ( int position, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    char alter_message[MAX_SYSLOGMSG] = { 0 };
    char tmp_content[9] = { 0 };

    int i = 0;


    /* If we do _not_ have a decoded JSON event_id,  we attempt to find it via a traditional
       way.  This is the equivalent of:

       content: " 1234|3a| "; depth: 8;

       1234 == the event ID.  This is how most logging programs (NXlog, Evtsys, etc) record the
       event ID. */


    if ( SaganProcSyslog_LOCAL->event_id[0] == '\0' )
        {

            for (i = 0; i < rulestruct[position].event_id_count; i++ )
                {

                    /* Basically - depth: 8; offset: 0; */

                    strlcpy(alter_message, SaganProcSyslog_LOCAL->syslog_message, 8);
                    tmp_content[0] = '\0';

                    /* New equivalent to a "content" */

                    snprintf(tmp_content, sizeof(tmp_content), " %s: ", rulestruct[position].event_id[i]);

                    /* Search.  If we find it,  return true! */

                    if ( Sagan_stristr(alter_message, tmp_content, 0 ))
                        {
                            return(true);
                        }
                }

            return(false);

        }
    else
        {

            /* If we have a decoded "event id" via JSON/liblognorm,  we can use that
               value instead */


            for (i = 0; i < rulestruct[position].event_id_count; i++ )
                {

                    if ( !strcmp(rulestruct[position].event_id[i], SaganProcSyslog_LOCAL->event_id ) )
                        {
                            return(true);
                        }

                }

            return(false);
        }


}
