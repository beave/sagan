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

/* This handles "content" rule option */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "content.h"

#include "parsers/parsers.h"

extern struct _Rule_Struct *rulestruct;


bool Content ( int rule_position, const char *syslog_message )
{

    int z = 0;
    int alter_num = 0;
    char alter_content[MAX_SYSLOGMSG] = { 0 };

    /* Content: OFFSET */

    alter_num = 0;

    for(z=0; z<rulestruct[rule_position].content_count; z++)
        {


            if ( rulestruct[rule_position].s_offset[z] != 0 )
                {

                    if ( strlen(syslog_message) > rulestruct[rule_position].s_offset[z] )
                        {

                            alter_num = strlen(syslog_message) - rulestruct[rule_position].s_offset[z];
                            strlcpy(alter_content, syslog_message + (strlen(syslog_message) - alter_num), alter_num + 1);

                        }
                    else
                        {

                            alter_content[0] = '\0';    /* The offset is larger than the message.  Set content too NULL */

                        }

                }
            else
                {

                    strlcpy(alter_content, syslog_message, sizeof(alter_content));

                }

            /* Content: DEPTH */

            if ( rulestruct[rule_position].s_depth[z] != 0 )
                {

                    /* We do +2 to account for alter_count[0] and whitespace at the begin of syslog message */

                    strlcpy(alter_content, alter_content, rulestruct[rule_position].s_depth[z] + 2);

                }

            /* Content: DISTANCE */

            if ( rulestruct[rule_position].s_distance[z] != 0 )
                {

                    alter_num = strlen(syslog_message) - ( rulestruct[rule_position].s_depth[z-1] + rulestruct[rule_position].s_distance[z] + 1);
                    strlcpy(alter_content, syslog_message + (strlen(syslog_message) - alter_num), alter_num + 1);

                    /* Content: WITHIN */

                    if ( rulestruct[rule_position].s_within[z] != 0 )
                        {
                            strlcpy(alter_content, alter_content, rulestruct[rule_position].s_within[z] + 1);

                        }

                }

            /* If case insensitive - nocase */

            if ( rulestruct[rule_position].content_case[z] == true )
                {

                    if ( rulestruct[rule_position].content_not[z] == false )
                        {


                            if ( !Sagan_stristr(alter_content, rulestruct[rule_position].content[z], true))
                                {
                                    return(false);
                                }

                        }
                    else
                        {

                            /* content not */

                            if ( Sagan_stristr(alter_content, rulestruct[rule_position].content[z], true))
                                {
                                    return(false);
                                }

                        }

                }
            else
                {

                    if ( rulestruct[rule_position].content_not[z] == false )
                        {

                            if ( !Sagan_strstr(alter_content, rulestruct[rule_position].content[z]))
                                {
                                    return(false);
                                }

                        }
                    else
                        {

                            /* content not */

                            if ( Sagan_strstr(alter_content, rulestruct[rule_position].content[z]))
                                {
                                    return(false);
                                }

                        }
                }
        }

    return(true);
}


