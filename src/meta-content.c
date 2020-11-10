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

/* meta-content.c - This allows content style "searching" that
 * involve variables.  For example,  if we wanted to search for "bob",
 * "frank" and "mary",  we'd typically need three content rules.
 * This allows one rule with the $USER variable for "bob", "frank" and
 * "mary".
 *
 * meta_content: "Username: %sagan%", $USERNAME"; meta_nocase;
 *
 * The %sagan% becomes whatever the variable holds.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "meta-content.h"
#include "rules.h"
#include "parsers/parsers.h"

extern struct _Rule_Struct *rulestruct;

bool Meta_Content(int rule_position, const char *syslog_message)
{

    int z=0;
    int meta_alter_num=0;
    int match=0;

    char meta_alter_content[MAX_SYSLOGMSG] = { 0 };

    bool rc = 0;

    for (z=0; z<rulestruct[rule_position].meta_content_count; z++)
        {

            meta_alter_num = 0;

            /* Meta_content: OFFSET */

            if ( rulestruct[rule_position].meta_offset[z] != 0 )
                {

                    if ( strlen(syslog_message) > rulestruct[rule_position].meta_offset[z] )
                        {

                            meta_alter_num = strlen(syslog_message) - rulestruct[rule_position].meta_offset[z];
                            strlcpy(meta_alter_content, syslog_message + (strlen(syslog_message) - meta_alter_num), meta_alter_num + 1);

                        }
                    else
                        {

                            meta_alter_content[0] = '\0';    /* The offset is larger than the message.  Set meta_content too NULL */

                        }

                }
            else
                {

                    strlcpy(meta_alter_content, syslog_message, sizeof(meta_alter_content));

                }


            /* Meta_content: DEPTH */

            if ( rulestruct[rule_position].meta_depth[z] != 0 )
                {

                    /* We do +2 to account for alter_count[0] and whitespace at the begin of syslog message */

                    strlcpy(meta_alter_content, meta_alter_content, rulestruct[rule_position].meta_depth[z] + 2);

                }

            /* Meta_content: DISTANCE */

            if ( rulestruct[rule_position].meta_distance[z] != 0 )
                {

                    meta_alter_num = strlen(syslog_message) - ( rulestruct[rule_position].meta_depth[z-1] + rulestruct[rule_position].meta_distance[z] + 1 );
                    strlcpy(meta_alter_content, syslog_message + (strlen(syslog_message) - meta_alter_num), meta_alter_num + 1);

                    /* Meta_ontent: WITHIN */

                    if ( rulestruct[rule_position].meta_within[z] != 0 )
                        {
                            strlcpy(meta_alter_content, meta_alter_content, rulestruct[rule_position].meta_within[z] + 1);

                        }

                }

            /* Search through the meta contents! */

            rc = Meta_Content_Search( meta_alter_content, rule_position, z );

            if ( rc == true )
                {
                    match++;
                }

        }

    /* Got positive results, return true */

    if ( match == rulestruct[rule_position].meta_content_count )
        {
            return(true);
        }

    return(false);

}

/*****************************************************************************/
/* Meta_Content_Search does the actual "searching" (or content!) of the data */
/*****************************************************************************/

bool Meta_Content_Search(char *syslog_msg, int rule_position, int meta_content_count)
{

    int z = meta_content_count;
    int i;

    /* Normal "meta_content" search */

    if ( rulestruct[rule_position].meta_content_not[z] == false )
        {
            for ( i=0; i<rulestruct[rule_position].meta_content_containers[z].meta_counter; i++ )
                {
                    if ( rulestruct[rule_position].meta_content_case[z] == true )
                        {

                            if (Sagan_stristr(syslog_msg, rulestruct[rule_position].meta_content_containers[z].meta_content_converted[i], true))
                                {
                                    return(true);
                                }
                        }
                    else
                        {

                            if (Sagan_strstr(syslog_msg, rulestruct[rule_position].meta_content_containers[z].meta_content_converted[i]))
                                {
                                    return(true);
                                }
                        }
                }

            return(false);

        }
    else
        {

            for ( i=0; i<rulestruct[rule_position].meta_content_containers[z].meta_counter; i++ )
                {

                    if ( rulestruct[rule_position].meta_content_case[z] == true )
                        {

                            if (Sagan_stristr(syslog_msg, rulestruct[rule_position].meta_content_containers[z].meta_content_converted[i], true))
                                {
                                    return(false);
                                }
                        }
                    else
                        {

                            if (Sagan_strstr(syslog_msg, rulestruct[rule_position].meta_content_containers[z].meta_content_converted[i]))
                                {
                                    return(false);
                                }
                        }
                }

            return(true);

        } /* End of "else" meta_content_not[z] == 0 */

} /* End of Meta_Content_Search() */

