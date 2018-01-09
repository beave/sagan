/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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

struct _Rule_Struct *rulestruct;

int Meta_Content_Search(char *syslog_msg, int rule_position , int meta_content_count)
{

    int z = meta_content_count;
    int i;

    /* Normal "meta_content" search */

    if ( rulestruct[rule_position].meta_content_not[z] == 0 )
        {
            for ( i=0; i<rulestruct[rule_position].meta_content_containers[z].meta_counter; i++ )
                {
                    if ( rulestruct[rule_position].meta_content_case[z] == 1 )
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
                    if ( rulestruct[rule_position].meta_content_case[z] == 1 )
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
