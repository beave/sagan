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

/* json-meta-content.c controls how the 'json_meta_content: "{key}", {val1},{val2},{val3}....;"
   works.  Similar to "meta_content" but works on JSON key/value pairs. */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "json-meta-content.h"
#include "search-type.h"

#include "parsers/parsers.h"

extern struct _Rule_Struct *rulestruct;

bool JSON_Meta_Content(int rule_position, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL)
{

    int i=0;
    int a=0;

    int rc=0;
    int match = 0;

    for (i=0; i < rulestruct[rule_position].json_meta_content_count; i++)
        {

            for (a=0; a < SaganProcSyslog_LOCAL->json_count; a++)
                {

                    /* Locate the key (if it's avaliable */

                    if ( !strcmp(SaganProcSyslog_LOCAL->json_key[a], rulestruct[rule_position].json_meta_content_key[i] ) )
                        {

                            /* Key found, test for json_meta_content */

                            rc = JSON_Meta_Content_Search(rule_position, SaganProcSyslog_LOCAL->json_value[a], i );


                            /* Got hit */

                            if ( rc == true )
                                {
                                    match++;
                                }
                        }
                }
        }

    /* Does the number of json_meta_contents match what we expect? */

    if ( match == rulestruct[rule_position].json_meta_content_count )
        {
            return(true);
        }

    return(false);

}

/*******************************************************************************/
/* JSON_Meta_Content_Search - Does the actual "work" involved in determinining */
/* a "json_meta_content" hit.                                                  */
/*******************************************************************************/

bool JSON_Meta_Content_Search(int rule_position, const char *json_string, int i )
{

    int z = 0;

    if ( rulestruct[rule_position].json_meta_content_not[i] == false )
        {

            /* Standard "json_meta_content" (without !) */

            for ( z = 0; z < rulestruct[rule_position].json_meta_content_containers[i].json_meta_counter; z++ )
                {

                    if ( rulestruct[rule_position].json_meta_content_case[i] == true )
                        {

                            if ( Search_Nocase(json_string, rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z], false,  rulestruct[rule_position].json_meta_strstr[i] ) )
                                {
                                    return(true);
                                }
                        }
                    else
                        {

                            if ( Search_Case(json_string, rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z], rulestruct[rule_position].json_meta_strstr[i] ) )
                                {
                                    return(true);
                                }
                        }

                }

            return(false);
        }

    else

        {

            for ( z = 0; z < rulestruct[rule_position].json_meta_content_containers[i].json_meta_counter; z++ )
                {

                    /* "json_meta_content:!" */

                    if ( rulestruct[rule_position].json_meta_content_case[i] == true )
                        {

                            if ( Search_Nocase(json_string, rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z], false,  rulestruct[rule_position].json_meta_strstr[i] ) )
                                {
                                    return(false);
                                }
                        }
                    else
                        {

                            if ( Search_Case(json_string, rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z], rulestruct[rule_position].json_meta_strstr[i] ) )
                                {
                                    return(false);
                                }
                        }

                }

            return(true);

        }

    return(false);
}
