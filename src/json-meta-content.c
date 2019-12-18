/*                                                                                                  ** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>                                 **                                                                                                  ** This program is free software; you can redistribute it and/or modify                             ** it under the terms of the GNU General Public License Version 2 as                                ** published by the Free Software Foundation.  You may not use, modify or                           ** distribute this program under any other version of the GNU General                               ** Public License.                                                                                  **                                                                                                  ** This program is distributed in the hope that it will be useful,
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

struct _Rule_Struct *rulestruct;

bool JSON_Meta_Content(int rule_position, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL)
{

    int i=0;
    int a=0;
    int z=0;

    bool flag = false;

    for (i=0; i < rulestruct[rule_position].json_meta_content_count; i++)
        {

            for (a=0; a < SaganProcSyslog_LOCAL->json_count; a++)
                {

                    if ( !strcmp(SaganProcSyslog_LOCAL->json_key[a], rulestruct[rule_position].json_meta_content_key[i] ) )
                        {

                            for ( z = 0; z < rulestruct[rule_position].json_meta_content_containers[i].json_meta_counter; z++ )
                                {

                                    flag = false;

                                    if ( rulestruct[rule_position].json_meta_content_not[i] == false )
                                        {

                                            if ( rulestruct[rule_position].json_meta_content_case[i] == true )
                                                {

                                                    if ( Search_Nocase(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z], false,  rulestruct[rule_position].json_meta_strstr[i] ) )
                                                        {
                                                            flag = true;
                                                            break;
                                                        }
                                                }
                                            else
                                                {

                                                    if ( Search_Case(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z], rulestruct[rule_position].json_meta_strstr[i] ) )
                                                        {
                                                            flag = true;
                                                            break;
                                                        }
                                                }

                                        }
                                    else
                                        {

                                            if ( rulestruct[rule_position].json_meta_content_case[i] == true )
                                                {

                                                    if ( !Search_Nocase(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z],false, rulestruct[rule_position].json_meta_strstr[i] ))
                                                        {
                                                            flag = true;
                                                            break;
                                                        }
                                                }
                                            else
                                                {

                                                    if ( !Search_Case(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z], rulestruct[rule_position].json_meta_strstr[i] ))
                                                        {

                                                            flag = true;
                                                            break;
                                                        }
                                                }
                                        }
                                }

                            /* The last pass got _no_ hits.  No need to go
                               any further */

                            if ( flag == false )
                                {
                                    return(false);
                                }
                        }
                }
        }

    /* Got all matches */

    return(true);

}

