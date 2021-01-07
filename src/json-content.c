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

/* json-content.c controls the 'json-content: "{key}", "{content}";" rule option.
   This works similar to "content" but searches json key/value pairs */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "json-content.h"
#include "search-type.h"

#include "parsers/parsers.h"

extern struct _Rule_Struct *rulestruct;

bool JSON_Content(int rule_position, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL)
{

    int i = 0;
    int a = 0;

    bool key_search = false;

    for (i=0; i < rulestruct[rule_position].json_content_count; i++)
        {

            key_search = false;

            for (a=0; a < SaganProcSyslog_LOCAL->json_count; a++)
                {

                    /* Search for the "key" specified in json_content */

                    if ( !strcmp(SaganProcSyslog_LOCAL->json_key[a], rulestruct[rule_position].json_content_key[i] ) )
                        {

                            key_search = true;

                            /* Key was found,  is this a "nocase" rule or is it case sensitive */

                            if ( rulestruct[rule_position].json_content_case[i] == true )
                                {

                                    /* Is this a json_content or json_content:! */

                                    if ( rulestruct[rule_position].json_content_not[i] == false )
                                        {

                                            if ( Search_Nocase(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_content_content[i], false, rulestruct[rule_position].json_content_strstr[i] ) == false  )
                                                {

                                                    return(false);

                                                }

                                        }
                                    else
                                        {

                                            if ( Search_Nocase(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_content_content[i], false, rulestruct[rule_position].json_content_strstr[i] ) == true )
                                                {
                                                    return(false);
                                                }


                                        }

                                }
                            else
                                {

                                    /* Case sensitive */

                                    if ( rulestruct[rule_position].json_content_not[i] == false )
                                        {

                                            if ( Search_Case(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_content_content[i], rulestruct[rule_position].json_content_strstr[i]) ==  false )
                                                {
                                                    return(false);
                                                }

                                        }
                                    else
                                        {

                                            if ( Search_Case(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_content_content[i], rulestruct[rule_position].json_content_strstr[i]) == true )
                                                {
                                                    return(false);
                                                }

                                        }

                                }
                        }
                }

            /* If we don't find the key, there is no point going any further */

            if ( key_search == false )
                {
                    return(false);
                }

        }

    /* If everything lines up,  we have a full json_content match */

    return(true);

}


