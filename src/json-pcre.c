/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**                                                                                                  ** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* json-pcre.c controls how 'json_pcre: "{key}", "/{pcre}/";' rule options
   works.  This works similar to "pcre" but on JSON key/value pairs */

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

#include "parsers/parsers.h"

struct _Rule_Struct *rulestruct;

bool JSON_Pcre(int rule_position, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL)
{

    int i=0;
    int a=0;
    int rc=0;

    int ovector[PCRE_OVECCOUNT];

    for (i=0; i < rulestruct[rule_position].json_pcre_count; i++)
        {

            for (a=0; a < SaganProcSyslog_LOCAL->json_count; a++)
                {

                    if ( !strcmp(SaganProcSyslog_LOCAL->json_key[a], rulestruct[rule_position].json_pcre_key[i] ) )
                        {

                            rc = pcre_exec( rulestruct[rule_position].json_re_pcre[i], rulestruct[rule_position].json_pcre_extra[i], SaganProcSyslog_LOCAL->json_value[a], (int)strlen(SaganProcSyslog_LOCAL->json_value[a]), 0, 0, ovector, PCRE_OVECCOUNT);

                            /* If it's _not_ a match, no need to test other conditions */

                            if ( rc < 0 )
                                {
                                    return(false);
                                }
                        }
                }
        }

    /* All conditions matched,  so return true */

    return(true);
}

