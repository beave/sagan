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

/* This controls the "pcre" rule options */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <pcre.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"

struct _Rule_Struct *rulestruct;


bool PcreS ( int rule_position, const char *syslog_message )
{


    int z = 0;
    int match = 0;
    int rc = 0;
    int ovector[PCRE_OVECCOUNT];


    for(z=0; z<rulestruct[rule_position].pcre_count; z++)
        {

            rc = pcre_exec( rulestruct[rule_position].re_pcre[z], rulestruct[rule_position].pcre_extra[z], syslog_message, (int)strlen(syslog_message), 0, 0, ovector, PCRE_OVECCOUNT);

            if ( rc > 0 )
                {
                    match++;
                }

        }

    if ( match == rulestruct[rule_position].pcre_count )
        {
            return(true);
        }

    return(false);

}
