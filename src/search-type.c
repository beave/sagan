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

/* search-type.c is used by json-content.c & json-meta-content.c to determine
   if a search will be done via strcmp/strcasecmp or Sagan_strstr/Sagan_stristr.
   This works with the "json_strstr", "json_meta_strstr" or lack of (strcmp).  */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include "sagan.h"
#include "sagan-defs.h"
#include "search-type.h"

#include "parsers/parsers.h"

bool Search_Case ( const char *haystack, const char *needle, bool type)
{

    /* Search via Sagan_strstr */

    if ( type == true )
        {
            if ( Sagan_strstr( haystack, needle) )
                {
                    return(true);
                }

            return(false);

        }
    else
        {

            /* Search via strcmp */

            if ( !strcmp( haystack, needle ) )
                {
                    return(true);
                }

            return(false);
        }


}

bool Search_Nocase ( const char *haystack, const char *needle, bool needle_lower, bool type)
{

    /* Search via Sagan_stristr (case insenstive) */

    if ( type == true )
        {
            if ( Sagan_stristr( haystack, needle, type) )
                {
                    return(true);
                }

            return(false);

        }
    else
        {

            /* Search via strcasecmp */

            if ( !strcasecmp( haystack, needle ) )
                {
                    return(true);
                }

            return(false);
        }

}

