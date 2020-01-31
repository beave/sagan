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

/* ignore-list.c
 *
 * Loads the "ignore list" into memory
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "ignore-list.h"
#include "sagan-config.h"

struct _Sagan_Ignorelist *SaganIgnorelist;
struct _SaganCounters *counters;
struct _SaganConfig *config;

/****************************************************************************
 * "ignore" list.
 ****************************************************************************/

void Load_Ignore_List ( void )
{

    FILE *droplist;

    char droplistbuf[1024] = { 0 };

    if (( droplist = fopen(config->sagan_droplistfile, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] No drop list/ignore list to load (%s)", __FILE__, __LINE__, config->sagan_droplistfile);
            config->sagan_droplist_flag=0;
        }

    while(fgets(droplistbuf, 1024, droplist) != NULL)
        {

            /* Skip comments and blank linkes */

            if (droplistbuf[0] == '#' || droplistbuf[0] == 10 || droplistbuf[0] == ';' || droplistbuf[0] == 32)
                {
                    continue;

                }
            else
                {

                    /* Allocate memory for references,  not comments */

                    SaganIgnorelist = (_Sagan_Ignorelist *) realloc(SaganIgnorelist, (counters->droplist_count+1) * sizeof(_Sagan_Ignorelist));

                    if ( SaganIgnorelist == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganIgnorelist. Abort!", __FILE__, __LINE__);
                        }

                    Remove_Return(droplistbuf);

                    strlcpy(SaganIgnorelist[counters->droplist_count].ignore_string, droplistbuf, sizeof(SaganIgnorelist[counters->droplist_count].ignore_string));

                    __atomic_add_fetch(&counters->droplist_count, 1, __ATOMIC_SEQ_CST);


                }
        }
}
