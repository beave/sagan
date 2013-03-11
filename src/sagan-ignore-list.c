/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-ignore-list.c
 *
 * Loads the "ignore list" into memory
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>

#include "sagan.h"

struct _Sagan_Droplist *SaganDroplist;
struct _SaganCounters *counters;
struct _SaganConfig *config;

/****************************************************************************/
/* "ignore" list.
/****************************************************************************/

void Load_Ignore_List ( void ) { 

FILE *droplist;

char droplistbuf[1024] = { 0 };


if ( config->sagan_droplist_flag ) {

if (( droplist = fopen(config->sagan_droplistfile, "r" )) == NULL ) {
   Sagan_Log(1, "[%s, line %d] No drop list/ignore list to load (%s)", __FILE__, __LINE__, config->sagan_droplistfile);
   config->sagan_droplist_flag=0;
   }

while(fgets(droplistbuf, 1024, droplist) != NULL) {

     /* Skip comments and blank linkes */

     if (droplistbuf[0] == '#' || droplistbuf[0] == 10 || droplistbuf[0] == ';' || droplistbuf[0] == 32) {
     continue;

     } else {

     /* Allocate memory for references,  not comments */
     SaganDroplist = (_Sagan_Droplist *) realloc(SaganDroplist, (counters->droplist_count+1) * sizeof(_Sagan_Droplist));
     snprintf(SaganDroplist[counters->droplist_count].ignore_string, sizeof(SaganDroplist[counters->droplist_count].ignore_string), "%s", Remove_Return(droplistbuf));
     counters->droplist_count++;
     }
    }
   }
}
