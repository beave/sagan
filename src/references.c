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

/* references.c
 *
 * Loads the references into memory.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "version.h"

#include "sagan.h"
#include "sagan-defs.h"
#include "references.h"
#include "rules.h"

struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct _Ref_Struct *refstruct;
struct _Rule_Struct *rulestruct;

void Load_Reference( const char *ruleset )
{

    FILE *reffile;

    char refbuf[1024];
    char *saveptr=NULL;
    char *tmptoken=NULL;
    char *laststring=NULL;

    int linecount=0;

    counters->refcount = 0;

    Sagan_Log(NORMAL, "Loading references.conf file. [%s]", ruleset);

    if (( reffile = fopen(ruleset, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open rule file %s. [%s]", __FILE__, __LINE__, ruleset, strerror(errno));
        }

    while(fgets(refbuf, 1024, reffile) != NULL)
        {

            linecount++;

            /* Skip comments and blank linkes */

            if (refbuf[0] == '#' || refbuf[0] == 10 || refbuf[0] == ';' || refbuf[0] == 32)
                {

                    continue;

                }

            /* Allocate memory for references,  not comments */

            refstruct = (_Ref_Struct *) realloc(refstruct, (counters->refcount+1) * sizeof(_Ref_Struct));

            if ( refstruct == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for refstruct. Abort!", __FILE__, __LINE__);
                }

            memset(&refstruct[counters->refcount], 0, sizeof(struct _Ref_Struct));

            strtok_r(refbuf, ":", &saveptr);
            tmptoken = strtok_r(NULL, " ", &saveptr);

            laststring = strtok_r(tmptoken, ",", &saveptr);

            if ( laststring == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] The file %s at line %d is improperly formated. Abort!", __FILE__, __LINE__, ruleset, linecount);
                }

            strlcpy(refstruct[counters->refcount].s_refid, laststring, sizeof(refstruct[counters->refcount].s_refid));

            laststring = strtok_r(NULL, ",", &saveptr);

            if ( laststring == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] The file %s at line %d is improperly formated. Abort!", __FILE__, __LINE__, ruleset, linecount);
                }

            strlcpy(refstruct[counters->refcount].s_refurl, laststring, sizeof(refstruct[counters->refcount].s_refurl));
            refstruct[counters->refcount].s_refurl[strlen(refstruct[counters->refcount].s_refurl)-1] = '\0';

            if (debug->debugload)
                {
                    Sagan_Log(DEBUG, "[D-%d] Reference: %s|%s", counters->refcount, refstruct[counters->refcount].s_refid, refstruct[counters->refcount].s_refurl);
                }

            counters->refcount++;

        }
    fclose(reffile);
    Sagan_Log(NORMAL, "%d references loaded.", counters->refcount);
}


/****************************************************************************/
/* This simple looks up references and returns a string with them formatted */
/* properly.  It gets passed the location of the rule in memory (based on   */
/* the rulecount.  This is used for sagan-alert.c and sagan-esmtp.c         */
/****************************************************************************/

// 0 == alert
// 1 == parsable.

void Reference_Lookup( int rulemem, int type, char *str, size_t size )
{

    char reftmp[256] = { 0 };

    int i=0;
    int b=0;

    char *tmptok=NULL;
    char *tmp=NULL;

    char reftype[25];
    char url[255];

    char refinfo[512];
    char refinfo2[512];

    for (i=0; i <= rulestruct[rulemem].ref_count; i++ )
        {

            strlcpy(refinfo, rulestruct[rulemem].s_reference[i], sizeof(refinfo));

            tmp = strtok_r(refinfo, ",", &tmptok);

            if ( tmp != NULL )
                {
                    strlcpy(reftype, tmp, sizeof(reftype));
                }
            else
                {
                    strlcpy(str, "", 1);
                    return;
                }

            tmp  = strtok_r(NULL, ",", &tmptok);

            if ( tmp != NULL )
                {
                    strlcpy(url, tmp, sizeof(url));
                }
            else
                {
                    strlcpy(str, "", 1);
                    return;
                }


            for ( b=0; b < counters->refcount; b++)
                {

                    if (!strcmp(refstruct[b].s_refid,  reftype))
                        {
                            if ( type == 0 )
                                {
                                    snprintf(refinfo2, sizeof(refinfo2)-1, "[Xref => %s%s]",  refstruct[b].s_refurl, url);
                                }

                            if ( type == 1 )
                                {
                                    snprintf(refinfo2, sizeof(refinfo2)-1, "Reference:%s%s\n", refstruct[b].s_refurl, url);
                                }

                            strlcat(reftmp,  refinfo2,  sizeof(reftmp));
                        }
                }
        }

    snprintf(str, size, "%s", reftmp);
}
