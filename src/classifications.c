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

/* classifications.c
 *
 * Loads the classifications file into memory for future use.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "version.h"

#include "sagan.h"
#include "sagan-defs.h"
#include "gen-msg.h"
#include "classifications.h"

extern struct _SaganCounters *counters;
extern struct _Class_Struct *classstruct;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;

void Load_Classifications( const char *ruleset )
{

    FILE *classfile;

    char classbuf[CLASSBUF];
    char *saveptr=NULL;
    char *tmptoken=NULL;
    char *laststring=NULL;
    char tmpbuf2[5];
    int  linecount=0;

    __atomic_store_n (&counters->classcount, 0, __ATOMIC_SEQ_CST);

    Sagan_Log(NORMAL, "Loading classifications.conf file. [%s]", ruleset);

    if (( classfile = fopen(ruleset, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open rule file %s. [%s]", __FILE__,  __LINE__, ruleset, strerror(errno) );
        }

    while(fgets(classbuf, sizeof(classbuf), classfile) != NULL)
        {

            linecount++;

            /* Skip comments and blank linkes */

            if (classbuf[0] == '#' || classbuf[0] == 10 || classbuf[0] == ';' || classbuf[0] == 32)
                {
                    continue;
                }

            /* Allocate memory for classifications,  but not comments */

            classstruct = (_Class_Struct *) realloc(classstruct, (counters->classcount+1) * sizeof(_Class_Struct));

            if ( classstruct == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for classstruct. Abort!", __FILE__, __LINE__);
                }

            memset(&classstruct[counters->classcount], 0, sizeof(struct _Class_Struct));

            strtok_r(classbuf, ":", &saveptr);
            tmptoken = strtok_r(NULL, ":", &saveptr);

            laststring = strtok_r(tmptoken, ",", &saveptr);

            if ( laststring == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] The file %s at line %d is improperly formated. Abort!", __FILE__, __LINE__, ruleset, linecount);
                }

            Remove_Spaces(laststring);
            strlcpy(classstruct[counters->classcount].s_shortname, laststring, sizeof(classstruct[counters->classcount].s_shortname));

            laststring = strtok_r(NULL, ",", &saveptr);

            if ( laststring == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] The file %s at line %d is improperly formated. Abort!", __FILE__, __LINE__, ruleset, linecount);
                }

            strlcpy(classstruct[counters->classcount].s_desc, laststring, sizeof(classstruct[counters->classcount].s_desc));

            laststring = strtok_r(NULL, ",", &saveptr);

            if ( laststring == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] The file %s at line %d is improperly formated. Abort!", __FILE__, __LINE__, ruleset, linecount);
                }

            strlcpy(tmpbuf2, laststring, sizeof(tmpbuf2));
            classstruct[counters->classcount].s_priority=atoi(tmpbuf2);

            if ( classstruct[counters->classcount].s_priority == 0 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Classification error at line number %d in %s", __FILE__, __LINE__, linecount, ruleset);
                }

            if (debug->debugload)
                {
                    Sagan_Log(DEBUG, "[D-%d] Classification: %s|%s|%d", counters->classcount, classstruct[counters->classcount].s_shortname, classstruct[counters->classcount].s_desc, classstruct[counters->classcount].s_priority);
                }

            __atomic_add_fetch(&counters->classcount, 1, __ATOMIC_SEQ_CST);

        }
    fclose(classfile);

    Sagan_Log(NORMAL, "%d classifications loaded", counters->classcount);

}

/****************************************************************************
 * Classtype_Lookup - Simple routine that looks up the classtype
 * (s_shortname) and returns the classtype's description
 ****************************************************************************/

int Classtype_Lookup( const char *classtype, char *str, size_t size )
{

    int i;

    for (i = 0; i < counters->classcount; i++)
        {

            if (!strcmp(classtype, classstruct[i].s_shortname))
                {
                    snprintf(str, size, "%s", classstruct[i].s_desc);
                    return 0;
                }
        }


    snprintf(str, sizeof("UNKNOWN"), "UNKNOWN");
    return -1;
}

