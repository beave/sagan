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

/* sagan-classifications.c
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
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <pcre.h>

#include "version.h"

#include "sagan.h"

struct _SaganCounters *counters;
struct _Class_Struct *classstruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

void Load_Classifications( const char *ruleset )  { 


FILE *classfile;

char classbuf[CLASSBUF];
char *saveptr=NULL;
char *firststring=NULL;
char *tmptoken=NULL;
char *laststring=NULL;
char tmpbuf2[5];
int  linecount=0;

Sagan_Log(0, "Loading classifications.conf file. [%s]", ruleset);

         if (( classfile = fopen(ruleset, "r" )) == NULL ) {
             Sagan_Log(1, "[%s, line %d] Cannot open rule file (%s)", __FILE__,  __LINE__, ruleset);
             }

while(fgets(classbuf, sizeof(classbuf), classfile) != NULL) {

     linecount++;

     /* Skip comments and blank linkes */
 
     if (classbuf[0] == '#' || classbuf[0] == 10 || classbuf[0] == ';' || classbuf[0] == 32) { 
     continue;
     } else { 
     /* Allocate memory for classifications,  but not comments */
     classstruct = (_Class_Struct *) realloc(classstruct, (counters->classcount+1) * sizeof(_Class_Struct));
     }

     firststring = strtok_r(classbuf, ":", &saveptr);
     tmptoken = strtok_r(NULL, ":" , &saveptr);

     laststring = strtok_r(tmptoken, ",", &saveptr);
     Remove_Spaces(laststring);
     snprintf(classstruct[counters->classcount].s_shortname, sizeof(classstruct[counters->classcount].s_shortname), "%s", laststring);

     laststring = strtok_r(NULL, ",", &saveptr);
     snprintf(classstruct[counters->classcount].s_desc, sizeof(classstruct[counters->classcount].s_desc), "%s", laststring);

     laststring = strtok_r(NULL, ",", &saveptr);
     snprintf(tmpbuf2, sizeof(tmpbuf2), "%s", laststring);
     tmpbuf2[strlen(tmpbuf2)-1] = '\0';
     classstruct[counters->classcount].s_priority=atoi(tmpbuf2);

     if ( classstruct[counters->classcount].s_priority == 0 ) Sagan_Log(1, "[%s, line %d] Classification error at line number %d in %s", __FILE__, __LINE__, linecount, ruleset);

     if (debug->debugload) Sagan_Log(0, "[D-%d] Classification: %s|%s|%d", counters->classcount, classstruct[counters->classcount].s_shortname, classstruct[counters->classcount].s_desc, classstruct[counters->classcount].s_priority);
		      
     counters->classcount++;

} 
fclose(classfile);

Sagan_Log(0, "%d classifications loaded", counters->classcount);

}
