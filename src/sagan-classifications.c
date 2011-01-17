/*
** Copyright (C) 2009-2011 Softwink, Inc. 
** Copyright (C) 2009-2011 Champ Clark III <champ@softwink.com>
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


struct class_struct *classstruct;
int classcount;
sbool debugload;

char ruleset[MAXPATH];

void load_classifications( void )  { 

FILE *classfile;

char classbuf[CLASSBUF];
char *saveptr=NULL;
char *firststring=NULL;
char *tmptoken=NULL;
char *laststring=NULL;
char tmpbuf2[5];
int  linecount=0;

sagan_log(0, "Loading classifications.conf file. [%s]", ruleset);

         if (( classfile = fopen(ruleset, "r" )) == NULL ) {
             sagan_log(1, "[%s, line %d] Cannot open rule file (%s)", __FILE__,  __LINE__, ruleset);
             }

while(fgets(classbuf, sizeof(classbuf), classfile) != NULL) {

     linecount++;

     /* Skip comments and blank linkes */
 
     if (classbuf[0] == '#' || classbuf[0] == 10 || classbuf[0] == ';' || classbuf[0] == 32) { 
     continue;
     } else { 
     /* Allocate memory for classifications,  but not comments */
     classstruct = (class_struct *) realloc(classstruct, (classcount+1) * sizeof(class_struct));
     }

     firststring = strtok_r(classbuf, ":", &saveptr);
     tmptoken = strtok_r(NULL, ":" , &saveptr);

     laststring = strtok_r(tmptoken, ",", &saveptr);
     remspaces(laststring);
     snprintf(classstruct[classcount].s_shortname, sizeof(classstruct[classcount].s_shortname), "%s", laststring);

     laststring = strtok_r(NULL, ",", &saveptr);
     snprintf(classstruct[classcount].s_desc, sizeof(classstruct[classcount].s_desc), "%s", laststring);

     laststring = strtok_r(NULL, ",", &saveptr);
     snprintf(tmpbuf2, sizeof(tmpbuf2), "%s", laststring);
     tmpbuf2[strlen(tmpbuf2)-1] = '\0';
     classstruct[classcount].s_priority=atoi(tmpbuf2);

     if ( classstruct[classcount].s_priority == 0 ) sagan_log(1, "[%s, line %d] Classification error at line number %d in %s", __FILE__, __LINE__, linecount, ruleset);

     if (debugload) sagan_log(0, "[D-%d] Classification: %s|%s|%d", classcount, classstruct[classcount].s_shortname, classstruct[classcount].s_desc, classstruct[classcount].s_priority);
		      
     classcount++;

} 
fclose(classfile);

sagan_log(0, "%d classifications loaded", classcount);

}

char *classlookup( char *classtype ) {

int i; 
char *ret;

for ( i=0; i < classcount; i++ ) { 

if ( !strcmp( classstruct[i].s_shortname, classtype ) )  { 
   ret=classstruct[i].s_desc;
   return(ret);
   }
}

sagan_log(0, "Hmmm.. Classification not found for a classification loaded?!?");
ret="Classification not found!";
return(ret);

}

