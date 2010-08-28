/*
** Copyright (C) 2009-2010 Softwink, Inc. 
** Copyright (C) 2009-2010 Champ Clark III <champ@softwink.com>
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

/* sagan-references.c 
 *
 * Loads the references into memory. 
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

struct ref_struct *refstruct;
struct rule_struct *rulestruct;

int refcount;
int devdebug;

char ruleset[1024];

void load_reference( void )  { 

FILE *reffile;

char refbuf[1024];
char *saveptr=NULL;
char *firststring=NULL;
char *tmptoken=NULL;
char *laststring=NULL;


sagan_log(0, "Loading references.conf file. [%s]" , ruleset);

if (( reffile = fopen(ruleset, "r" )) == NULL ) {
   sagan_log(1, "[%s, line %d] Cannot open rule file (%s)", __FILE__, __LINE__, ruleset);
   }
						             
while(fgets(refbuf, 1024, reffile) != NULL) {

     /* Skip comments and blank linkes */
 
     if (refbuf[0] == '#' || refbuf[0] == 10 || refbuf[0] == ';' || refbuf[0] == 32) {
     continue;
     } else {
     /* Allocate memory for references,  not comments */
     refstruct = (ref_struct *) realloc(refstruct, (refcount+1) * sizeof(ref_struct));
     }

     firststring = strtok_r(refbuf, ":", &saveptr);
     tmptoken = strtok_r(NULL, " " , &saveptr);

     laststring = strtok_r(tmptoken, ",", &saveptr);
     snprintf(refstruct[refcount].s_refid, sizeof(refstruct[refcount].s_refid), "%s", laststring);
     
     laststring = strtok_r(NULL, ",", &saveptr);
     snprintf(refstruct[refcount].s_refurl, sizeof(refstruct[refcount].s_refurl), "%s", laststring);
     refstruct[refcount].s_refurl[strlen(refstruct[refcount].s_refurl)-1] = '\0';

    if (devdebug) sagan_log(0, "[D-%d] Reference: %s|%s", refcount, refstruct[refcount].s_refid, refstruct[refcount].s_refurl);
		      
     refcount++;

} 
fclose(reffile);
sagan_log(0, "%d references loaded.", refcount);
}


/****************************************************************************/
/* This simple looks up references and returns a string with them formatted */
/* properly.  It gets passed the location of the rule in memory (based on   */
/* the rulecount.  This is used for sagan-alert.c and sagan-esmtp.c         */
/****************************************************************************/

char *reflookup( int rulemem ) { 

int i=0;
int b=0;
char *tmptok=NULL;
char *tmp=NULL;
char *tmp2=NULL;
char refinfo[512]="";
char refinfo2[512]="";
char reftmp[2048]="";
char *ret;

for (i=0; i < rulestruct[rulemem].ref_count + 1 ; i++ ) {

        strlcpy(refinfo, rulestruct[rulemem].s_reference[i], sizeof(refinfo));
        tmp = strtok_r(refinfo, ",", &tmptok);
        tmp2 = strtok_r(NULL, ",", &tmptok);

    for ( b=0; b < refcount; b++) {

        if (!strcmp(refstruct[b].s_refid,  tmp)) {
	   snprintf(refinfo2, sizeof(refinfo2), "[Xref => %s%s]",  refstruct[b].s_refurl, tmp2);
	   strlcat(reftmp,  refinfo2,  sizeof(reftmp));
           }
        }
}

ret=reftmp;
return(ret);
}
