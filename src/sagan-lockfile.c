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

/* sagan-lockfile.c
 *
 * Creates a lock file for the Sagan process.    We don't want Sagan to be 
 * running more than once.  Also does a simple 'test' to see if the PID
 * in the lock file is 'running' (via kill -0).   Wrote this to decrease
 * the dependancies of Sagan,  as opposed to using liblockfile.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif


#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

#include "sagan.h"

#include "version.h"

struct _SaganConfig *config;


/* Was using liblockfile but decided for portability reasons, it was a
 * bad idea */

void checklockfile ( void ) { 

char buf[10];
FILE *lck;
int pid;
struct stat lckcheck;

/* Check for lockfile first */

if (stat(config->sagan_lockfile, &lckcheck) == 0 ) {
   
   /* Lock file is present,  open for read */
   if (( lck = fopen(config->sagan_lockfile, "r" )) == NULL ) {
      Sagan_Log(1, "[%s, line %d] Lock file (%s) is present but can't be read", __FILE__, __LINE__, config->sagan_lockfile);
      } else {
      if (!fgets(buf, sizeof(buf), lck)) Sagan_Log(1, "[%s, line %d] Lock file (%s) is open for reading,  but can't read contents.", __FILE__, __LINE__, config->sagan_lockfile);
      fclose(lck);
      pid = atoi(buf);
      if ( pid == 0 ) Sagan_Log(1, "[%s, line %d] Lock file read but pid value is zero.  Aborting.....", __FILE__, __LINE__);

      /* Check to see if process is running.  We use kill with 0 signal
       * to determine this.  We check this return value.  Signal 0
       * won't affect running processes */

      if ( kill(pid, 0) != -1 ) {
         Sagan_Log(1, "[%s, line %d] It appears that Sagan is already running (pid: %d).", __FILE__, __LINE__, pid);
	 } else {

	 Sagan_Log(0, "[%s, line %d] Lock file is present,  but Sagan isn't at pid %d (Removing stale %s file)", __FILE__, __LINE__, pid, config->sagan_lockfile);
	 if (unlink(config->sagan_lockfile)) { 
	    Sagan_Log(1, "Unable to delete %s. ", config->sagan_lockfile);
	    }
	 }
        } 

} else {

      /* No lock file present, so create it */

      if (( lck = fopen(config->sagan_lockfile, "w" )) == NULL ) {
      Sagan_Log(1, "[%s, line %d] Cannot create lock file (%s)", __FILE__, __LINE__, config->sagan_lockfile);
      } else {
      fprintf(lck, "%d", getpid() );
      fflush(lck); fclose(lck);
      }
}
}

void Remove_Lock_File ( void ) { 

struct stat lckcheck;

if ((stat(config->sagan_lockfile, &lckcheck) == 0) && unlink(config->sagan_lockfile) != 0 ) {
    Sagan_Log(1, "[%s, line %d] Cannot remove lock file (%s)\n", __FILE__, __LINE__, config->sagan_lockfile);
    }
}
