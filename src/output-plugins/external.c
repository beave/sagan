/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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

/* external.c
 *
 * Threaded function for user defined external system (execl) calls.  This
 * allows sagan to pass information to a external program.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "version.h"

#include "lockfile.h"
#include "references.h"
#include "sagan-config.h"
#include "output-plugins/external.h"

struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

pthread_mutex_t ext_mutex = PTHREAD_MUTEX_INITIALIZER;


void External_Thread ( _Sagan_Event *Event, char *execute_script )
{

    int in[2];
    int out[2];
    int n, pid;
    char buf[MAX_SYSLOGMSG];
    char data[MAX_SYSLOGMSG];
    char tmpref[256];
    char tmp[6];

    if ( debug->debugexternal )
        {
            Sagan_Log(S_WARN, "[%s, line %d] In External_Thread()", __FILE__, __LINE__);
        }


    Reference_Lookup( Event->found, 1, tmpref, sizeof(tmpref));

    if ( Event->drop == 1 )
        {

            snprintf(tmp, sizeof(tmp), "True");

        }
    else
        {

            snprintf(tmp, sizeof(tmp), "False");
        }


    snprintf(data, sizeof(data), "\n\
ID:%lu:%s\n\
Message:%s\n\
Classification:%s\n\
Drop:%s\n\
Priority:%d\n\
Date:%s\n\
Time:%s\n\
Source:%s\n\
Source Port:%d\n\
Destination:%s\n\
Destination Port:%d\n\
Facility:%s\n\
Syslog Priority:%s\n\
Liblognorm JSON:%s\n\
%sSyslog message:%s\n"\
             \
             ,Event->generatorid\
             ,Event->sid,\
             Event->f_msg,\
             Event->class,\
             tmp,\
             Event->pri,\
             Event->date,\
             Event->time,\
             Event->ip_src,\
             Event->src_port,\
             Event->ip_dst,\
             Event->dst_port,\
             Event->facility,\
             Event->priority,\
             !Event->json_normalize ? "{}" : json_object_to_json_string_ext(Event->json_normalize, FJSON_TO_STRING_PLAIN),
             tmpref,\
             Event->message);


    pthread_mutex_lock( &ext_mutex );

    if ( pipe(in) < 0 )
        {
            Remove_Lock_File();
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot create input pipe!", __FILE__, __LINE__);
        }


    if ( pipe(out) < 0 )
        {
            Remove_Lock_File();
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot create output pipe!", __FILE__, __LINE__);
        }

    pid=fork();
    if ( pid < 0 )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot create external program process", __FILE__, __LINE__);
        }
    else if ( pid == 0 )
        {
            /* Causes problems with alert.log */

            close(0);
            close(1);
            close(2);

            dup2(in[0],0);		// Stdin..
            dup2(out[1],1);
            dup2(out[1],2);

            close(in[1]);
            close(out[0]);

            execl(execute_script, execute_script, NULL, (char *)NULL);

            Remove_Lock_File();
            Sagan_Log(S_WARN, "[%s, line %d] Cannot execute %s", __FILE__, __LINE__, config->sagan_external_command);
        }

    close(in[0]);
    close(out[1]);

    /* Write to child input */

    n = write(in[1], data, strlen(data));
    close(in[1]);

    n = read(out[0], buf, sizeof(buf));
    close(out[0]);
    buf[n] = 0;

    waitpid(pid, NULL, 0);

    pthread_mutex_unlock( &ext_mutex );

    if ( debug->debugexternal == 1 )
        {
            Sagan_Log(S_DEBUG, "[%s, line %d] Executed %s", __FILE__, __LINE__, config->sagan_external_command);
        }

}

