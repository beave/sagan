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

/* key.c
 *
 * This runs as a thread for stdin.  This allows users,  when running
 * in the foreground,  to hit "enter" to see statistics of sagan.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "version.h"

#include "sagan.h"
#include "sagan-defs.h"
#include "key.h"
#include "stats.h"

struct _SaganConfig *config;

void Key_Handler( void )
{

#ifdef HAVE_SYS_PRCTL_H
    (void)SetThreadName("SaganKeyhandler");
#endif

    while(1)
        {

            int key;

            key=getchar();

            if ( key != 0 )
                {
                    Statistics();
                }

        }
}
