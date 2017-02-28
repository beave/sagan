/* $Id$ */

/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-json.c
 *
 * Functions that handle JSON output.
 *
 */



#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
//#include <stdlib.h>
//#include <pthread.h>
//#include <string.h>

#include "sagan.h"
//#include "sagan-alert.h"
#include "references.h"
#include "sagan-config.h"
#include "sagan-json.h"



char *Format_Sagan_JSON_Alert( _Sagan_Event *event)
{

    char *ret;

    char *proto;
    char *drop;

    static __thread char tmp[1024];

    if ( event->ip_proto == 17 ) {
        proto = "UDP";
    }

    else if ( event->ip_proto == 6 ) {
        proto = "TCP";
    }

    else if ( event->ip_proto == 1 ) {
        proto = "ICMP";
    }

    else if ( event->ip_proto != 1 || event->ip_proto != 6 || event->ip_proto != 17 ) {
        proto = "UNKNOWN";
    }

    if ( event->drop == true ) {

        /* Blocked?  Look at what Suricata says */

        drop = "blocked";
    } else {
        drop = "allowed";
    }

    snprintf(tmp, sizeof(tmp), JSON_ALERT, event->date, event->time, event->ip_src, event->src_port,
             event->ip_dst, event->dst_port, proto, drop, event->generatorid, event->sid, event->rev,
             event->f_msg, event->class, event->pri );

    return(tmp);

}
