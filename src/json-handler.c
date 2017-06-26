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

/* json.c
 *
 * Functions that handle JSON output.
 *
 */



#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "references.h"
#include "util-base64.h"
#include "util-time.h"
#include "sagan-config.h"
#include "json-handler.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;

void Format_JSON_Alert_EVE( _Sagan_Event *Event, char *str, size_t size )
{


    char *proto = NULL;
    char *drop = NULL;

    char timebuf[64];
    char classbuf[64];

    if ( Event->ip_proto == 17 )
        {
            proto = "UDP";
        }

    else if ( Event->ip_proto == 6 )
        {
            proto = "TCP";
        }

    else if ( Event->ip_proto == 1 )
        {
            proto = "ICMP";
        }

    else if ( Event->ip_proto != 1 || Event->ip_proto != 6 || Event->ip_proto != 17 )
        {
            proto = "UNKNOWN";
        }

    if ( Event->drop == true )
        {

            drop = "blocked";

        }
    else
        {

            drop = "allowed";
        }

    CreateIsoTimeString(&Event->event_time, timebuf, sizeof(timebuf));

    unsigned long b64_len = strlen(Event->message) * 2;
    uint8_t b64_target[b64_len];

    Base64Encode( (const unsigned char*)Event->message, strlen(Event->message), b64_target, &b64_len);
    Classtype_Lookup( Event->class, classbuf, sizeof(classbuf) );

    snprintf(str, size, EVE_ALERT, timebuf, FlowGetId(Event), config->eve_interface, Event->ip_src, Event->src_port, Event->ip_dst, Event->dst_port, proto, drop, Event->generatorid, Event->sid, Event->rev,Event->f_msg, classbuf, Event->pri, b64_target, "");

    if ( debug->debugjson )
        {

            Sagan_Log(S_DEBUG, "[%s, line %d] JSON Output: %s", __FILE__, __LINE__, str);

        }

}
