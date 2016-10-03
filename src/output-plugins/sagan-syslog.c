/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-syslog.c
*
* Send Sagan alerts to a remote syslog server using the same format that
* Snort uses.
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_SYSLOG

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "sagan.h"
#include "sagan-alert.h"
#include "sagan-classifications.h"
#include "sagan-config.h"

struct _Rule_Struct *rulestruct;
struct _SaganConfig *config;
struct _SaganCounters *counters;

void Sagan_Alert_Syslog( _Sagan_Event *Event )
{

    char syslog_message_output[1024] = { 0 };
    char *tmp_proto = NULL;

    /* Template to mimic Snort syslog output */

    char *syslog_template = "[%lu:%s:%s] %s [Classification: %s] [Priority: %d] %s %s:%d -> %s:%d - %s";

    if ( Event->ip_proto != 1 || Event->ip_proto != 6 || Event->ip_proto != 17 ) {
        tmp_proto = "{UNKNOWN}";
    }

    if ( Event->ip_proto == 1 ) {
        tmp_proto = "{ICMP}";
    }

    if ( Event->ip_proto == 6 ) {
        tmp_proto = "{TCP}";
    }

    if ( Event->ip_proto == 17 ) {
        tmp_proto = "{UDP}";
    }

    snprintf(syslog_message_output, sizeof(syslog_message_output), syslog_template, Event->generatorid, Event->sid, Event->rev, Event->f_msg, Sagan_Classtype_Lookup ( Event->class ), Event->pri, tmp_proto, Event->ip_src, Event->src_port, Event->ip_dst, Event->dst_port, Event->message);

    /* Send syslog message */

    openlog("sagan", config->sagan_syslog_options, config->sagan_syslog_facility);
    syslog(config->sagan_syslog_priority, "%s", syslog_message_output);
    closelog();


}

#endif
