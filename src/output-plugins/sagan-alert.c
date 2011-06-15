/*
** Copyright (C) 2009-2011 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2011 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-alert.c 
 *
 * Provides logging functionality in a 'snort like' format.  Usually in 
 * the /var/log/sagan directory named 'alert'
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "sagan.h"

#include "version.h"

struct rule_struct *rulestruct;
struct ref_struct *refstruct;

void sagan_alert( SaganEvent *Event ) { 

char tmpref[2048]="";

fprintf(Event->config->sagan_alert_stream, "\n[**] [%s] %s [**]\n", rulestruct[Event->found].s_sid, Event->f_msg);
fprintf(Event->config->sagan_alert_stream, "[Classification: %s] [Priority: %d]\n", rulestruct[Event->found].s_classtype, rulestruct[Event->found].s_pri );
fprintf(Event->config->sagan_alert_stream, "%s %s %s:%d -> %s:%d %s %s\n", Event->date, Event->time, Event->ip_src, Event->src_port, Event->ip_dst, Event->dst_port, Event->facility, Event->priority);
fprintf(Event->config->sagan_alert_stream, "Message: %s\n", Event->message);
snprintf(tmpref, sizeof(tmpref), "%s", reflookup( Event->found, 0 ));
if ( strcmp(tmpref, "")) fprintf(Event->config->sagan_alert_stream, "%s\n", tmpref);

fflush(Event->config->sagan_alert_stream);

}
