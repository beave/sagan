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

/* General debugging functions */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "debug.h"


void Debug_Sagan_Proc_Syslog ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    Sagan_Log(DEBUG, "Data in _Sagan_Proc_Syslog (including extracted JSON)");
    Sagan_Log(DEBUG, "-----------------------------------------------------------------------------");
    Sagan_Log(DEBUG, " * message: \"%s\"", SaganProcSyslog_LOCAL->syslog_message );
    Sagan_Log(DEBUG, " * program: \"%s\"", SaganProcSyslog_LOCAL->syslog_program );
    Sagan_Log(DEBUG, " * host: \"%s\"", SaganProcSyslog_LOCAL->syslog_host );
    Sagan_Log(DEBUG, " * level: \"%s\"", SaganProcSyslog_LOCAL->syslog_level );
    Sagan_Log(DEBUG, " * facility: \"%s\"", SaganProcSyslog_LOCAL->syslog_facility );
    Sagan_Log(DEBUG, " * priority: \"%s\"", SaganProcSyslog_LOCAL->syslog_priority );
    Sagan_Log(DEBUG, " * tag: \"%s\"", SaganProcSyslog_LOCAL->syslog_tag );
    Sagan_Log(DEBUG, " * time: \"%s\"", SaganProcSyslog_LOCAL->syslog_time );
    Sagan_Log(DEBUG, " * date: \"%s\"", SaganProcSyslog_LOCAL->syslog_date );
    Sagan_Log(DEBUG, " * src_ip : \"%s\"", SaganProcSyslog_LOCAL->src_ip );
    Sagan_Log(DEBUG, " * dst_ip : \"%s\"", SaganProcSyslog_LOCAL->dst_ip );
    Sagan_Log(DEBUG, " * src_port : \"%d\"", SaganProcSyslog_LOCAL->src_port );
    Sagan_Log(DEBUG, " * dst_port : \"%d\"", SaganProcSyslog_LOCAL->dst_port );
    Sagan_Log(DEBUG, " * proto : \"%d\"", SaganProcSyslog_LOCAL->proto );
    Sagan_Log(DEBUG, " * ja3: \"%s\"", SaganProcSyslog_LOCAL->ja3 );
    Sagan_Log(DEBUG, " * event_id: \"%s\"", SaganProcSyslog_LOCAL->event_id );
    Sagan_Log(DEBUG, " * md5: \"%s\"", SaganProcSyslog_LOCAL->md5 );
    Sagan_Log(DEBUG, " * sha1: \"%s\"", SaganProcSyslog_LOCAL->sha1 );
    Sagan_Log(DEBUG, " * sha256: \"%s\"", SaganProcSyslog_LOCAL->sha256 );
    Sagan_Log(DEBUG, " * filename: \"%s\"", SaganProcSyslog_LOCAL->filename );
    Sagan_Log(DEBUG, " * hostname: \"%s\"", SaganProcSyslog_LOCAL->hostname );
    Sagan_Log(DEBUG, " * url: \"%s\"", SaganProcSyslog_LOCAL->url );

}
