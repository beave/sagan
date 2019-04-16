/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>
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

#include "sagan-defs.h"

typedef struct _JSON_Message_Map _JSON_Message_Map;
struct _JSON_Message_Map
{

    char program[MAX_SYSLOG_PROGRAM];
    char message[MAX_SYSLOGMSG];

    char src_ip[MAXIP];
    char dst_ip[MAXIP];

    char src_port[32];
    char dst_port[32];

    char proto[32];

};

typedef struct _JSON_Message_Map_Found _JSON_Message_Map_Found;
struct _JSON_Message_Map_Found
{

    char program[MAX_SYSLOG_PROGRAM];
    char message[MAX_SYSLOGMSG];

    char src_ip[MAXIP];
    char dst_ip[MAXIP];

    char src_port[MAXIP];
    char dst_port[MAXIP];

    char proto[5];

};



void Load_Message_JSON_Map ( const char *json_map );
void Parse_JSON_Message ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL );

