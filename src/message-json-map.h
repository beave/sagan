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

#include "sagan-defs.h"

typedef struct _JSON_Message_Map _JSON_Message_Map;
struct _JSON_Message_Map
{

    char program[MAX_SYSLOG_PROGRAM];
    char message[MAX_SYSLOGMSG];

};

typedef struct _JSON_Message_Map_Found _JSON_Message_Map_Found;
struct _JSON_Message_Map_Found
{

    char program[MAX_SYSLOG_PROGRAM];
    char message[MAX_SYSLOGMSG];

};



void Load_Message_JSON_Map ( const char *json_map );
void Parse_JSON_Message ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL );

