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

    char software[32];
    //char eventtime[32];
    char hostname[256];
    //char keywords[32];
    //char eventtype[32];
    //int  severityvalue;
    //char severity[16];
    int  eventid;
    char program[MAX_SYSLOG_PROGRAM];
    //char guid[32];
    //int  version;
    //int  taskvalue;
    //int  opcodevalue;
    //uint64_t recordnumber;
    //uint64_t executionprocessid;
    //uint64_t exectionthreadid;
    //char channel[32];
    //char domain[32];
    char username[64];
    //char accountname[64];
    char message[MAX_SYSLOGMSG];
    //char opcode[64];
    //char userdata[512];
    //char eventreceviedtime[32];

};


void Load_Message_JSON_Map ( const char *json_map );
