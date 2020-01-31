/* $Id$ */
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


void Xbit_Set_MMAP(int rule_position, char *ip_src_char, char *ip_dst_char, char *syslog_message );
bool Xbit_Condition_MMAP(int rule_position, char *ip_src_char, char *ip_dst_char);
void Clean_Xbit_MMAP(void);

typedef struct _Sagan_IPC_Xbit _Sagan_IPC_Xbit;
struct _Sagan_IPC_Xbit
{
    char xbit_name[64];
    uint32_t xbit_hash;
    uint32_t xbit_name_hash;
    uint64_t xbit_expire;
    int expire;
    char syslog_message[MAX_SYSLOGMSG];
    uint64_t sid;
    char signature_msg[MAX_SAGAN_MSG];

};
