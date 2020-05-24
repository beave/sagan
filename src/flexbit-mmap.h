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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include "sagan-defs.h"

bool Flexbit_Condition_MMAP ( int, char *, char *, int, int, char * );
void Flexbit_Cleanup_MMAP( void );
void Flexbit_Set_MMAP(int rule_position, char *ip_src, char *ip_dst, int src_port, int dst_port, char *username, char *syslog_message );
bool Flexbit_Count_MMAP( int rule_position, char *ip_src, char *ip_dst );

typedef struct _Sagan_Flexbit_Track _Sagan_Flexbit_Track;
struct _Sagan_Flexbit_Track
{
    char	flexbit_name[64];
    int		flexbit_timeout;
    int		flexbit_srcport;
    int		flexbit_dstport;
};

typedef struct _Sagan_IPC_Flexbit _Sagan_IPC_Flexbit;
struct _Sagan_IPC_Flexbit
{
    char flexbit_name[64];
    bool flexbit_state;
    unsigned char ip_src[MAXIPBIT];
    unsigned char ip_dst[MAXIPBIT];
    int src_port;
    int dst_port;
    char username[64];
    uint64_t flexbit_date;
    uint64_t flexbit_expire;
    int expire;
    char syslog_message[MAX_SYSLOGMSG];
    uint64_t sid;
    char signature_msg[MAX_SAGAN_MSG];

};


