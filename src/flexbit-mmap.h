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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include "sagan-defs.h"

void Flexbit_Set_MMAP( int, char *, char *, int, int, char *, char * );
bool Flexbit_Condition_MMAP ( int, char *, char *, int, int, char * );
void Flexbit_Cleanup_MMAP( void );
bool Flexbit_Count_MMAP( int, char *, char *, char * );

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
    bool xbit_state;
    unsigned char ip_src[MAXIPBIT];
    unsigned char ip_dst[MAXIPBIT];
    int src_port;
    int dst_port;
    char username[64];
    uint64_t xbit_date;
    uint64_t xbit_expire;
    int expire;
    char selector[MAXSELECTOR];  /* No need to clean this, as we always set it when tracking */
    char syslog_message[MAX_SYSLOGMSG];
    uint64_t sid;
    char signature_msg[MAX_SAGAN_MSG];

};

