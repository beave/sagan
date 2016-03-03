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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

void Sagan_Flowbit_Set( int, char *, char * );
int Sagan_Flowbit_Condition ( int, char *, char * );
int Sagan_Flowbit_Type ( char *, int, const char *);
void Sagan_Flowbit_Cleanup(void);

typedef struct _Sagan_Flowbit_Track _Sagan_Flowbit_Track;
struct _Sagan_Flowbit_Track
{
    char	flowbit_name[64];
    int		flowbit_timeout;
};



typedef struct _Sagan_IPC_Flowbit _Sagan_IPC_Flowbit;
struct _Sagan_IPC_Flowbit
{
    char flowbit_name[64];
    sbool flowbit_state;
    uint32_t ip_src;
    uint32_t ip_dst;
    uintmax_t flowbit_expire;
    int expire;
};

