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

void Sagan_Xbit_Set( int, char *, char * );
int Sagan_Xbit_Condition ( int, char *, char * );
int Sagan_Xbit_Type ( char *, int, const char *);
void Sagan_Xbit_Cleanup(void);

typedef struct _Sagan_Xbit_Track _Sagan_Xbit_Track;
struct _Sagan_Xbit_Track {
    char	xbit_name[64];
    int		xbit_timeout;
};



typedef struct _Sagan_IPC_Xbit _Sagan_IPC_Xbit;
struct _Sagan_IPC_Xbit {
    char xbit_name[64];
    sbool xbit_state;
    uint32_t ip_src;
    uint32_t ip_dst;
    char username[64];
    uintmax_t xbit_date;
    uintmax_t xbit_expire;
    int expire;
};

