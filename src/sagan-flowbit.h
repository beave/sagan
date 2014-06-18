/*
** Copyright (C) 2009-2014 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2014 Champ Clark III <cclark@quadrantsec.com>
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

int Sagan_Flowbit( int, char *, char * );
int Sagan_Flowbit_Type ( char *, int, const char *);

typedef struct _Sagan_Flowbit _Sagan_Flowbit;
struct _Sagan_Flowbit
{
    char flowbit_name[128];
};

typedef struct _Sagan_Flowbit_Track _Sagan_Flowbit_Track;
struct _Sagan_Flowbit_Track
{
    int flowbit_memory_position;
    char *flowbit_name;
    sbool flowbit_state;
    uint64_t ip_src;
    uint64_t ip_dst;
    uint64_t flowbit_expire;
};




