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

#include "sagan-defs.h"

void Sagan_Blacklist_Load ( void );
void Sagan_Blacklist_Init( void );
bool Sagan_Blacklist_IPADDR( unsigned char * );
bool Sagan_Blacklist_IPADDR_All ( char *, _Sagan_Lookup_Cache_Entry *lookup_cache, int lookup_cache_size );

typedef struct _Sagan_Blacklist _Sagan_Blacklist;
struct _Sagan_Blacklist
{

    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;

};

