/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
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

void Sagan_Blacklist_Load ( void );
void Sagan_Blacklist_Init( void );
sbool Sagan_Blacklist_IPADDR( uint32_t );
sbool Sagan_Blacklist_IPADDR_All ( char * );

typedef struct _Sagan_Blacklist _Sagan_Blacklist;
struct _Sagan_Blacklist
{

    uint32_t u32_lower;
    uint32_t u32_higher;

};

