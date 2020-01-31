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

struct tm *Sagan_LocalTime(time_t, struct tm *);
void CreateTimeString (const struct timeval *, char *, size_t, bool );
void CreateIsoTimeString (const struct timeval *, char *, size_t );
void Return_Date( uint32_t, char *str, size_t size );
void Return_Time( uint32_t, char *str, size_t size );
void u32_Time_To_Human ( uint32_t, char *str, size_t size );
uint64_t Return_Epoch( void );



