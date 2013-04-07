/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
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

#define SEARCH_PROCESSOR_NAME "Sagan_Search"
#define SEARCH_PROCESSOR_FACILITY "daemon"
#define SEARCH_PROCESSOR_PRIORITY "warning"
#define SEARCH_PROCESSOR_PRI 1
#define SEARCH_PROCESSOR_CLASS "Search"
#define SEARCH_PROCESSOR_REV "1"
#define SEARCH_PROCESSOR_TAG NULL
#define SEARCH_PROCESSOR_GENERATOR_ID 1002


typedef struct _Sagan_Nocase_Searchlist _Sagan_Nocase_Searchlist;
struct _Sagan_Nocase_Searchlist {
char search[512];
};

typedef struct _Sagan_Case_Searchlist _Sagan_Case_Searchlist;
struct _Sagan_Case_Searchlist {
char search[512];
};

void Sagan_Search ( _SaganProcSyslog *, int );
int Sagan_Search_Load ( int );
