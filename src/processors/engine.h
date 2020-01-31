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

#define SAGAN_PROCESSOR_NAME "Sagan_Engine"
#define SAGAN_PROCESSOR_FACILITY "daemon"
#define SAGAN_PROCESSOR_PRIORITY "warning"
#define SAGAN_PROCESSOR_PRI 1
#define SAGAN_PROCESSOR_CLASS "Sagan_Engine"
#define SAGAN_PROCESSOR_REV 1
#define SAGAN_PROCESSOR_TAG NULL
#define SAGAN_PROCESSOR_GENERATOR_ID 1

int Sagan_Engine ( _Sagan_Proc_Syslog *, bool );
void Sagan_Engine_Init ( void );
