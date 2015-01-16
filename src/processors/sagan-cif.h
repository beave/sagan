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

/* sagan-cif.c
*
* This process is to lookup data via the CIF (Collective Intelligence Framework).
* For more information about CIF,  please see:
*
* https://code.google.com/p/collective-intelligence-framework/
* http://csirtgadgets.org/
*
*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#if defined(HAVE_LIBJSON) || defined(HAVE_LIBJSON_C)

/* Move to configuration file */

#define CIF_PROCESSOR_NAME "CIF"
#define CIF_PROCESSOR_FACILITY "daemon"
#define CIF_PROCESSOR_PRIORITY "warning"
#define CIF_PROCESSOR_PRI 2
#define CIF_PROCESSOR_CLASS "CIF"
#define CIF_PROCESSOR_REV "1"
#define CIF_PROCESSOR_TAG NULL
#define CIF_PROCESSOR_GENERATOR_ID 1000
#define CIF_PROCESSOR_USER_AGENT "User-Agent: Sagan-SIEM"

int Sagan_CIF_Ignore_List ( void );
void Sagan_CIF_Clean_Cache ( void );
void Sagan_CIF_Init(void);

typedef struct _Sagan_CIF_Ignore_List _Sagan_CIF_Ignore_List;
struct _Sagan_CIF_Ignore_List {
char    ignore[26];
};


typedef struct _Sagan_CIF_Cache _Sagan_CIF_Cache;
struct _Sagan_CIF_Cache  {
char    host[16];               /* IPv4? */
uint64_t utime;
int     alertid;
char    generator_msg[80];
sbool   status;
};

typedef struct _Sagan_CIF_Queue _Sagan_CIF_Queue;
struct _Sagan_CIF_Queue {
char    host[16];
};

int Sagan_CIF ( _SaganProcSyslog *, int  );
void Sagan_CIF_Send_Alert ( _SaganProcSyslog *, int , char *, char * , int );

#endif


