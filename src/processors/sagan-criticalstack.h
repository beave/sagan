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

/* sagan-criticalstack.c
*
* This allows Sagan to read in,  parse and use the Critical Stack threat
* feeds.  Please see:
*
* https://intel.criticalstack.com
*
*/


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#define CRITICALSTACK_PROCESSOR_NAME "Sagan_CriticalStack"
#define CRITICALSTACK_PROCESSOR_FACILITY "daemon"
#define CRITICALSTACK_PROCESSOR_PRIORITY "warning"
#define CRITICALSTACK_PROCESSOR_PRI 1
#define CRITICALSTACK_PROCESSOR_CLASS "CriticalStack"
#define CRITICALSTACK_PROCESSOR_REV "1"
#define CRITICALSTACK_PROCESSOR_TAG NULL
#define CRITICALSTACK_PROCESSOR_GENERATOR_ID 1003


typedef struct _Sagan_CriticalStack_Intel_Addr _Sagan_CriticalStack_Intel_Addr;
struct _Sagan_CriticalStack_Intel_Addr
{
    uint32_t u32_ip;
};

typedef struct _Sagan_CriticalStack_Intel_Domain _Sagan_CriticalStack_Intel_Domain;
struct _Sagan_CriticalStack_Intel_Domain
{
    char domain[255];
};

typedef struct _Sagan_CriticalStack_Intel_File_Hash _Sagan_CriticalStack_Intel_File_Hash;
struct _Sagan_CriticalStack_Intel_File_Hash
{
    char hash[64];
};

typedef struct _Sagan_CriticalStack_Intel_URL _Sagan_CriticalStack_Intel_URL;
struct _Sagan_CriticalStack_Intel_URL
{
    char url[10240];
};

typedef struct _Sagan_CriticalStack_Intel_Software _Sagan_CriticalStack_Intel_Software;
struct _Sagan_CriticalStack_Intel_Software
{
    char software[128];
};

typedef struct _Sagan_CriticalStack_Intel_Email _Sagan_CriticalStack_Intel_Email;
struct _Sagan_CriticalStack_Intel_Email
{
    char email[128];
};

typedef struct _Sagan_CriticalStack_Intel_User_Name _Sagan_CriticalStack_Intel_User_Name;
struct _Sagan_CriticalStack_Intel_User_Name
{
    char username[64];
};

typedef struct _Sagan_CriticalStack_Intel_File_Name _Sagan_CriticalStack_Intel_File_Name;
struct _Sagan_CriticalStack_Intel_File_Name
{
    char file_name[128];
};

typedef struct _Sagan_CriticalStack_Intel_Cert_Hash _Sagan_CriticalStack_Intel_Cert_Hash;
struct _Sagan_CriticalStack_Intel_Cert_Hash
{
    char cert_hash[64];
};


void Sagan_CriticalStack_Init(void);
void Sagan_CriticalStack_Load_File(void);
int  Sagan_CriticalStack_IPADDR ( uint32_t );
int  Sagan_CriticalStack_DOMAIN ( char * );
int  Sagan_CriticalStack_FILE_HASH ( char * );
int  Sagan_CriticalStack_URL ( char * );
int  Sagan_CriticalStack_SOFTWARE( char * );
int  Sagan_CriticalStack_EMAIL( char * );
int  Sagan_CriticalStack_USER_NAME ( char * );
int  Sagan_CriticalStack_FILE_NAME ( char * );
int  Sagan_CriticalStack_CERT_HASH ( char * );

