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

/* sagan-bro-intel.c
*
* This allows Sagan to read in Bro Intel files,  like those from Critical
* Stack (https://intel.criticalstack.com).
*
*/


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#define BROINTEL_PROCESSOR_NAME "Sagan_BroIntel"
#define BROINTEL_PROCESSOR_FACILITY "daemon"
#define BROINTEL_PROCESSOR_PRIORITY "warning"
#define BROINTEL_PROCESSOR_PRI 1
#define BROINTEL_PROCESSOR_CLASS "BroIntel"
#define BROINTEL_PROCESSOR_REV 1
#define BROINTEL_PROCESSOR_TAG NULL
#define BROINTEL_PROCESSOR_GENERATOR_ID 1003


typedef struct _Sagan_BroIntel_Intel_Addr _Sagan_BroIntel_Intel_Addr;
struct _Sagan_BroIntel_Intel_Addr
{
    unsigned char bits_ip[MAXIPBIT];
};

typedef struct _Sagan_BroIntel_Intel_Domain _Sagan_BroIntel_Intel_Domain;
struct _Sagan_BroIntel_Intel_Domain
{
    char domain[255];
};

typedef struct _Sagan_BroIntel_Intel_File_Hash _Sagan_BroIntel_Intel_File_Hash;
struct _Sagan_BroIntel_Intel_File_Hash
{
    char hash[64];
};

typedef struct _Sagan_BroIntel_Intel_URL _Sagan_BroIntel_Intel_URL;
struct _Sagan_BroIntel_Intel_URL
{
    char url[10240];
};

typedef struct _Sagan_BroIntel_Intel_Software _Sagan_BroIntel_Intel_Software;
struct _Sagan_BroIntel_Intel_Software
{
    char software[128];
};

typedef struct _Sagan_BroIntel_Intel_Email _Sagan_BroIntel_Intel_Email;
struct _Sagan_BroIntel_Intel_Email
{
    char email[128];
};

typedef struct _Sagan_BroIntel_Intel_User_Name _Sagan_BroIntel_Intel_User_Name;
struct _Sagan_BroIntel_Intel_User_Name
{
    char username[64];
};

typedef struct _Sagan_BroIntel_Intel_File_Name _Sagan_BroIntel_Intel_File_Name;
struct _Sagan_BroIntel_Intel_File_Name
{
    char file_name[128];
};

typedef struct _Sagan_BroIntel_Intel_Cert_Hash _Sagan_BroIntel_Intel_Cert_Hash;
struct _Sagan_BroIntel_Intel_Cert_Hash
{
    char cert_hash[64];
};


void Sagan_BroIntel_Init(void);
void Sagan_BroIntel_Load_File(void);

bool  Sagan_BroIntel_IPADDR ( unsigned char *, char *ipaddr );
bool  Sagan_BroIntel_IPADDR_All ( char *, _Sagan_Lookup_Cache_Entry *, size_t);

bool  Sagan_BroIntel_DOMAIN ( char * );
bool  Sagan_BroIntel_FILE_HASH ( char * );
bool  Sagan_BroIntel_URL ( char * );
bool  Sagan_BroIntel_SOFTWARE( char * );
bool  Sagan_BroIntel_EMAIL( char * );
bool  Sagan_BroIntel_USER_NAME ( char * );
bool  Sagan_BroIntel_FILE_NAME ( char * );
bool  Sagan_BroIntel_CERT_HASH ( char * );

