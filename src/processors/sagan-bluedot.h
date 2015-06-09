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

/* sagan-bluedot.h
 *
 * Does real time lookups of IP addresses from the Quadrant reputation
 * database.   This means you have to have authentication!
 *
 */


#ifdef WITH_BLUEDOT

#define BLUEDOT_PROCESSOR_USER_AGENT "User-Agent: Sagan-SIEM"

/* Extensions on URL passed depending on what type of query we want to do */

#define BLUEDOT_IP_LOOKUP_URL "&qip="
#define BLUEDOT_HASH_LOOKUP_URL "&qhash="
#define BLUEDOT_FILENAME_LOOKUP_URL "&qfilename="

#define BLUEDOT_LOOKUP_IP 1
#define BLUEDOT_LOOKUP_HASH 2
#define BLUEDOT_LOOKUP_FILENAME 3

#define BLUEDOT_MAX_HASH_SIZE	257			/* This can handle MD5,  SHA1 and SHA256 */

int Sagan_Bluedot_Cat_Compare ( int, int );
int Sagan_Bluedot ( _SaganProcSyslog *, int  );
int Sagan_Bluedot_Lookup(char *, int);			/* what to lookup,  lookup type */
int Sagan_Bluedot_IP_Lookup_All(char *, int);

void Sagan_Bluedot_Clean_Cache ( void );
void Sagan_Bluedot_Init(void);
void Sagan_Bluedot_Load_Cat(void);



typedef struct _Sagan_Bluedot_Cat_List _Sagan_Bluedot_Cat_List;
struct _Sagan_Bluedot_Cat_List
{
    int		cat_number;
    char	cat[50];
};


typedef struct _Sagan_Bluedot_IP_Cache _Sagan_Bluedot_IP_Cache;
struct _Sagan_Bluedot_IP_Cache
{
    uint32_t host;
    uint64_t utime;
    int	alertid;
};

typedef struct _Sagan_Bluedot_Hash_Cache _Sagan_Bluedot_Hash_Cache;
struct _Sagan_Bluedot_Hash_Cache
{
    char hash[BLUEDOT_MAX_HASH_SIZE];
    uint64_t utime;
    int alertid;
};


typedef struct _Sagan_Bluedot_Queue _Sagan_Bluedot_Queue;
struct _Sagan_Bluedot_Queue
{
    char	host[16];
};



#endif

