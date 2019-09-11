/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>
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

#define BLUEDOT_IP_LOOKUP_URL "&ip="
#define BLUEDOT_HASH_LOOKUP_URL "&hash="
#define BLUEDOT_FILENAME_LOOKUP_URL "&filename="
#define BLUEDOT_URL_LOOKUP_URL "&url="
#define BLUEDOT_JA3_LOOKUP_URL "&ja3="

#define BLUEDOT_LOOKUP_IP 1
#define BLUEDOT_LOOKUP_HASH 2
#define BLUEDOT_LOOKUP_URL 3
#define BLUEDOT_LOOKUP_FILENAME 4
#define BLUEDOT_LOOKUP_JA3 5

int Sagan_Bluedot_Cat_Compare ( unsigned char, int, unsigned char );
int Sagan_Bluedot ( _Sagan_Proc_Syslog *, int  );
unsigned char Sagan_Bluedot_Lookup(char *data,  unsigned char type, int rule_position, char *bluedot_str, size_t bluedot_size );
int Sagan_Bluedot_IP_Lookup_All ( char *, int, _Sagan_Lookup_Cache_Entry *, int );

void Sagan_Bluedot_Clean_Cache ( void );
void Sagan_Bluedot_Init(void);
void Sagan_Bluedot_Load_Cat(void);
void Sagan_Verify_Categories( char *, int, const char *, int, unsigned char );
void Sagan_Bluedot_Check_Cache_Time (void);

int Sagan_Bluedot_Clean_Queue ( char *, unsigned char );


typedef struct _Sagan_Bluedot_Cat_List _Sagan_Bluedot_Cat_List;
struct _Sagan_Bluedot_Cat_List
{
    int		cat_number;
    char	cat[50];
};


typedef struct _Sagan_Bluedot_IP_Cache _Sagan_Bluedot_IP_Cache;
struct _Sagan_Bluedot_IP_Cache
{
    unsigned char ip[MAXIPBIT];
    uint64_t mdate_utime;
    uint64_t cdate_utime;
    uint64_t cache_utime;
    char bluedot_json[BLUEDOT_JSON_SIZE];
    int	alertid;
};

typedef struct _Sagan_Bluedot_Hash_Cache _Sagan_Bluedot_Hash_Cache;
struct _Sagan_Bluedot_Hash_Cache
{
    char hash[SHA256_HASH_SIZE+1];
    uint64_t cache_utime;
    char bluedot_json[BLUEDOT_JSON_SIZE];
    int alertid;
};

typedef struct _Sagan_Bluedot_URL_Cache _Sagan_Bluedot_URL_Cache;
struct _Sagan_Bluedot_URL_Cache
{
    char url[8192];
    uint64_t cache_utime;
    char bluedot_json[BLUEDOT_JSON_SIZE];
    int alertid;
};

typedef struct _Sagan_Bluedot_Filename_Cache _Sagan_Bluedot_Filename_Cache;
struct _Sagan_Bluedot_Filename_Cache
{
    char filename[256];
    uint64_t cache_utime;
    char bluedot_json[BLUEDOT_JSON_SIZE];
    int alertid;
};

typedef struct _Sagan_Bluedot_JA3_Cache _Sagan_Bluedot_JA3_Cache;
struct _Sagan_Bluedot_JA3_Cache
{
    char ja3[MD5_HASH_SIZE+1];
    uint64_t cache_utime;
    char bluedot_json[BLUEDOT_JSON_SIZE];
    int alertid;
};


typedef struct _Sagan_Bluedot_IP_Queue _Sagan_Bluedot_IP_Queue;
struct _Sagan_Bluedot_IP_Queue
{
    unsigned char ip[MAXIPBIT];
};

typedef struct _Sagan_Bluedot_Hash_Queue _Sagan_Bluedot_Hash_Queue;
struct _Sagan_Bluedot_Hash_Queue
{
    char hash[SHA256_HASH_SIZE+1];
};

typedef struct _Sagan_Bluedot_URL_Queue _Sagan_Bluedot_URL_Queue;
struct _Sagan_Bluedot_URL_Queue
{
    char url[8192];
};

typedef struct _Sagan_Bluedot_Filename_Queue _Sagan_Bluedot_Filename_Queue;
struct _Sagan_Bluedot_Filename_Queue
{
    char filename[256];
};

typedef struct _Sagan_Bluedot_JA3_Queue _Sagan_Bluedot_JA3_Queue;
struct _Sagan_Bluedot_JA3_Queue
{
    char ja3[MD5_HASH_SIZE+1];
};



typedef struct _Sagan_Bluedot_Skip _Sagan_Bluedot_Skip;
struct _Sagan_Bluedot_Skip
{

    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;

};



#endif

