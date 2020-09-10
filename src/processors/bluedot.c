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

/* bluedot.c
 *
 * Does real time lookups of IP addresses from the Quadrant reputation
 * database.   This means you have to have authentication!
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_BLUEDOT

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <json.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "rules.h"

#include "processors/bluedot.h"

#include "parsers/parsers.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _Sagan_Bluedot_Skip *Bluedot_Skip;

struct _Sagan_Bluedot_IP_Cache *SaganBluedotIPCache = NULL;
struct _Sagan_Bluedot_Hash_Cache *SaganBluedotHashCache = NULL;
struct _Sagan_Bluedot_URL_Cache *SaganBluedotURLCache = NULL;
struct _Sagan_Bluedot_Filename_Cache *SaganBluedotFilenameCache = NULL;
struct _Sagan_Bluedot_JA3_Cache *SaganBluedotJA3Cache = NULL;

struct _Sagan_Bluedot_Cat_List *SaganBluedotCatList = NULL;

struct _Sagan_Bluedot_IP_Queue *SaganBluedotIPQueue = NULL;
struct _Sagan_Bluedot_Hash_Queue *SaganBluedotHashQueue = NULL;
struct _Sagan_Bluedot_URL_Queue *SaganBluedotURLQueue = NULL;
struct _Sagan_Bluedot_Filename_Queue *SaganBluedotFilenameQueue = NULL;
struct _Sagan_Bluedot_JA3_Queue *SaganBluedotJA3Queue = NULL;

struct _Rule_Struct *rulestruct;

pthread_mutex_t SaganProcBluedotWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t CounterBluedotGenericMutex=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t SaganProcBluedotIPWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotHashWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotURLWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotFilenameWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotJA3WorkMutex=PTHREAD_MUTEX_INITIALIZER;


bool bluedot_cache_clean_lock=0;
bool bluedot_dns_global=0;

/****************************************************************************
 * Sagan_Bluedot_Init() - init's some global variables and other items
 * that need to be done only once. - Champ Clark 05/15/2013
 ****************************************************************************/

void Sagan_Bluedot_Init(void)
{

    char  timet[20] = { 0 };

    time_t t;
    struct tm *now = NULL;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    config->bluedot_last_time = atol(timet);

    /* Bluedot IP Cache */

    if ( config->bluedot_ip_max_cache > 0 )
        {

            SaganBluedotIPCache = malloc(config->bluedot_ip_max_cache * sizeof(struct _Sagan_Bluedot_IP_Cache));

            if ( SaganBluedotIPCache == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotIPCache. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotIPCache, 0, config->bluedot_ip_max_cache * sizeof(_Sagan_Bluedot_IP_Cache));
        }

    /* Bluedot Hash Cache */

    if ( config->bluedot_hash_max_cache > 0 )
        {

            SaganBluedotHashCache = malloc(config->bluedot_hash_max_cache * sizeof(struct _Sagan_Bluedot_Hash_Cache));

            if ( SaganBluedotHashCache == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotHashCache. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotHashCache, 0, config->bluedot_hash_max_cache * sizeof(_Sagan_Bluedot_Hash_Cache));
        }


    /* Bluedot URL Cache */

    if ( config->bluedot_url_max_cache > 0 )
        {

            SaganBluedotURLCache = malloc(config->bluedot_url_max_cache * sizeof(struct _Sagan_Bluedot_URL_Cache));

            if ( SaganBluedotURLCache == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotURLCache. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotURLCache, 0, config->bluedot_url_max_cache * sizeof(_Sagan_Bluedot_URL_Cache));
        }

    /* Bluedot Filename Cache */

    if ( config->bluedot_filename_max_cache > 0 )
        {

            SaganBluedotFilenameCache = malloc(config->bluedot_filename_max_cache * sizeof(struct _Sagan_Bluedot_Filename_Cache));

            if ( SaganBluedotFilenameCache == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotFilenameCache. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotFilenameCache, 0, config->bluedot_filename_max_cache * sizeof(_Sagan_Bluedot_Filename_Cache));
        }

    /* Bluedot JA3 Cache */

    if ( config->bluedot_ja3_max_cache > 0 )
        {

            SaganBluedotJA3Cache = malloc(config->bluedot_ja3_max_cache * sizeof(struct _Sagan_Bluedot_JA3_Cache));

            if ( SaganBluedotJA3Cache == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotJA3Cache. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotJA3Cache, 0, config->bluedot_ja3_max_cache * sizeof(_Sagan_Bluedot_JA3_Cache));
        }

    /* ------------------ Queues ------------------------------------------------------ */

    /* Bluedot IP Queue */

    if ( config->bluedot_ip_queue > 0 )
        {

            SaganBluedotIPQueue = malloc(config->bluedot_ip_queue * sizeof(struct _Sagan_Bluedot_IP_Queue));

            if ( SaganBluedotIPQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotIPQueue, 0, config->bluedot_ip_queue * sizeof(_Sagan_Bluedot_IP_Queue));
        }


    /* Bluedot Hash Queue */

    if ( config->bluedot_hash_queue > 0 )
        {
            SaganBluedotHashQueue = malloc(config->bluedot_hash_queue * sizeof(struct _Sagan_Bluedot_Hash_Queue));

            if ( SaganBluedotHashQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotHashQueue, 0, config->bluedot_hash_queue * sizeof(_Sagan_Bluedot_Hash_Queue));
        }

    /* Bluedot URL Queue */

    if ( config->bluedot_url_queue > 0 )
        {

            SaganBluedotURLQueue = malloc(config->bluedot_url_queue * sizeof(struct _Sagan_Bluedot_URL_Queue));

            if ( SaganBluedotURLQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotURLQueue. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotURLQueue, 0, config->bluedot_url_queue * sizeof(_Sagan_Bluedot_URL_Queue));
        }

    /* Bluedot Filename Queue */

    if ( config->bluedot_filename_queue > 0 )
        {
            SaganBluedotFilenameQueue = malloc(config->bluedot_filename_queue * sizeof(struct _Sagan_Bluedot_Filename_Queue));

            if ( SaganBluedotFilenameQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotFilenameQueue, 0, config->bluedot_filename_queue * sizeof(_Sagan_Bluedot_Filename_Queue));
        }

    /* Bluedot JA3 Queue */

    if ( config->bluedot_ja3_queue > 0 )
        {

            SaganBluedotJA3Queue = malloc(config->bluedot_ja3_queue * sizeof(struct _Sagan_Bluedot_JA3_Queue));

            if ( SaganBluedotJA3Queue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotJA3Queue. Abort!", __FILE__, __LINE__);
                }

            memset(SaganBluedotJA3Queue, 0, config->bluedot_ja3_queue * sizeof(_Sagan_Bluedot_JA3_Queue));
        }

}


/****************************************************************************
 * Sagan_Bluedot_Clean_Queue - Clean's the "queue" of the type of lookup
 * that happened.  This is called after a successful lookup.  We do this to
 * prevent multiple lookups (at the same time!) of the same item!  This
 * happens a lot with IP address looks
 ****************************************************************************/

int Sagan_Bluedot_Clean_Queue ( char *data, unsigned char type )
{

    int i=0;

    unsigned char ip_convert[MAXIPBIT] = { 0 };

    if ( type == BLUEDOT_LOOKUP_IP && config->bluedot_ip_max_cache > 0 )
        {

            IP2Bit(data, ip_convert);

            for (i=0; i<config->bluedot_ip_queue; i++)
                {

                    if ( !memcmp(ip_convert, SaganBluedotIPQueue[i].ip, MAXIPBIT) )
                        {

                            pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);
                            memset(SaganBluedotIPQueue[i].ip, 0, MAXIPBIT);
                            pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);

                        }

                }

            __atomic_sub_fetch(&counters->bluedot_ip_queue_current, 1, __ATOMIC_SEQ_CST);

        }

    else if ( type == BLUEDOT_LOOKUP_HASH && config->bluedot_hash_max_cache > 0 )
        {

            for (i=0; i<config->bluedot_hash_queue; i++)
                {

                    if ( !strcasecmp(data, SaganBluedotHashQueue[i].hash ) )
                        {

                            pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);
                            memset(SaganBluedotHashQueue[i].hash, 0, SHA256_HASH_SIZE+1);
                            pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);

                        }

                }

            __atomic_sub_fetch(&counters->bluedot_hash_queue_current, 1, __ATOMIC_SEQ_CST);

        }

    else if ( type == BLUEDOT_LOOKUP_URL && config->bluedot_url_max_cache > 0 )
        {

            for (i =0; i<config->bluedot_url_queue; i++)
                {

                    if ( !strcasecmp(data, SaganBluedotURLQueue[i].url ) )
                        {

                            pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);
                            memset(SaganBluedotURLQueue[i].url, 0, sizeof(SaganBluedotURLQueue[i].url));
                            pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);
                        }
                }

            __atomic_sub_fetch(&counters->bluedot_url_queue_current, 1, __ATOMIC_SEQ_CST);

        }

    else if ( type == BLUEDOT_LOOKUP_FILENAME && config->bluedot_filename_max_cache > 0 )
        {

            for  (i=0; i<config->bluedot_filename_queue; i++)
                {

                    if ( !strcasecmp(data, SaganBluedotFilenameQueue[i].filename ) )
                        {

                            pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);
                            memset(SaganBluedotFilenameQueue[i].filename, 0, sizeof(SaganBluedotFilenameQueue[i].filename));
                            pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);
                        }

                }

            __atomic_sub_fetch(&counters->bluedot_filename_queue_current, 1, __ATOMIC_SEQ_CST);


        }

    else if ( type == BLUEDOT_LOOKUP_JA3 && config->bluedot_ja3_max_cache > 0 )
        {

            for  (i=0; i<config->bluedot_ja3_queue; i++)
                {

                    if ( !strcasecmp(data, SaganBluedotJA3Queue[i].ja3 ) )
                        {

                            pthread_mutex_lock(&SaganProcBluedotJA3WorkMutex);
                            memset(SaganBluedotJA3Queue[i].ja3, 0, sizeof(SaganBluedotJA3Queue[i].ja3));
                            pthread_mutex_unlock(&SaganProcBluedotJA3WorkMutex);
                        }

                }

            __atomic_sub_fetch(&counters->bluedot_ja3_queue_current, 1, __ATOMIC_SEQ_CST);

        }

    return(true);
}

/****************************************************************************
 * Sagan_Bluedot_Load_Cat() - load all "Bluedot" categories in memory
 ****************************************************************************/

void Sagan_Bluedot_Load_Cat(void)
{

    FILE *bluedot_cat_file;
    char buf[1024] = { 0 };
    char *saveptr = NULL;

    char *bluedot_tok1 = NULL;
    char *bluedot_tok2 = NULL;

    if (( bluedot_cat_file = fopen(config->bluedot_cat, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] No Bluedot categories list to load (%s)!", __FILE__, __LINE__, config->bluedot_cat);
        }

    while(fgets(buf, 1024, bluedot_cat_file) != NULL)
        {

            /* Skip comments and blank linkes */

            if (buf[0] == '#' || buf[0] == 10 || buf[0] == ';' || buf[0] == 32)
                {
                    continue;

                }
            else
                {

                    /* Allocate memory for references,  not comments */

                    SaganBluedotCatList = (_Sagan_Bluedot_Cat_List *) realloc(SaganBluedotCatList, (counters->bluedot_cat_count+1) * sizeof(_Sagan_Bluedot_Cat_List));

                    if ( SaganBluedotCatList == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotCatList. Abort!", __FILE__, __LINE__);
                        }

                    memset(&SaganBluedotCatList[counters->bluedot_cat_count], 0, sizeof(_Sagan_Bluedot_Cat_List));

                    /* Normalize the list for later use.  Better to do this here than when processing rules */

                    bluedot_tok1 = strtok_r(buf, "|", &saveptr);

                    if ( bluedot_tok1 == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Bluedot categories file appears to be malformed.", __FILE__, __LINE__);
                        }

                    Remove_Return(bluedot_tok1);
                    Remove_Spaces(bluedot_tok1);

                    SaganBluedotCatList[counters->bluedot_cat_count].cat_number = atoi(bluedot_tok1);

                    bluedot_tok2 = strtok_r(NULL, "|", &saveptr);

                    if ( bluedot_tok2 == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Bluedot categories file appears to be malformed.", __FILE__, __LINE__);
                        }

                    Remove_Return(bluedot_tok2);
                    Remove_Spaces(bluedot_tok2);
                    To_LowerC(bluedot_tok2);

                    strlcpy(SaganBluedotCatList[counters->bluedot_cat_count].cat, bluedot_tok2, sizeof(SaganBluedotCatList[counters->bluedot_cat_count].cat));

                    __atomic_add_fetch(&counters->bluedot_cat_count, 1, __ATOMIC_SEQ_CST);

                }
        }

}

/****************************************************************************
 * Sagan_Bluedot_Clean_Cache() - Cleans cache.  Remove old,  stale entries
 * to make room for new,  fresh entries :)
 ****************************************************************************/

void Sagan_Bluedot_Check_Cache_Time (void)
{

    time_t t;
    struct tm *now = NULL;

    char  timet[20] = { 0 };

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    if ( bluedot_cache_clean_lock == 0 && atol(timet) > ( config->bluedot_last_time + config->bluedot_timeout ) )
        {

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);

            bluedot_cache_clean_lock = 1;

            Sagan_Log(NORMAL, "Bluedot cache timeout reached %d minutes.  Cleaning up.", config->bluedot_timeout / 60);
            Sagan_Bluedot_Clean_Cache();

            bluedot_cache_clean_lock = 0;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

        }

    if ( counters->bluedot_ip_cache_count >= config->bluedot_ip_max_cache && config->bluedot_ip_max_cache != 0  )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of IP cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

    if ( counters->bluedot_hash_cache_count >= config->bluedot_hash_max_cache && config->bluedot_hash_max_cache != 0 )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of hash cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

    if ( counters->bluedot_url_cache_count >= config->bluedot_url_max_cache && config->bluedot_url_max_cache != 0 )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of URL cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

    if ( counters->bluedot_filename_cache_count >= config->bluedot_filename_max_cache && config->bluedot_filename_max_cache != 0 )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of URL cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

    if ( counters->bluedot_ja3_cache_count >= config->bluedot_ja3_max_cache && config->bluedot_ja3_max_cache != 0 )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of JA3 cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

}

/****************************************************************************
 * Sagan_Bluedot_Clean_Cache - Cleans old Bluedot entries over the
 * specified "cache_timeout".
 ****************************************************************************/

void Sagan_Bluedot_Clean_Cache ( void )
{

    int i;
    int deleted_count=0;

    int new_bluedot_ip_max_cache = 0;
    int new_bluedot_hash_max_cache = 0;
    int new_bluedot_url_max_cache = 0;
    int new_bluedot_filename_max_cache = 0;
    int new_bluedot_ja3_max_cache = 0;

    char  timet[20] = { 0 };
    time_t t;
    struct tm *now=NULL;
    uint64_t timeint;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);
    timeint = atol(timet);

    if (debug->debugbluedot)
        {
            Sagan_Log(DEBUG, "[%s, line %d] Sagan/Bluedot cache clean time has been reached.", __FILE__, __LINE__);
            Sagan_Log(DEBUG, "[%s, line %d] ----------------------------------------------------------------------", __FILE__, __LINE__);
        }

    config->bluedot_last_time = timeint;

    deleted_count = 0;

    for (i=0; i < config->bluedot_ip_max_cache; i++ )
        {

            if ( ( timeint - SaganBluedotIPCache[i].cache_utime ) > config->bluedot_timeout )
                {

                    if (debug->debugbluedot)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] == Deleting IP address from cache -> %u",  __FILE__, __LINE__, SaganBluedotIPCache[i].ip);
                        }

                    pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);

                    memset(SaganBluedotIPCache[i].ip, 0, MAXIPBIT);
                    SaganBluedotIPCache[i].mdate_utime = 0;
                    SaganBluedotIPCache[i].cdate_utime = 0;
                    SaganBluedotIPCache[i].cache_utime = 0;
                    SaganBluedotIPCache[i].alertid = 0;

                    pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);

                    deleted_count++;

                }
            else
                {

                    new_bluedot_ip_max_cache++;

                }
        }

    pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);
    deleted_count = counters->bluedot_ip_cache_count - new_bluedot_ip_max_cache;
    counters->bluedot_ip_cache_count = new_bluedot_ip_max_cache;
    pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);

    Sagan_Log(NORMAL, "[%s, line %d] Deleted %d IP addresses from Bluedot cache. New IP cache count is %d.",__FILE__, __LINE__, deleted_count, counters->bluedot_ip_cache_count);

    /* Clean hash cache */

    deleted_count = 0;

    for (i=0; i < config->bluedot_hash_max_cache; i++ )
        {

            if ( ( timeint - SaganBluedotHashCache[i].cache_utime ) > config->bluedot_timeout )
                {

                    if (debug->debugbluedot)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] == Deleting Hash address from cache -> %s",  __FILE__, __LINE__, SaganBluedotHashCache[i].hash);
                        }

                    pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);

                    memset(SaganBluedotHashCache[i].hash, 0, SHA256_HASH_SIZE+1);
                    SaganBluedotHashCache[i].cache_utime = 0;
                    SaganBluedotHashCache[i].alertid = 0;

                    pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);

                    deleted_count++;

                }
            else
                {

                    new_bluedot_hash_max_cache++;

                }
        }

    pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);
    deleted_count = counters->bluedot_hash_cache_count - new_bluedot_hash_max_cache;
    counters->bluedot_hash_cache_count = new_bluedot_hash_max_cache;
    pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);

    Sagan_Log(NORMAL, "[%s, line %d] Deleted %d hashes from Bluedot cache. New hash cache count is %d.",__FILE__, __LINE__, deleted_count, counters->bluedot_hash_cache_count);

    /* Clean URL cache */

    deleted_count = 0;

    for (i=0; i < config->bluedot_url_max_cache; i++ )
        {

            if ( ( timeint - SaganBluedotURLCache[i].cache_utime ) > config->bluedot_timeout )
                {

                    if (debug->debugbluedot)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] == Deleting URL address from cache -> %s",  __FILE__, __LINE__, SaganBluedotURLCache[i].url);
                        }

                    pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);

                    memset(SaganBluedotURLCache[i].url, 0, sizeof(SaganBluedotURLCache[i].url));
                    SaganBluedotURLCache[i].cache_utime = 0;
                    SaganBluedotURLCache[i].alertid = 0;

                    pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);

                    deleted_count++;

                }
            else
                {

                    new_bluedot_url_max_cache++;

                }
        }

    pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);
    deleted_count = counters->bluedot_url_cache_count - new_bluedot_url_max_cache;
    counters->bluedot_url_cache_count = new_bluedot_url_max_cache;
    pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);

    Sagan_Log(NORMAL, "[%s, line %d] Deleted %d URLs from Bluedot cache. New URL cache count is %d.",__FILE__, __LINE__, deleted_count, counters->bluedot_url_cache_count);

    /* Clean Filename cache */

    deleted_count = 0;

    for (i=0; i < config->bluedot_filename_max_cache; i++ )
        {

            if ( ( timeint - SaganBluedotFilenameCache[i].cache_utime ) > config->bluedot_timeout )
                {

                    if (debug->debugbluedot)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] == Deleting filename from cache -> %s",  __FILE__, __LINE__, SaganBluedotFilenameCache[i].filename);
                        }

                    pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);

                    memset(SaganBluedotFilenameCache[i].filename, 0, sizeof(SaganBluedotFilenameCache[i].filename));
                    SaganBluedotFilenameCache[i].cache_utime = 0;
                    SaganBluedotFilenameCache[i].alertid = 0;

                    pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);

                    deleted_count++;

                }
            else
                {

                    new_bluedot_filename_max_cache++;

                }
        }

    pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);
    deleted_count = counters->bluedot_filename_cache_count - new_bluedot_filename_max_cache;
    counters->bluedot_filename_cache_count = new_bluedot_filename_max_cache;
    pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);

    Sagan_Log(NORMAL, "[%s, line %d] Deleted %d Filenames from Bluedot cache. New Filename cache count is %d.",__FILE__, __LINE__, deleted_count, counters->bluedot_filename_cache_count);

    /* Clean JA3 cache */

    deleted_count = 0;

    for (i=0; i < config->bluedot_ja3_max_cache; i++ )
        {

            if ( ( timeint - SaganBluedotJA3Cache[i].cache_utime ) > config->bluedot_timeout )
                {

                    if (debug->debugbluedot)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] == Deleting JA3 from cache -> %s",  __FILE__, __LINE__, SaganBluedotJA3Cache[i].ja3);
                        }

                    pthread_mutex_lock(&SaganProcBluedotJA3WorkMutex);

                    memset(SaganBluedotJA3Cache[i].ja3, 0, sizeof(SaganBluedotJA3Cache[i].ja3));
                    SaganBluedotFilenameCache[i].cache_utime = 0;
                    SaganBluedotFilenameCache[i].alertid = 0;

                    pthread_mutex_unlock(&SaganProcBluedotJA3WorkMutex);

                    deleted_count++;

                }
            else
                {

                    new_bluedot_ja3_max_cache++;

                }
        }

    pthread_mutex_lock(&SaganProcBluedotJA3WorkMutex);
    deleted_count = counters->bluedot_ja3_cache_count - new_bluedot_ja3_max_cache;
    counters->bluedot_ja3_cache_count = new_bluedot_ja3_max_cache;
    pthread_mutex_unlock(&SaganProcBluedotJA3WorkMutex);

    Sagan_Log(NORMAL, "[%s, line %d] Deleted %d JA3 hashes from Bluedot cache. New Filename cache count is %d.",__FILE__, __LINE__, deleted_count, counters->bluedot_ja3_cache_count);


}

/***************************************************************************
 * Sagan_Bluedot_IP_Lookup - This does the actual Bluedot lookup.  It returns
 * the bluedot_alertid value (0 if not found)
 ***************************************************************************/

/* type
 *
 * 1 == IP
 * 2 == Hash
 * 3 == URL
 * 4 == Filename
 * 5 == JA3
 */

unsigned char Sagan_Bluedot_Lookup(char *data,  unsigned char type, int rule_position, char *bluedot_str, size_t bluedot_size )
{

    unsigned char ip_convert[MAXIPBIT] = { 0 };

    char buff[2048] = { 0 };
    char tmpdeviceid[64] = { 0 };
    char bluedot_json[BLUEDOT_JSON_SIZE] = { 0 };

    char *jsonptr = NULL;
    char *jsonptr_f = NULL;

    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    char json_final[2048] = { 0 };

    struct json_object *json_in = NULL;
    json_object *string_obj;

    const char *cat=NULL;
    const char *cdate_utime=NULL;
    const char *mdate_utime=NULL;

    uint64_t cdate_utime_u32;
    uint64_t mdate_utime_u32;

    signed char bluedot_alertid = 0;		/* -128 to 127 */
    int i;

    char tmp[64] = { 0 };

    char  timet[20] = { 0 };
    time_t t;
    struct tm *now=NULL;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    uint64_t epoch_time = atol(timet);

    /* Check IP TTL for Bluedot */

    if ( bluedot_dns_global == 0 && epoch_time - config->bluedot_dns_last_lookup > config->bluedot_dns_ttl )
        {

            if ( debug->debugbluedot )
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Bluedot host TTL of %d seconds reached.  Doing new lookup for '%s'.", __FILE__, __LINE__, config->bluedot_dns_ttl, config->bluedot_host);
                }


            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
            bluedot_dns_global = 1;

            i = DNS_Lookup( config->bluedot_host, tmp, sizeof(tmp) );

            if ( i != 0 )
                {
                    Sagan_Log(WARN, "[%s, line %d] Cannot lookup DNS for '%s'.  Staying with old value of %s.", __FILE__, __LINE__, config->bluedot_host, config->bluedot_ip);
                }
            else
                {

                    strlcpy(config->bluedot_ip, tmp, sizeof(config->bluedot_ip));

                    if ( debug->debugbluedot )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Bluedot host IP is now: %s", __FILE__, __LINE__, config->bluedot_ip);
                        }

                }

            config->bluedot_dns_last_lookup = epoch_time;
            bluedot_dns_global = 0;
            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

        }


    /************************************************************************/
    /* Lookup types                                                         */
    /************************************************************************/

    /* IP Address Lookup */

    if ( type == BLUEDOT_LOOKUP_IP )
        {

            /* For some reason, when I try to use the IP2Bit passed from engine.c,  it
               is sometimes 16 bytes off!  Not idea why and doesn't happen all the time.
               We call IP2Bit here to prevent it from getting off :(  Champ 2019/05/14 */

            IP2Bit(data, ip_convert);

            if ( is_notroutable(ip_convert) )
                {

                    if ( debug->debugbluedot )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, data);
                        }

                    return(false);
                }

            for ( i = 0; i < counters->bluedot_skip_count; i++ )
                {

                    if ( is_inrange(ip_convert, (unsigned char *)&Bluedot_Skip[i].range, 1) )
                        {

                            if ( debug->debugbluedot )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] IP address %s is in Bluedot 'skip_networks'. Skipping lookup.", __FILE__, __LINE__, data);
                                }

                            return(false);
                        }

                }


            for (i=0; i<config->bluedot_ip_max_cache; i++)
                {

                    if (!memcmp( ip_convert, SaganBluedotIPCache[i].ip, MAXIPBIT ))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled %s from Bluedot cache with category of \"%d\". [cdate_epoch: %d / mdate_epoch: %d]", __FILE__, __LINE__, data, SaganBluedotIPCache[i].alertid, SaganBluedotIPCache[i].cdate_utime, SaganBluedotIPCache[i].mdate_utime);
                                }

                            bluedot_alertid = SaganBluedotIPCache[i].alertid;

                            if ( bluedot_alertid != 0 && rulestruct[rule_position].bluedot_mdate_effective_period != 0 )
                                {

                                    if ( ( epoch_time - SaganBluedotIPCache[i].mdate_utime ) > rulestruct[rule_position].bluedot_mdate_effective_period )
                                        {

                                            if ( debug->debugbluedot )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] From Bluedot Cache - mdate_epoch for %s is over %d seconds.  Not alerting.", __FILE__, __LINE__, data, rulestruct[rule_position].bluedot_mdate_effective_period);
                                                }

                                            __atomic_add_fetch(&counters->bluedot_mdate_cache, 1, __ATOMIC_SEQ_CST);

                                            bluedot_alertid = 0;
                                        }
                                }

                            else if ( bluedot_alertid != 0 && rulestruct[rule_position].bluedot_cdate_effective_period != 0 )
                                {

                                    if ( ( epoch_time - SaganBluedotIPCache[i].cdate_utime ) > rulestruct[rule_position].bluedot_cdate_effective_period )
                                        {

                                            if ( debug->debugbluedot )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] ctime_epoch for %s is over %d seconds.  Not alerting.", __FILE__, __LINE__, data, rulestruct[rule_position].bluedot_cdate_effective_period);
                                                }

                                            __atomic_add_fetch(&counters->bluedot_cdate_cache, 1, __ATOMIC_SEQ_CST);

                                            bluedot_alertid = 0;
                                        }
                                }

                            __atomic_add_fetch(&counters->bluedot_ip_cache_hit, 1, __ATOMIC_SEQ_CST);

                            snprintf(bluedot_str, bluedot_size, "%s",  SaganBluedotIPCache[i].bluedot_json);
                            return(bluedot_alertid);

                        }

                }

            /* Check Bluedot IP Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < config->bluedot_ip_queue; i++)
                {
                    if ( !memcmp(ip_convert, SaganBluedotIPQueue[i].ip, MAXIPBIT ))
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] %s (%u) is already being looked up. Skipping....", __FILE__, __LINE__, data, SaganBluedotIPQueue[i].ip);
                                }

                            return(false);
                        }
                }

            /* If not in Bluedot IP queue,  add it */

            if ( counters->bluedot_ip_queue_current >= config->bluedot_ip_queue )
                {
                    Sagan_Log(NORMAL, "[%s, line %d] Out of IP queue space! Considering increasing cache size!", __FILE__, __LINE__);
                    return(false);
                }


            for (i=0; i < config->bluedot_ip_queue; i++)
                {

                    /* Find an empty slot */

                    if ( SaganBluedotIPQueue[i].ip[0] == 0 )
                        {
                            pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);

                            memcpy(SaganBluedotIPQueue[i].ip, ip_convert, MAXIPBIT);
                            counters->bluedot_ip_queue_current++;

                            pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);

                            break;

                        }
                }


            snprintf(buff, sizeof(buff), "GET /%s%s%s HTTP/1.1\r\nHost: %s\r\n%s\r\nX-BLUEDOT-DEVICEID: %s\r\nConnection: close\r\n\r\n", config->bluedot_uri, BLUEDOT_IP_LOOKUP_URL, data, config->bluedot_host, BLUEDOT_PROCESSOR_USER_AGENT, config->bluedot_device_id);

        }  /* BLUEDOT_LOOKUP_IP */

    else if ( type == BLUEDOT_LOOKUP_HASH )
        {

            for (i=0; i<counters->bluedot_hash_cache_count; i++)
                {

                    if (!strcasecmp(data, SaganBluedotHashCache[i].hash))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled file hash '%s' from Bluedot hash cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotHashCache[i].alertid);
                                }

                            __atomic_add_fetch(&counters->bluedot_hash_cache_hit, 1, __ATOMIC_SEQ_CST);

                            snprintf(bluedot_str, bluedot_size, "%s", SaganBluedotHashCache[i].bluedot_json);
                            return(SaganBluedotHashCache[i].alertid);

                        }

                }

            /* Check Bluedot Hash Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < config->bluedot_hash_queue; i++)
                {
                    if ( !strcasecmp(data, SaganBluedotHashQueue[i].hash ) )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] %s is already being looked up. Skipping....", __FILE__, __LINE__, data);
                                }

                            return(false);
                        }
                }


            if ( counters->bluedot_hash_queue_current >= config->bluedot_hash_queue )
                {
                    Sagan_Log(NORMAL, "[%s, line %d] Out of hash queue space! Considering increasing cache size!", __FILE__, __LINE__);
                    return(false);
                }

            /* If not in Bluedot Hash queue,  add it */

            for (i=0; i < config->bluedot_ip_queue; i++)
                {
                    /* Find an empty slot */

                    if ( SaganBluedotHashQueue[i].hash[0] == 0 )
                        {
                            pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);

                            strlcpy(SaganBluedotHashQueue[i].hash, data, sizeof(SaganBluedotHashQueue[i].hash));
                            counters->bluedot_hash_queue_current++;

                            pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);

                            break;

                        }
                }

            snprintf(buff, sizeof(buff), "GET /%s%s%s HTTP/1.1\r\nHost: %s\r\n%s\r\nX-BLUEDOT-DEVICEID: %s\r\nConnection: close\r\n\r\n", config->bluedot_uri, BLUEDOT_HASH_LOOKUP_URL, data, config->bluedot_host, BLUEDOT_PROCESSOR_USER_AGENT, config->bluedot_device_id);

        }

    else if ( type == BLUEDOT_LOOKUP_URL )
        {

            for (i=0; i<counters->bluedot_url_cache_count; i++)
                {

                    if (!strcasecmp(data, SaganBluedotURLCache[i].url))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled file URL '%s' from Bluedot URL cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotURLCache[i].alertid);
                                }

                            __atomic_add_fetch(&counters->bluedot_url_cache_hit, 1, __ATOMIC_SEQ_CST);

                            snprintf(bluedot_str, bluedot_size, "%s", SaganBluedotURLCache[i].bluedot_json);
                            return(SaganBluedotURLCache[i].alertid);

                        }


                }

            /* Check Bluedot Hash Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < config->bluedot_url_queue; i++)
                {
                    if ( !strcasecmp(data, SaganBluedotURLQueue[i].url ) )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] %s is already being looked up. Skipping....", __FILE__, __LINE__, data);
                                }

                            return(false);
                        }
                }


            /* If not in Bluedot URL queue,  add it */

            if ( counters->bluedot_url_queue_current >= config->bluedot_url_queue )
                {
                    Sagan_Log(NORMAL, "[%s, line %d] Out of URL queue space! Considering increasing cache size!", __FILE__, __LINE__);
                    return(false);
                }


            for (i=0; i < config->bluedot_url_queue; i++)
                {

                    /* Find an empty slot */

                    if ( SaganBluedotURLQueue[i].url[0] == 0 )
                        {
                            pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);

                            strlcpy(SaganBluedotURLQueue[i].url, data, sizeof(SaganBluedotURLQueue[i].url));
                            counters->bluedot_url_queue_current++;

                            pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);

                            break;

                        }
                }

            snprintf(buff, sizeof(buff), "GET /%s%s%s HTTP/1.1\r\nHost: %s\r\n%s\r\nX-BLUEDOT-DEVICEID: %s\r\nConnection: close\r\n\r\n", config->bluedot_uri, BLUEDOT_URL_LOOKUP_URL, data, config->bluedot_host, BLUEDOT_PROCESSOR_USER_AGENT, config->bluedot_device_id);

        }

    else if ( type == BLUEDOT_LOOKUP_FILENAME )
        {

            for (i=0; i<counters->bluedot_filename_cache_count; i++)
                {

                    if (!strcasecmp(data, SaganBluedotFilenameCache[i].filename))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled file filename '%s' from Bluedot filename cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotFilenameCache[i].alertid);
                                }

                            __atomic_add_fetch(&counters->bluedot_filename_cache_hit, 1, __ATOMIC_SEQ_CST);

                            snprintf(bluedot_str, bluedot_size, "%s",  SaganBluedotFilenameCache[i].bluedot_json);
                            return(SaganBluedotFilenameCache[i].alertid);

                        }

                }

            /* Check Bluedot File Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < config->bluedot_filename_queue; i++)
                {
                    if ( !strcasecmp(SaganBluedotFilenameQueue[i].filename, data ) )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] %s is already being looked up. Skipping....", __FILE__, __LINE__, data);
                                }

                            return(false);
                        }
                }


            /* If not in Bluedot Filename queue,  add it */

            if ( counters->bluedot_filename_queue_current >= config->bluedot_filename_queue )
                {
                    Sagan_Log(NORMAL, "[%s, line %d] Out of filename queue space! Considering increasing cache size!", __FILE__, __LINE__);
                    return(false);
                }


            for (i=0; i < config->bluedot_filename_queue; i++)
                {

                    /* Find an empty slot */

                    if ( SaganBluedotFilenameQueue[i].filename[0] == 0 )
                        {
                            pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);

                            strlcpy(SaganBluedotFilenameQueue[i].filename, data, sizeof(SaganBluedotFilenameQueue[i].filename));
                            counters->bluedot_filename_queue_current++;

                            pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);

                            break;

                        }
                }

            snprintf(buff, sizeof(buff), "GET /%s%s%s HTTP/1.1\r\nHost: %s\r\n%s\r\nX-BLUEDOT-DEVICEID: %s\r\nConnection: close\r\n\r\n", config->bluedot_uri, BLUEDOT_FILENAME_LOOKUP_URL, data, config->bluedot_host, BLUEDOT_PROCESSOR_USER_AGENT, config->bluedot_device_id);

        }

    else if ( type == BLUEDOT_LOOKUP_JA3 )
        {

            for (i=0; i<counters->bluedot_ja3_cache_count; i++)
                {

                    if (!strcasecmp(data, SaganBluedotJA3Cache[i].ja3))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled file JA3 '%s' from Bluedot JA3 cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotJA3Cache[i].alertid);
                                }

                            __atomic_add_fetch(&counters->bluedot_ja3_cache_hit, 1, __ATOMIC_SEQ_CST);

                            snprintf(bluedot_str, bluedot_size, "%s",  SaganBluedotJA3Cache[i].bluedot_json);
                            return(SaganBluedotJA3Cache[i].alertid);

                        }

                }

            /* Check Bluedot JA3 Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < config->bluedot_ja3_queue; i++)
                {
                    if ( !strcasecmp(SaganBluedotJA3Queue[i].ja3, data ) )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] %s is already being looked up. Skipping....", __FILE__, __LINE__, data);
                                }

                            return(false);
                        }
                }


            /* If not in Bluedot JA3 queue,  add it */

            if ( counters->bluedot_ja3_queue_current >= config->bluedot_ja3_queue )
                {
                    Sagan_Log(NORMAL, "[%s, line %d] Out of JA3 queue space! Considering increasing cache size!", __FILE__, __LINE__);
                    return(false);
                }


            for (i=0; i < config->bluedot_ja3_queue; i++)
                {

                    /* Find an empty slot */

                    if ( SaganBluedotJA3Queue[i].ja3[0] == 0 )
                        {
                            pthread_mutex_lock(&SaganProcBluedotJA3WorkMutex);

                            strlcpy(SaganBluedotJA3Queue[i].ja3, data, sizeof(SaganBluedotJA3Queue[i].ja3));
                            counters->bluedot_ja3_queue_current++;

                            pthread_mutex_unlock(&SaganProcBluedotJA3WorkMutex);

                            break;

                        }
                }

            snprintf(buff, sizeof(buff), "GET /%s%s%s HTTP/1.1\r\nHost: %s\r\n%s\r\nX-BLUEDOT-DEVICEID: %s\r\nConnection: close\r\n\r\n", config->bluedot_uri, BLUEDOT_JA3_LOOKUP_URL, data, config->bluedot_host, BLUEDOT_PROCESSOR_USER_AGENT, config->bluedot_device_id);

        }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
        {
            Sagan_Log(WARN, "[%s, %d] Unable to create socket for Bluedot request!", __FILE__, __LINE__);
            return(false);
        }


    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(config->bluedot_ip);
    servaddr.sin_port = htons(80);

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
        {
            Sagan_Log(WARN, "[%s, %d] Unabled to connect to server %s!", __FILE__, __LINE__, config->bluedot_ip);
            __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(false);
        }

    /* Send request */

    write(sockfd, buff, sizeof(buff));

    /* Get response */

    bzero(buff, sizeof(buff));
    read(sockfd, buff, sizeof(buff));

    /* Close the socket! */

    close(sockfd);

    /* Search for the JSON */

    strtok_r( buff, "{", &jsonptr);
    jsonptr_f = strtok_r( NULL, "{", &jsonptr);

    if ( jsonptr_f == NULL )
        {
            Sagan_Log(WARN, "[%s, line %d] Unable to find JSON in server response!", __FILE__, __LINE__);
            __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(false);
        }


    /* The strtork_r removes the first { so we re-add it */

    snprintf(json_final, sizeof(json_final), "{%s", jsonptr_f);
    json_final[ sizeof(json_final) - 1 ] = '\0';

    /* Do actual JSON parsing ! */

    json_in = json_tokener_parse(json_final);

    if ( json_in == NULL )
        {
            Sagan_Log(WARN, "[%s, line %d] Unable to parse bluedot JSON: %s", __FILE__, __LINE__, json_final);
            __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);
            return(false);
        }


    if ( type == BLUEDOT_LOOKUP_IP )
        {

            json_object_object_get_ex(json_in, "ctime_epoch", &string_obj);
            cdate_utime = json_object_get_string(string_obj);

            if ( cdate_utime != NULL )
                {

                    cdate_utime_u32 = atol(cdate_utime);

                }
            else
                {

                    Sagan_Log(WARN, "Bluedot return a bad ctime_epoch.");

                }

            json_object_object_get_ex(json_in, "mtime_epoch", &string_obj);
            mdate_utime = json_object_get_string(string_obj);

            if ( mdate_utime != NULL )
                {

                    mdate_utime_u32 = atol(mdate_utime);

                }
            else
                {

                    Sagan_Log(WARN, "Bluedot return a bad mdate_epoch.");

                }

        }

    json_object_object_get_ex(json_in, "code", &string_obj);
    cat = json_object_get_string(string_obj);

    if ( cat == NULL )
        {
            Sagan_Log(WARN, "Bluedot return a qipcode category.");

            __atomic_add_fetch(&counters->bluedot_error_count, 1, __ATOMIC_SEQ_CST);

            return(false);
        }

    /* strtok_r() doesn't like const char *cat */

    bluedot_alertid  = atoi(cat);

    if ( debug->debugbluedot)
        {
            Sagan_Log(DEBUG, "[%s, line %d] Bluedot return category \"%d\" for %s. [cdate_epoch: %d / mdate_epoch: %d]", __FILE__, __LINE__, bluedot_alertid, data, cdate_utime_u32, mdate_utime_u32);
        }

    if ( bluedot_alertid == -1 )
        {
            Sagan_Log(WARN, "Bluedot reports an invalid API key.  Lookup aborted!");
            counters->bluedot_error_count++;
            return(false);
        }


    /************************************************************************/
    /* Add entries to cache                                                 */
    /************************************************************************/

    /* IP Address lookup */

    if ( type == BLUEDOT_LOOKUP_IP )
        {

            pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);

            /* Store data into cache */

            memcpy(SaganBluedotIPCache[counters->bluedot_ip_cache_count].ip, ip_convert, MAXIPBIT);
            strlcpy(SaganBluedotIPCache[counters->bluedot_ip_cache_count].bluedot_json, json_final, sizeof(SaganBluedotIPCache[counters->bluedot_ip_cache_count].bluedot_json));
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].cache_utime = epoch_time;                   /* store utime */
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].cdate_utime = cdate_utime_u32;
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].mdate_utime = mdate_utime_u32;
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].alertid = bluedot_alertid;

            counters->bluedot_ip_total++;
            counters->bluedot_ip_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);

            if ( bluedot_alertid != 0 && rulestruct[rule_position].bluedot_mdate_effective_period != 0 )
                {

                    if ( ( epoch_time - mdate_utime_u32 ) > rulestruct[rule_position].bluedot_mdate_effective_period )
                        {

                            if ( debug->debugbluedot )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] mdate_epoch for %s is over %d seconds.  Not alerting.", __FILE__, __LINE__, data, rulestruct[rule_position].bluedot_mdate_effective_period);
                                }

                            __atomic_add_fetch(&counters->bluedot_mdate, 1, __ATOMIC_SEQ_CST);

                            bluedot_alertid = 0;
                        }
                }

            else if ( bluedot_alertid != 0 && rulestruct[rule_position].bluedot_cdate_effective_period != 0 )
                {

                    if ( ( epoch_time - cdate_utime_u32 ) > rulestruct[rule_position].bluedot_cdate_effective_period )
                        {

                            if ( debug->debugbluedot )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] cdate_epoch for %s is over %d seconds.  Not alerting.", __FILE__, __LINE__, data, rulestruct[rule_position].bluedot_cdate_effective_period);
                                }

                            __atomic_add_fetch(&counters->bluedot_cdate, 1, __ATOMIC_SEQ_CST);


                            bluedot_alertid = 0;
                        }
                }

        }

    /* File hash lookup */

    else if ( type == BLUEDOT_LOOKUP_HASH )
        {

            pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);

            counters->bluedot_hash_total++;

            strlcpy(SaganBluedotHashCache[counters->bluedot_hash_cache_count].hash, data, sizeof(SaganBluedotHashCache[counters->bluedot_hash_cache_count].hash));
            strlcpy(SaganBluedotHashCache[counters->bluedot_hash_cache_count].bluedot_json, json_final, sizeof(SaganBluedotHashCache[counters->bluedot_hash_cache_count].bluedot_json));
            SaganBluedotHashCache[counters->bluedot_hash_cache_count].cache_utime = epoch_time;
            SaganBluedotHashCache[counters->bluedot_hash_cache_count].alertid = bluedot_alertid;
            counters->bluedot_hash_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);

        }

    /* URL lookup */

    else if ( type == BLUEDOT_LOOKUP_URL )
        {
            pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);

            counters->bluedot_url_total++;

            strlcpy(SaganBluedotURLCache[counters->bluedot_url_cache_count].url, data, sizeof(SaganBluedotURLCache[counters->bluedot_url_cache_count].url));
            strlcpy(SaganBluedotURLCache[counters->bluedot_url_cache_count].bluedot_json, json_final, sizeof(SaganBluedotURLCache[counters->bluedot_url_cache_count].bluedot_json));
            SaganBluedotURLCache[counters->bluedot_url_cache_count].cache_utime = epoch_time;
            SaganBluedotURLCache[counters->bluedot_url_cache_count].alertid = bluedot_alertid;
            counters->bluedot_url_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);

        }

    /* Filename Lookup */

    else if ( type == BLUEDOT_LOOKUP_FILENAME )
        {

            pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);

            counters->bluedot_filename_total++;

            strlcpy(SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].filename, data, sizeof(SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].filename));
            strlcpy(SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].bluedot_json, json_final, sizeof(SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].bluedot_json));
            SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].cache_utime = epoch_time;
            SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].alertid = bluedot_alertid;
            counters->bluedot_filename_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);
        }

    /* JA3 Lookup */

    else if ( type == BLUEDOT_LOOKUP_JA3 )
        {

            pthread_mutex_lock(&SaganProcBluedotJA3WorkMutex);

            counters->bluedot_ja3_total++;

            strlcpy(SaganBluedotJA3Cache[counters->bluedot_ja3_cache_count].ja3, data, sizeof(SaganBluedotJA3Cache[counters->bluedot_ja3_cache_count].ja3));
            strlcpy(SaganBluedotJA3Cache[counters->bluedot_ja3_cache_count].bluedot_json, json_final, sizeof(SaganBluedotJA3Cache[counters->bluedot_ja3_cache_count].bluedot_json));
            SaganBluedotJA3Cache[counters->bluedot_ja3_cache_count].cache_utime = epoch_time;
            SaganBluedotJA3Cache[counters->bluedot_ja3_cache_count].alertid = bluedot_alertid;
            counters->bluedot_ja3_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotJA3WorkMutex);
        }

    Sagan_Bluedot_Clean_Queue(data, type);	/* Remove item for "queue" */

    json_object_put(json_in);       		/* Clear json_in as we're done with it */

    snprintf(bluedot_str, bluedot_size, "%s", json_final);

    return(bluedot_alertid);
}

/***************************************************************************
 * Sagan_Bluedot_Cat_Compare - Takes the Bluedot query results and
 * compares to what the rule is looking for
 ***************************************************************************/

int Sagan_Bluedot_Cat_Compare ( unsigned char bluedot_results, int rule_position, unsigned char type )
{

    int i;

    if ( type == BLUEDOT_LOOKUP_IP )
        {

            for ( i = 0; i < rulestruct[rule_position].bluedot_ip_cat_count; i++ )
                {

                    if ( bluedot_results == rulestruct[rule_position].bluedot_ip_cats[i] )
                        {

                            __atomic_add_fetch(&counters->bluedot_ip_positive_hit, 1, __ATOMIC_SEQ_CST);

                            return(true);
                        }

                }

            return(false);
        }

    if ( type == BLUEDOT_LOOKUP_HASH )
        {
            for ( i = 0; i < rulestruct[rule_position].bluedot_hash_cat_count; i++ )
                {

                    if ( bluedot_results == rulestruct[rule_position].bluedot_hash_cats[i] )
                        {
                            __atomic_add_fetch(&counters->bluedot_hash_positive_hit, 1, __ATOMIC_SEQ_CST);

                            return(true);
                        }
                }
            return(false);
        }

    if ( type == BLUEDOT_LOOKUP_URL )
        {
            for ( i = 0; i < rulestruct[rule_position].bluedot_url_cat_count; i++ )
                {

                    if ( bluedot_results == rulestruct[rule_position].bluedot_url_cats[i] )
                        {

                            __atomic_add_fetch(&counters->bluedot_url_positive_hit, 1, __ATOMIC_SEQ_CST);

                            return(true);
                        }
                }
            return(false);
        }

    if ( type == BLUEDOT_LOOKUP_FILENAME )
        {
            for ( i = 0; i < rulestruct[rule_position].bluedot_filename_cat_count; i++ )
                {

                    if ( bluedot_results == rulestruct[rule_position].bluedot_filename_cats[i] )
                        {
                            __atomic_add_fetch(&counters->bluedot_filename_positive_hit, 1, __ATOMIC_SEQ_CST);

                            return(true);

                        }
                }
            return(false);
        }


    if ( type == BLUEDOT_LOOKUP_JA3 )
        {
            for ( i = 0; i < rulestruct[rule_position].bluedot_ja3_cat_count; i++ )
                {

                    if ( bluedot_results == rulestruct[rule_position].bluedot_ja3_cats[i] )
                        {
                            __atomic_add_fetch(&counters->bluedot_ja3_positive_hit, 1, __ATOMIC_SEQ_CST);

                            return(true);

                        }
                }
            return(false);
        }


    return(false);
}

/***************************************************************************
 * Sagan_Bluedot_Lookup_All - Find _all_ IPv4 addresses in a syslog
 * message and preforms a Bluedot query.
 ***************************************************************************/

int Sagan_Bluedot_IP_Lookup_All ( char *syslog_message, int rule_position, _Sagan_Lookup_Cache_Entry *lookup_cache, int lookup_cache_size )
{

    int i;

    unsigned char bluedot_results;
    bool bluedot_flag;

    char bluedot_json[BLUEDOT_JSON_SIZE] = { 0 };

    for (i = 0; i < lookup_cache_size; i++)
        {

            bluedot_results = Sagan_Bluedot_Lookup(lookup_cache[i].ip, BLUEDOT_LOOKUP_IP, rule_position, bluedot_json, sizeof(bluedot_json));
            bluedot_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, rule_position, BLUEDOT_LOOKUP_IP );

            if ( bluedot_flag == 1 )
                {
                    return(true);
                }

        }

    return(false);
}

void Sagan_Verify_Categories( char *categories, int rule_number, const char *ruleset, int linecount, unsigned char type )
{

    char tmp2[64];
    char *tmptoken;
    char *saveptrrule;

    int i;

    bool found;

    tmptoken = strtok_r(categories, ",", &saveptrrule);

    while ( tmptoken != NULL )
        {

            strlcpy(tmp2, tmptoken, sizeof(tmp2));

            Remove_Spaces(tmptoken);
            To_LowerC(tmptoken);

            found = 0;

            for ( i = 0; i < counters->bluedot_cat_count; i++ )
                {


                    if (!strcmp(SaganBluedotCatList[i].cat, tmptoken))
                        {
                            found = 1;

                            if ( type == BLUEDOT_LOOKUP_IP )
                                {

                                    if ( rulestruct[rule_number].bluedot_ip_cat_count <= BLUEDOT_MAX_CAT )
                                        {
                                            rulestruct[rule_number].bluedot_ip_cats[rulestruct[rule_number].bluedot_ip_cat_count] =  SaganBluedotCatList[i].cat_number;
                                            rulestruct[rule_number].bluedot_ip_cat_count++;
                                        }
                                    else
                                        {
                                            Sagan_Log(WARN, "[%s, line %d] To many Bluedot IP catagories detected in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
                                        }
                                }

                            if ( type == BLUEDOT_LOOKUP_HASH )
                                {
                                    if ( rulestruct[rule_number].bluedot_hash_cat_count <= BLUEDOT_MAX_CAT )
                                        {
                                            rulestruct[rule_number].bluedot_hash_cats[rulestruct[rule_number].bluedot_hash_cat_count] =  SaganBluedotCatList[i].cat_number;
                                            rulestruct[rule_number].bluedot_hash_cat_count++;
                                        }
                                    else
                                        {
                                            Sagan_Log(WARN, "[%s, line %d] To many Bluedot hash catagories detected in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
                                        }
                                }

                            if ( type == BLUEDOT_LOOKUP_URL )
                                {
                                    if ( rulestruct[rule_number].bluedot_url_cat_count <= BLUEDOT_MAX_CAT )
                                        {
                                            rulestruct[rule_number].bluedot_url_cats[rulestruct[rule_number].bluedot_url_cat_count] =  SaganBluedotCatList[i].cat_number;
                                            rulestruct[rule_number].bluedot_url_cat_count++;
                                        }
                                    else
                                        {
                                            Sagan_Log(WARN, "[%s, line %d] To many Bluedot URL catagories detected in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
                                        }
                                }

                            if ( type == BLUEDOT_LOOKUP_FILENAME )
                                {
                                    if ( rulestruct[rule_number].bluedot_filename_cat_count <= BLUEDOT_MAX_CAT )
                                        {
                                            rulestruct[rule_number].bluedot_filename_cats[rulestruct[rule_number].bluedot_filename_cat_count] =  SaganBluedotCatList[i].cat_number;
                                            rulestruct[rule_number].bluedot_filename_cat_count++;
                                        }
                                    else
                                        {
                                            Sagan_Log(WARN, "[%s, line %d] To many Bluedot Filename catagories detected in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
                                        }
                                }

                            if ( type == BLUEDOT_LOOKUP_JA3 )
                                {
                                    if ( rulestruct[rule_number].bluedot_ja3_cat_count <= BLUEDOT_MAX_CAT )
                                        {
                                            rulestruct[rule_number].bluedot_ja3_cats[rulestruct[rule_number].bluedot_ja3_cat_count] =  SaganBluedotCatList[i].cat_number;
                                            rulestruct[rule_number].bluedot_ja3_cat_count++;
                                        }
                                    else
                                        {
                                            Sagan_Log(WARN, "[%s, line %d] To many Bluedot JA3 catagories detected in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
                                        }
                                }

                        }
                }

            if ( found == 0 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Unknown Bluedot category '%s' found in %s at line %d. Abort!", __FILE__, __LINE__, tmp2, ruleset, linecount);
                }

            tmptoken = strtok_r(NULL, ",", &saveptrrule);

        }

}

#endif

