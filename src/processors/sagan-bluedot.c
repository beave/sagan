/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-bluedot.c
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
#include <curl/curl.h>
#include <json.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "sagan-rules.h"
#include "sagan-bluedot.h"

#include "parsers/parsers.h"

struct _SaganCounters *counters;
struct _SaganConfig *config;
struct _SaganDebug *debug;

struct _Sagan_Bluedot_IP_Cache *SaganBluedotIPCache;
struct _Sagan_Bluedot_Hash_Cache *SaganBluedotHashCache;
struct _Sagan_Bluedot_URL_Cache *SaganBluedotURLCache;
struct _Sagan_Bluedot_Filename_Cache *SaganBluedotFilenameCache;
struct _Sagan_Bluedot_Cat_List *SaganBluedotCatList;

struct _Sagan_Bluedot_IP_Queue *SaganBluedotIPQueue;
struct _Sagan_Bluedot_Hash_Queue *SaganBluedotHashQueue;
struct _Sagan_Bluedot_URL_Queue *SaganBluedotURLQueue;
struct _Sagan_Bluedot_Filename_Queue *SaganBluedotFilenameQueue;

struct _Rule_Struct *rulestruct;

pthread_mutex_t SaganProcBluedotWorkMutex=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t SaganProcBluedotIPWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotHashWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotURLWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotFilenameWorkMutex=PTHREAD_MUTEX_INITIALIZER;


sbool bluedot_cache_clean_lock=0;

int bluedot_ip_queue=0;
int bluedot_hash_queue=0;
int bluedot_url_queue=0;
int bluedot_filename_queue=0;

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

    /* Bluedot IP Cache */

    SaganBluedotIPCache = malloc(config->bluedot_max_cache * sizeof(struct _Sagan_Bluedot_IP_Cache));

    if ( SaganBluedotIPCache == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotIPCache. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotIPCache, 0, sizeof(_Sagan_Bluedot_IP_Cache));

    /* Bluedot Hash Cache */

    SaganBluedotHashCache = malloc(config->bluedot_max_cache * sizeof(struct _Sagan_Bluedot_Hash_Cache));

    if ( SaganBluedotHashCache == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotHashCache. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotHashCache, 0, sizeof(_Sagan_Bluedot_Hash_Cache));

    /* Bluedot URL Cache */

    SaganBluedotURLCache = malloc(config->bluedot_max_cache * sizeof(struct _Sagan_Bluedot_URL_Cache));

    if ( SaganBluedotURLCache == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotURLCache. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotURLCache, 0, sizeof(_Sagan_Bluedot_URL_Cache));

    /* Bluedot Filename Cache */

    SaganBluedotFilenameCache = malloc(config->bluedot_max_cache * sizeof(struct _Sagan_Bluedot_Filename_Cache));

    if ( SaganBluedotFilenameCache == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotFilenameCache. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotFilenameCache, 0, sizeof(_Sagan_Bluedot_Filename_Cache));

    /* Bluedot Catlist */

    SaganBluedotCatList = malloc(sizeof(_Sagan_Bluedot_Cat_List));

    if ( SaganBluedotCatList == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotCatList. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotCatList, 0, sizeof(_Sagan_Bluedot_Cat_List));

    /* Bluedot IP Queue */

    SaganBluedotIPQueue = malloc(sizeof(_Sagan_Bluedot_IP_Queue));

    if ( SaganBluedotIPQueue == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotIPQueue, 0, sizeof(_Sagan_Bluedot_IP_Queue));

    /* Bluedot Hash Queue */

    SaganBluedotHashQueue = malloc(sizeof(_Sagan_Bluedot_Hash_Queue));

    if ( SaganBluedotHashQueue == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
        }


    memset(SaganBluedotHashQueue, 0, sizeof(_Sagan_Bluedot_Hash_Queue));

    /* Bluedot Filename Queue */

    SaganBluedotFilenameQueue = malloc(sizeof(_Sagan_Bluedot_Filename_Queue));

    if ( SaganBluedotFilenameQueue == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
        }


    memset(SaganBluedotHashQueue, 0, sizeof(_Sagan_Bluedot_Hash_Queue));

    /* Bluedot URL Queue */

    SaganBluedotURLQueue = malloc(sizeof(_Sagan_Bluedot_URL_Queue));

    if ( SaganBluedotURLQueue == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
        }

    config->bluedot_last_time = atol(timet);

}


/****************************************************************************
 * Sagan_Bluedot_Clean_Queue - Clean's the "queue" of the type of lookup
 * that happened.  This is called after a successful lookup.  We do this to
 * prevent multiple lookups (at the same time!) of the same item!  This
 * happens a lot with IP address looks
 ****************************************************************************/

int Sagan_Bluedot_Clean_Queue ( char *data, unsigned char type )
{

    uint32_t ip_u32;
    int i=0;

    int tmp_bluedot_queue_count=0;


    /* Remove IP address from lookup queue */

    if ( type == BLUEDOT_LOOKUP_IP )
        {

            ip_u32  = IP2Bit(data);		/* Convert "data" to u32 int. */

            struct _Sagan_Bluedot_IP_Queue *TmpSaganBluedotIPQueue;
            TmpSaganBluedotIPQueue = malloc(sizeof(_Sagan_Bluedot_IP_Queue));

            if ( TmpSaganBluedotIPQueue  == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
                }

            memset(TmpSaganBluedotIPQueue, 0, sizeof(_Sagan_Bluedot_IP_Queue));

            for (i=0; i<bluedot_ip_queue; i++)
                {
                    if ( ip_u32 == SaganBluedotIPQueue[i].host )
                        {
                            TmpSaganBluedotIPQueue = (_Sagan_Bluedot_IP_Queue *) realloc(TmpSaganBluedotIPQueue, (tmp_bluedot_queue_count+1) * sizeof(_Sagan_Bluedot_IP_Queue));

                            if ( TmpSaganBluedotIPQueue == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
                                }

                            TmpSaganBluedotIPQueue[tmp_bluedot_queue_count].host = ip_u32;
                            tmp_bluedot_queue_count++;
                        }
                }


            pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);
            memset(SaganBluedotIPQueue, 0, sizeof(_Sagan_Bluedot_IP_Queue));

            bluedot_ip_queue=0;

            for (i=0; i<tmp_bluedot_queue_count; i++)
                {
                    SaganBluedotIPQueue = (_Sagan_Bluedot_IP_Queue *) realloc(SaganBluedotIPQueue, (bluedot_ip_queue+1) * sizeof(_Sagan_Bluedot_IP_Queue));

                    if ( SaganBluedotIPQueue == NULL )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
                        }

                    SaganBluedotIPQueue[bluedot_ip_queue].host = TmpSaganBluedotIPQueue[i].host;
                    bluedot_ip_queue++;
                }

            pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);
            free(TmpSaganBluedotIPQueue);

        }

    else if ( type == BLUEDOT_LOOKUP_HASH )
        {

            struct _Sagan_Bluedot_Hash_Queue *TmpSaganBluedotHashQueue;
            TmpSaganBluedotHashQueue = malloc(sizeof(_Sagan_Bluedot_Hash_Queue));

            if ( TmpSaganBluedotHashQueue  == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
                }

            memset(TmpSaganBluedotHashQueue, 0, sizeof(_Sagan_Bluedot_Hash_Queue));

            for (i=0; i<bluedot_hash_queue; i++)
                {
                    if (!strcmp(data, SaganBluedotHashQueue[i].hash))
                        {
                            TmpSaganBluedotHashQueue = (_Sagan_Bluedot_Hash_Queue *) realloc(TmpSaganBluedotHashQueue, (tmp_bluedot_queue_count+1) * sizeof(_Sagan_Bluedot_Hash_Queue));

                            if ( TmpSaganBluedotHashQueue == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotHashQueue[tmp_bluedot_queue_count].hash, data, sizeof(TmpSaganBluedotHashQueue[tmp_bluedot_queue_count].hash));
                            tmp_bluedot_queue_count++;
                        }
                }

            pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);
            memset(SaganBluedotHashQueue, 0, sizeof(_Sagan_Bluedot_Hash_Queue));

            bluedot_hash_queue=0;

            for (i=0; i<tmp_bluedot_queue_count; i++)
                {
                    SaganBluedotHashQueue = (_Sagan_Bluedot_Hash_Queue *) realloc(SaganBluedotHashQueue, (bluedot_hash_queue+1) * sizeof(_Sagan_Bluedot_Hash_Queue));

                    if ( SaganBluedotHashQueue == NULL )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
                        }

                    strlcpy(SaganBluedotHashQueue[bluedot_hash_queue].hash, TmpSaganBluedotHashQueue[i].hash, sizeof(SaganBluedotHashQueue[bluedot_hash_queue].hash));
                    bluedot_hash_queue++;
                }

            pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);
            free(TmpSaganBluedotHashQueue);


        }

    else if ( type == BLUEDOT_LOOKUP_URL )
        {

            struct _Sagan_Bluedot_URL_Queue *TmpSaganBluedotURLQueue;
            TmpSaganBluedotURLQueue = malloc(sizeof(_Sagan_Bluedot_URL_Queue));

            if ( TmpSaganBluedotURLQueue == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotURLQueue. Abort!", __FILE__, __LINE__);
                }

            memset(TmpSaganBluedotURLQueue, 0, sizeof(_Sagan_Bluedot_URL_Queue));

            for (i=0; i<bluedot_url_queue; i++)
                {
                    if (!strcmp(data, SaganBluedotURLQueue[i].url))
                        {
                            TmpSaganBluedotURLQueue = (_Sagan_Bluedot_URL_Queue *) realloc(TmpSaganBluedotURLQueue, (tmp_bluedot_queue_count+1) * sizeof(_Sagan_Bluedot_URL_Queue));

                            if ( TmpSaganBluedotURLQueue == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotURLQueue. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotURLQueue[tmp_bluedot_queue_count].url, data, sizeof(TmpSaganBluedotURLQueue[tmp_bluedot_queue_count].url));
                            tmp_bluedot_queue_count++;
                        }
                }

            pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);
            memset(SaganBluedotURLQueue, 0, sizeof(_Sagan_Bluedot_URL_Queue));

            bluedot_url_queue=0;

            for (i=0; i<tmp_bluedot_queue_count; i++)
                {
                    SaganBluedotURLQueue = (_Sagan_Bluedot_URL_Queue *) realloc(SaganBluedotURLQueue, (bluedot_url_queue+1) * sizeof(_Sagan_Bluedot_URL_Queue));

                    if ( SaganBluedotURLQueue == NULL )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotURLQueue. Abort!", __FILE__, __LINE__);
                        }

                    strlcpy(SaganBluedotURLQueue[bluedot_url_queue].url, TmpSaganBluedotURLQueue[i].url, sizeof(SaganBluedotURLQueue[bluedot_url_queue].url));
                    bluedot_url_queue++;
                }

            pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);
            free(TmpSaganBluedotURLQueue);


        }

    else if ( type == BLUEDOT_LOOKUP_FILENAME )
        {

            struct _Sagan_Bluedot_Filename_Queue *TmpSaganBluedotFilenameQueue;
            TmpSaganBluedotFilenameQueue = malloc(sizeof(_Sagan_Bluedot_Filename_Queue));

            if ( TmpSaganBluedotFilenameQueue == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
                }

            memset(TmpSaganBluedotFilenameQueue, 0, sizeof(_Sagan_Bluedot_Filename_Queue));

            for (i=0; i<bluedot_filename_queue; i++)
                {
                    if (!strcmp(data, SaganBluedotFilenameQueue[i].filename))
                        {
                            TmpSaganBluedotFilenameQueue = (_Sagan_Bluedot_Filename_Queue *) realloc(TmpSaganBluedotFilenameQueue, (tmp_bluedot_queue_count+1) * sizeof(_Sagan_Bluedot_Filename_Queue));

                            if ( TmpSaganBluedotFilenameQueue == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotFilenameQueue[tmp_bluedot_queue_count].filename, data, sizeof(TmpSaganBluedotFilenameQueue[tmp_bluedot_queue_count].filename));
                            tmp_bluedot_queue_count++;
                        }
                }

            pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);
            memset(SaganBluedotFilenameQueue, 0, sizeof(_Sagan_Bluedot_Filename_Queue));

            bluedot_filename_queue=0;

            for (i=0; i<tmp_bluedot_queue_count; i++)
                {
                    SaganBluedotFilenameQueue = (_Sagan_Bluedot_Filename_Queue *) realloc(SaganBluedotFilenameQueue, (bluedot_filename_queue+1) * sizeof(_Sagan_Bluedot_Filename_Queue));

                    if ( SaganBluedotFilenameQueue == NULL )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
                        }

                    strlcpy(SaganBluedotFilenameQueue[bluedot_filename_queue].filename, TmpSaganBluedotFilenameQueue[i].filename, sizeof(SaganBluedotFilenameQueue[bluedot_filename_queue].filename));
                    bluedot_filename_queue++;
                }

            pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);
            free(TmpSaganBluedotFilenameQueue);


        }

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
            Sagan_Log(S_ERROR, "[%s, line %d] No Bluedot categories list to load (%s)!", __FILE__, __LINE__, config->bluedot_cat);
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
                            Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotCatList. Abort!", __FILE__, __LINE__);
                        }

                    /* Normalize the list for later use.  Better to do this here than when processing rules */

                    bluedot_tok1 = Remove_Return(strtok_r(buf, "|", &saveptr));

                    if ( bluedot_tok1 == NULL )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Bluedot categories file appears to be malformed.", __FILE__, __LINE__);
                        }

                    Remove_Spaces(bluedot_tok1);
                    SaganBluedotCatList[counters->bluedot_cat_count].cat_number = atoi(bluedot_tok1);

                    bluedot_tok2 = Remove_Return(strtok_r(NULL, "|", &saveptr));


                    if ( bluedot_tok2 == NULL )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Bluedot categories file appears to be malformed.", __FILE__, __LINE__);
                        }

                    Remove_Return(bluedot_tok2);
                    Remove_Spaces(bluedot_tok2);
                    To_LowerC(bluedot_tok2);

                    strlcpy(SaganBluedotCatList[counters->bluedot_cat_count].cat, bluedot_tok2, sizeof(SaganBluedotCatList[counters->bluedot_cat_count].cat));
                    counters->bluedot_cat_count++;
                }
        }

}

/****************************************************************************
 * write_callback_func() - Callback for data received via libcurl
 ****************************************************************************/

size_t static write_callback_func(void *buffer, size_t size, size_t nmemb, void *userp)
{
    char **response_ptr =  (char**)userp;
    *response_ptr = strndup(buffer, (size_t)(size *nmemb));     /* Return the string */
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

    if (atol(timet) > config->bluedot_last_time + config->bluedot_timeout)
        {
            Sagan_Log(S_NORMAL, "Bluedot cache timeout reached %d minutes.  Cleaning up.", config->bluedot_timeout / 60);
            if ( bluedot_cache_clean_lock == 0 )
                {
                    Sagan_Bluedot_Clean_Cache();
                }
        }

    if ( counters->bluedot_ip_cache_count >= config->bluedot_max_cache )
        {
            Sagan_Log(S_NORMAL, "[%s, line %d] Out of cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

}

/****************************************************************************
 * Sagan_Bluedot_Clean_Cache - Cleans old Bluedot entries over the
 * specified "cache_timeout".
 ****************************************************************************/

void Sagan_Bluedot_Clean_Cache ( void )
{

    int i;
    int timeout_count=0;
    int deleted_count=0;

    char  timet[20] = { 0 };
    time_t t;
    struct tm *now=NULL;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    struct _Sagan_Bluedot_IP_Cache *TmpSaganBluedotIPCache = NULL;
    struct _Sagan_Bluedot_Hash_Cache *TmpSaganBluedotHashCache = NULL;
    struct _Sagan_Bluedot_URL_Cache *TmpSaganBluedotURLCache = NULL;
    struct _Sagan_Bluedot_Filename_Cache *TmpSaganBluedotFilenameCache = NULL;

    if ( bluedot_cache_clean_lock == 0 )	/* So no two threads try to "clean up" */
        {
            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
            bluedot_cache_clean_lock = 1;

            if (debug->debugbluedot)
                {
                    Sagan_Log(S_DEBUG, "[%s, line %d] Sagan/Bluedot cache clean time has been reached.", __FILE__, __LINE__);
                    Sagan_Log(S_DEBUG, "[%s, line %d] ----------------------------------------------------------------------", __FILE__, __LINE__);
                }

            config->bluedot_last_time = atol(timet);

            for (i=0; i<counters->bluedot_ip_cache_count; i++)
                {

                    if ( atol(timet) - SaganBluedotIPCache[i].utime > config->bluedot_timeout )
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] == Deleting IP address from cache -> %u",  __FILE__, __LINE__, SaganBluedotIPCache[i].host);
                                }

                        }
                    else
                        {

                            TmpSaganBluedotIPCache = (_Sagan_Bluedot_IP_Cache *) realloc(TmpSaganBluedotIPCache, (timeout_count+1) * sizeof(_Sagan_Bluedot_IP_Cache));

                            if ( TmpSaganBluedotIPCache == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotIPCache. Abort!", __FILE__, __LINE__);
                                }

                            TmpSaganBluedotIPCache[timeout_count].host = SaganBluedotIPCache[i].host;
                            TmpSaganBluedotIPCache[timeout_count].utime = SaganBluedotIPCache[i].utime;                                                                                 /* store utime */
                            TmpSaganBluedotIPCache[timeout_count].alertid = SaganBluedotIPCache[i].alertid;
                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {
                    SaganBluedotIPCache[i].host = TmpSaganBluedotIPCache[i].host;
                    SaganBluedotIPCache[i].utime = TmpSaganBluedotIPCache[i].utime;
                    SaganBluedotIPCache[i].alertid = TmpSaganBluedotIPCache[i].alertid;
                }

            deleted_count = counters->bluedot_ip_cache_count - (uintmax_t)timeout_count;
            counters->bluedot_ip_cache_count = (uintmax_t)timeout_count;

            Sagan_Log(S_NORMAL, "[%s, line %d] Deleted %d IP addresses from Bluedot cache.",__FILE__, __LINE__, deleted_count);

            /* Clean hash cache */

            timeout_count = 0;

            for (i=0; i<counters->bluedot_hash_cache_count; i++)
                {

                    if ( atol(timet) - SaganBluedotHashCache[i].utime > config->bluedot_timeout )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] == Deleting hash from cache -> %s",  __FILE__, __LINE__, SaganBluedotHashCache[i].hash);
                                }
                        }
                    else
                        {

                            TmpSaganBluedotHashCache = (_Sagan_Bluedot_Hash_Cache *) realloc(TmpSaganBluedotHashCache, (timeout_count+1) * sizeof(_Sagan_Bluedot_Hash_Cache));

                            if ( TmpSaganBluedotHashCache == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotHashCache. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotHashCache[timeout_count].hash, SaganBluedotHashCache[i].hash, sizeof(TmpSaganBluedotHashCache[timeout_count].hash));
                            TmpSaganBluedotHashCache[timeout_count].utime = SaganBluedotHashCache[i].utime;                                                                                 /* store utime */
                            TmpSaganBluedotHashCache[timeout_count].alertid = SaganBluedotHashCache[i].alertid;
                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {

                    strlcpy(SaganBluedotHashCache[i].hash, TmpSaganBluedotHashCache[i].hash, sizeof(SaganBluedotHashCache[i].hash));
                    SaganBluedotHashCache[i].utime = TmpSaganBluedotHashCache[i].utime;
                    SaganBluedotHashCache[i].alertid = TmpSaganBluedotHashCache[i].alertid;
                }

            deleted_count = counters->bluedot_hash_cache_count - (uintmax_t)timeout_count;
            counters->bluedot_hash_cache_count = (uintmax_t)timeout_count;

            Sagan_Log(S_NORMAL, "[%s, line %d] Deleted %d hashes from Bluedot cache.",__FILE__, __LINE__, deleted_count);

            /* Clean URL cache */

            timeout_count = 0;

            for (i=0; i<counters->bluedot_url_cache_count; i++)
                {

                    if ( atol(timet) - SaganBluedotURLCache[i].utime > config->bluedot_timeout )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] == Deleting URL from cache -> %s",  __FILE__, __LINE__, SaganBluedotURLCache[i].url);
                                }
                        }
                    else
                        {

                            TmpSaganBluedotURLCache = (_Sagan_Bluedot_URL_Cache *) realloc(TmpSaganBluedotURLCache, (timeout_count+1) * sizeof(_Sagan_Bluedot_URL_Cache));

                            if ( TmpSaganBluedotURLCache == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotURLCache. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotURLCache[timeout_count].url, SaganBluedotURLCache[i].url, sizeof(TmpSaganBluedotURLCache[timeout_count].url));
                            TmpSaganBluedotURLCache[timeout_count].utime = SaganBluedotURLCache[i].utime;
                            TmpSaganBluedotURLCache[timeout_count].alertid = SaganBluedotURLCache[i].alertid;
                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {
                    strlcpy(SaganBluedotURLCache[i].url, TmpSaganBluedotURLCache[i].url, sizeof(SaganBluedotURLCache[i].url));
                    SaganBluedotURLCache[i].utime = TmpSaganBluedotURLCache[i].utime;
                    SaganBluedotURLCache[i].alertid = TmpSaganBluedotURLCache[i].alertid;
                }

            deleted_count = counters->bluedot_url_cache_count - (uintmax_t)timeout_count;
            counters->bluedot_url_cache_count = (uintmax_t)timeout_count;

            Sagan_Log(S_NORMAL, "[%s, line %d] Deleted %d URLs from Bluedot cache.",__FILE__, __LINE__, deleted_count);

            /* Clean Filename cache */

            timeout_count = 0;

            for (i=0; i<counters->bluedot_filename_cache_count; i++)
                {
                    if ( atol(timet) - SaganBluedotFilenameCache[i].utime > config->bluedot_timeout )
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] == Deleting Filename from cache -> %s",  __FILE__, __LINE__, SaganBluedotFilenameCache[i].filename);
                                }
                        }
                    else
                        {

                            TmpSaganBluedotFilenameCache = (_Sagan_Bluedot_Filename_Cache *) realloc(TmpSaganBluedotFilenameCache, (timeout_count+1) * sizeof(_Sagan_Bluedot_Filename_Cache));

                            if ( TmpSaganBluedotFilenameCache == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotFilenameCache. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotFilenameCache[timeout_count].filename, SaganBluedotFilenameCache[i].filename, sizeof(TmpSaganBluedotFilenameCache[timeout_count].filename));
                            TmpSaganBluedotFilenameCache[timeout_count].utime = SaganBluedotFilenameCache[i].utime;
                            TmpSaganBluedotFilenameCache[timeout_count].alertid = SaganBluedotFilenameCache[i].alertid;
                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {
                    strlcpy(SaganBluedotFilenameCache[i].filename, TmpSaganBluedotFilenameCache[i].filename, sizeof(SaganBluedotFilenameCache[i].filename));
                    SaganBluedotFilenameCache[i].utime = TmpSaganBluedotFilenameCache[i].utime;
                    SaganBluedotFilenameCache[i].alertid = TmpSaganBluedotFilenameCache[i].alertid;
                }

            deleted_count = counters->bluedot_filename_cache_count - (uintmax_t)timeout_count;
            counters->bluedot_filename_cache_count = (uintmax_t)timeout_count;

            Sagan_Log(S_NORMAL, "[%s, line %d] Deleted %d filenames from Bluedot cache.",__FILE__, __LINE__, deleted_count);

            bluedot_cache_clean_lock = 0;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);
        }

    free(TmpSaganBluedotIPCache);
    free(TmpSaganBluedotHashCache);
    free(TmpSaganBluedotURLCache);
    free(TmpSaganBluedotFilenameCache);

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
 */

unsigned char Sagan_Bluedot_Lookup(char *data,  unsigned char type)
{

    char tmpurl[1024] = { 0 };
    char tmpdeviceid[64] = { 0 };

    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char *response=NULL;

    struct json_object *json_in = NULL;
    json_object *string_obj;

    const char *cat=NULL;
    char cattmp[128] = { 0 };
    char *saveptr=NULL;
    signed char bluedot_alertid = 0;		/* -128 to 127 */
    int i;

    char  timet[20] = { 0 };
    time_t t;
    struct tm *now=NULL;

    uintmax_t ip = 0;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    /************************************************************************/
    /* Lookup types                                                         */
    /************************************************************************/

    /* IP Address Lookup */

    if ( type == BLUEDOT_LOOKUP_IP )
        {

            ip = IP2Bit(data);

            if ( is_rfc1918(ip) )
                {

                    if ( debug->debugbluedot )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, data);
                        }

                    return(false);
                }

            for (i=0; i<counters->bluedot_ip_cache_count; i++)
                {

                    if ( ip == SaganBluedotIPCache[i].host)
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] Pulled %s (%u) from Bluedot cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotIPCache[i].host, SaganBluedotIPCache[i].alertid);
                                }

                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_ip_cache_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                            return(SaganBluedotIPCache[i].alertid);

                        }
                }

            /* Check Bluedot IP Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < bluedot_ip_queue; i++)
                {
                    if ( ip == SaganBluedotIPQueue[i].host )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] %s (%u) is already being looked up. Skipping....", __FILE__, __LINE__, data, SaganBluedotIPQueue[i].host);
                                }

                            return(false);
                        }
                }

            /* If not in Bluedot IP queue,  add it */

            pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);
            SaganBluedotIPQueue = (_Sagan_Bluedot_IP_Queue *) realloc(SaganBluedotIPQueue, (bluedot_ip_queue+1) * sizeof(_Sagan_Bluedot_IP_Queue));

            if ( SaganBluedotIPQueue == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
                }

            SaganBluedotIPQueue[bluedot_ip_queue].host = ip;
            bluedot_ip_queue++;
            pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);

            if (debug->debugbluedot)
                {
                    Sagan_Log(S_DEBUG, "[%s, line %d] Going to query IP %s (%u) from Bluedot.", __FILE__, __LINE__, data, ip);
                }


            snprintf(tmpurl, sizeof(tmpurl), "%s%s%s", config->bluedot_url, BLUEDOT_IP_LOOKUP_URL, data);

        }  /* BLUEDOT_LOOKUP_IP */


    if ( type == BLUEDOT_LOOKUP_HASH )
        {

            for (i=0; i<counters->bluedot_hash_cache_count; i++)
                {

                    if (!strcmp(data, SaganBluedotHashCache[i].hash))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] Pulled file hash '%s' from Bluedot hash cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotHashCache[i].alertid);
                                }

                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_hash_cache_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                            return(SaganBluedotHashCache[i].alertid);

                        }


                }

            snprintf(tmpurl, sizeof(tmpurl), "%s%s%s", config->bluedot_url, BLUEDOT_HASH_LOOKUP_URL, data);
        }

    if ( type == BLUEDOT_LOOKUP_URL )
        {

            for (i=0; i<counters->bluedot_url_cache_count; i++)
                {

                    if (!strcmp(data, SaganBluedotURLCache[i].url))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] Pulled file URL '%s' from Bluedot URL cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotURLCache[i].alertid);
                                }
                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_url_cache_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                            return(SaganBluedotURLCache[i].alertid);

                        }

                }

            snprintf(tmpurl, sizeof(tmpurl), "%s%s%s", config->bluedot_url, BLUEDOT_URL_LOOKUP_URL, data);

        }

    if ( type == BLUEDOT_LOOKUP_FILENAME )
        {

            for (i=0; i<counters->bluedot_filename_cache_count; i++)
                {
                    if (!strcmp(data, SaganBluedotFilenameCache[i].filename))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] Pulled file filename '%s' from Bluedot filename cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotFilenameCache[i].alertid);
                                }

                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_filename_cache_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                            return(SaganBluedotFilenameCache[i].alertid);

                        }
                }

            snprintf(tmpurl, sizeof(tmpurl), "%s%s%s", config->bluedot_url, BLUEDOT_FILENAME_LOOKUP_URL, data);

        }


    snprintf(tmpdeviceid, sizeof(tmpdeviceid), "X-BLUEDOT-DEVICEID: %s", config->bluedot_device_id);

    curl = curl_easy_init();

    if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, tmpurl);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);   /* WIll send SIGALRM if not set */
            headers = curl_slist_append (headers, BLUEDOT_PROCESSOR_USER_AGENT);
            headers = curl_slist_append (headers, tmpdeviceid);
//	    headers = curl_slist_append (headers, "X-Bluedot-Verbose: 1");		/* For more verbose output */
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER , headers );
            res = curl_easy_perform(curl);
        }

    curl_easy_cleanup(curl);

    if ( response == NULL )
        {
            Sagan_Log(S_WARN, "[%s, line %d] Bluedot returned a empty \"response\".", __FILE__, __LINE__);

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
            counters->bluedot_error_count++;
            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

            Sagan_Bluedot_Clean_Queue(data, type);

            return(false);
        }

    json_in = json_tokener_parse(response);

    if ( type == BLUEDOT_LOOKUP_IP )
        {
            json_object_object_get_ex(json_in, "qipcode", &string_obj);
            cat = json_object_get_string(string_obj);
        }

    else if ( type == BLUEDOT_LOOKUP_HASH )
        {
            json_object_object_get_ex(json_in, "qhashcode", &string_obj);
            cat = json_object_get_string(string_obj);
        }

    else if ( type == BLUEDOT_LOOKUP_URL )
        {
            json_object_object_get_ex(json_in, "qurlcode", &string_obj);
            cat = json_object_get_string(string_obj);
        }

    else if ( type == BLUEDOT_LOOKUP_FILENAME )
        {
            json_object_object_get_ex(json_in, "qfilenamecode", &string_obj);
            cat = json_object_get_string(string_obj);
        }


    if ( cat == NULL )
        {
            Sagan_Log(S_WARN, "Bluedot return a bad category.");

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
            counters->bluedot_error_count++;						// DEBUG <- Total error count
            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

            Sagan_Bluedot_Clean_Queue(data, type);

            return(false);
        }

    /* strtok_r() doesn't like const char *cat */

    snprintf(cattmp, sizeof(cattmp), "%s", cat);
    strtok_r(cattmp, "\"", &saveptr);

    bluedot_alertid  = atoi(strtok_r(NULL, "\"", &saveptr));

    if ( debug->debugbluedot)
        {
            Sagan_Log(S_DEBUG, "[%s, line %d] Bluedot return category \"%d\" for %s.", __FILE__, __LINE__, bluedot_alertid, data);
        }

    if ( bluedot_alertid == -1 )
        {
            Sagan_Log(S_WARN, "Bluedot reports an invalid API key.  Lookup aborted!");
            counters->bluedot_error_count++;
            return(false);
        }


    /************************************************************************/
    /* Add entries to cache                                                 */
    /************************************************************************/

    /* IP Address lookup */

    if ( type == BLUEDOT_LOOKUP_IP )
        {

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);

            counters->bluedot_ip_total++;

            SaganBluedotIPCache = (_Sagan_Bluedot_IP_Cache *) realloc(SaganBluedotIPCache, (counters->bluedot_ip_cache_count+1) * sizeof(_Sagan_Bluedot_IP_Cache));

            if ( SaganBluedotIPCache == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotIPCache. Abort!", __FILE__, __LINE__);
                }

            SaganBluedotIPCache[counters->bluedot_ip_cache_count].host = ip;
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].utime = atol(timet);                                                                                     /* store utime */
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].alertid = bluedot_alertid;
            counters->bluedot_ip_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

        }


    /* File hash lookup */

    else if ( type == BLUEDOT_LOOKUP_HASH )
        {

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);

            counters->bluedot_hash_total++;

            SaganBluedotHashCache = (_Sagan_Bluedot_Hash_Cache *) realloc(SaganBluedotHashCache, (counters->bluedot_hash_cache_count+1) * sizeof(_Sagan_Bluedot_Hash_Cache));

            if ( SaganBluedotHashCache == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotHashCache. Abort!", __FILE__, __LINE__);
                }

            strlcpy(SaganBluedotHashCache[counters->bluedot_hash_cache_count].hash, data, sizeof(SaganBluedotHashCache[counters->bluedot_hash_cache_count].hash));
            SaganBluedotHashCache[counters->bluedot_hash_cache_count].utime = atol(timet);                                                                                     /* store utime */
            SaganBluedotHashCache[counters->bluedot_hash_cache_count].alertid = bluedot_alertid;
            counters->bluedot_hash_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

        }

    /* URL lookup */

    else if ( type == BLUEDOT_LOOKUP_URL )
        {
            pthread_mutex_lock(&SaganProcBluedotWorkMutex);

            counters->bluedot_url_total++;

            SaganBluedotURLCache = (_Sagan_Bluedot_URL_Cache *) realloc(SaganBluedotURLCache, (counters->bluedot_url_cache_count+1) * sizeof(_Sagan_Bluedot_URL_Cache));

            if ( SaganBluedotURLCache == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotURLCache. Abort!", __FILE__, __LINE__);
                }

            strlcpy(SaganBluedotURLCache[counters->bluedot_url_cache_count].url, data, sizeof(SaganBluedotURLCache[counters->bluedot_url_cache_count].url));
            SaganBluedotURLCache[counters->bluedot_url_cache_count].utime = atol(timet);                                                                                     /* store utime */
            SaganBluedotURLCache[counters->bluedot_url_cache_count].alertid = bluedot_alertid;
            counters->bluedot_url_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

        }

    /* Filename Lookup */

    else if ( type == BLUEDOT_LOOKUP_FILENAME )
        {
            pthread_mutex_lock(&SaganProcBluedotWorkMutex);

            counters->bluedot_filename_total++;

            SaganBluedotFilenameCache = (_Sagan_Bluedot_Filename_Cache *) realloc(SaganBluedotFilenameCache, (counters->bluedot_filename_cache_count+1) * sizeof(_Sagan_Bluedot_Filename_Cache));

            if ( SaganBluedotFilenameCache == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotFilenameCache. Abort!", __FILE__, __LINE__);
                }


            strlcpy(SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].filename, data, sizeof(SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].filename));
            SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].utime = atol(timet);
            SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].alertid = bluedot_alertid;
            counters->bluedot_filename_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);
        }


    Sagan_Bluedot_Clean_Queue(data, type);	/* Remove item for "queue" */

    json_object_put(json_in);       /* Clear json_in as we're done with it */

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

                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_ip_positive_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

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
                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_hash_positive_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

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
                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_url_positive_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

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
                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_filename_positive_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

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

int Sagan_Bluedot_IP_Lookup_All ( char *syslog_message, int rule_position )
{

    int i;
    char results[64];

    unsigned char bluedot_results;
    sbool bluedot_flag;

    for ( i = 1; i < MAX_PARSE_IP; i++ )
        {


            strlcpy(results, Sagan_Parse_IP(syslog_message, i), sizeof(results));

            /* Failed to find next IP,  short circuit the process */

            if ( results[0] == '0' )
                {
                    return(false);
                }

            bluedot_results = Sagan_Bluedot_Lookup(results, BLUEDOT_LOOKUP_IP);
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

    sbool found;

    tmptoken = strtok_r(categories, "," , &saveptrrule);

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
                                            Sagan_Log(S_WARN, "[%s, line %d] To many Bluedot IP catagories detected in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
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
                                            Sagan_Log(S_WARN, "[%s, line %d] To many Bluedot hash catagories detected in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
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
                                            Sagan_Log(S_WARN, "[%s, line %d] To many Bluedot URL catagories detected in %s at line %d", __FILE__, __LINE__, ruleset, linecount);
                                        }
                                }


                        }
                }

            if ( found == 0 )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Unknown Bluedot category '%s' found in %s at line %d. Abort!", __FILE__, __LINE__, tmp2, ruleset, linecount);
                }

            tmptoken = strtok_r(NULL, "," , &saveptrrule);

        }


}


#endif
