/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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

// New IP queue
// Looks like cleanup might still be reallocing?

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
#include "rules.h"

#include "processors/bluedot.h"

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
pthread_mutex_t CounterBluedotGenericMutex=PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t SaganProcBluedotIPWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotHashWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotURLWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t SaganProcBluedotFilenameWorkMutex=PTHREAD_MUTEX_INITIALIZER;

sbool bluedot_cache_clean_lock=0;
sbool bluedot_dns_global=0;

sbool bluedot_ip_update = 0;
sbool bluedot_hash_update = 0;
sbool bluedot_url_update = 0;
sbool bluedot_filename_update = 0;

//int bluedot_ip_queue=0;
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

    config->bluedot_last_time = atol(timet);

    /* Bluedot IP Cache */

    SaganBluedotIPCache = malloc(config->bluedot_ip_max_cache * sizeof(struct _Sagan_Bluedot_IP_Cache));

    if ( SaganBluedotIPCache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotIPCache. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotIPCache, 0, sizeof(_Sagan_Bluedot_IP_Cache));

    /* Bluedot Hash Cache */

    SaganBluedotHashCache = malloc(config->bluedot_hash_max_cache * sizeof(struct _Sagan_Bluedot_Hash_Cache));

    if ( SaganBluedotHashCache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotHashCache. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotHashCache, 0, sizeof(_Sagan_Bluedot_Hash_Cache));

    /* Bluedot URL Cache */

    SaganBluedotURLCache = malloc(config->bluedot_url_max_cache * sizeof(struct _Sagan_Bluedot_URL_Cache));

    if ( SaganBluedotURLCache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotURLCache. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotURLCache, 0, sizeof(_Sagan_Bluedot_URL_Cache));

    /* Bluedot Filename Cache */

    SaganBluedotFilenameCache = malloc(config->bluedot_filename_max_cache * sizeof(struct _Sagan_Bluedot_Filename_Cache));

    if ( SaganBluedotFilenameCache == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotFilenameCache. Abort!", __FILE__, __LINE__);
        }

    memset(SaganBluedotFilenameCache, 0, sizeof(_Sagan_Bluedot_Filename_Cache));

    /* Bluedot IP Queue */
     
    SaganBluedotIPQueue = malloc(config->bluedot_ip_queue * sizeof(struct _Sagan_Bluedot_IP_Queue));
    
    if ( SaganBluedotIPQueue == NULL )
        {    
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
        }
    
    memset(SaganBluedotIPQueue, 0, sizeof(_Sagan_Bluedot_IP_Queue));

}


/****************************************************************************
 * Sagan_Bluedot_Clean_Queue - Clean's the "queue" of the type of lookup
 * that happened.  This is called after a successful lookup.  We do this to
 * prevent multiple lookups (at the same time!) of the same item!  This
 * happens a lot with IP address looks
 ****************************************************************************/

int Sagan_Bluedot_Clean_Queue ( char *data, unsigned char type, unsigned char *ip )
{

    uint32_t ip_u32;
    int i=0;

    unsigned char ip_convert[MAXIPBIT] = { 0 };
    memset(ip_convert, 0, MAXIPBIT);
    memcpy(ip_convert, ip, MAXIPBIT);

    char str[INET_ADDRSTRLEN];

    int tmp_bluedot_queue_count=0;

    /* Remove IP address from lookup queue */

    if ( type == BLUEDOT_LOOKUP_IP )
        {

	    sbool flag = 0; 

            for (i=0; i<config->bluedot_ip_queue; i++)
                {

                 if ( !memcmp(ip_convert, SaganBluedotIPQueue[i].ip, MAXIPBIT) )
                        { 

			flag = 1;

			//inet_ntop(AF_INET, ip_convert, str, INET_ADDRSTRLEN);
			//printf("Removeing : %s\n", str);

			pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);

			memset(SaganBluedotIPQueue[i].ip, 0, MAXIPBIT); 

			//counters->bluedot_ip_queue_current--;

			pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);

			}

		}

		pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);
		counters->bluedot_ip_queue_current--;
		pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);
/*
		if ( flag == 0 ) 
			{
			inet_ntop(AF_INET, ip_convert, str, INET_ADDRSTRLEN);
			printf("Missed: %s\n", str);

			}
*/


/*
            struct _Sagan_Bluedot_IP_Queue *TmpSaganBluedotIPQueue;
            TmpSaganBluedotIPQueue = malloc(sizeof(_Sagan_Bluedot_IP_Queue));

            if ( TmpSaganBluedotIPQueue  == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
                }

            for (i=0; i<bluedot_ip_queue; i++)
                {
                    if ( !memcmp(ip_convert, SaganBluedotIPQueue[i].ip, MAXIPBIT) )
                        {
                            TmpSaganBluedotIPQueue = (_Sagan_Bluedot_IP_Queue *) realloc(TmpSaganBluedotIPQueue, (tmp_bluedot_queue_count+1) * sizeof(_Sagan_Bluedot_IP_Queue));

                            if ( TmpSaganBluedotIPQueue == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
                                }

                            memcpy(TmpSaganBluedotIPQueue[tmp_bluedot_queue_count].ip, ip_convert, MAXIPBIT);
                            tmp_bluedot_queue_count++;
                        }
                }


            pthread_mutex_lock(&SaganProcBluedotIPWorkMutex);

            bluedot_ip_update = 1;

            memset(SaganBluedotIPQueue, 0, sizeof(_Sagan_Bluedot_IP_Queue));

            bluedot_ip_queue=0;

            for (i=0; i<tmp_bluedot_queue_count; i++)
                {
                    SaganBluedotIPQueue = (_Sagan_Bluedot_IP_Queue *) realloc(SaganBluedotIPQueue, (bluedot_ip_queue+1) * sizeof(_Sagan_Bluedot_IP_Queue));

                    if ( SaganBluedotIPQueue == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotIPQueue. Abort!", __FILE__, __LINE__);
                        }

                    memset(SaganBluedotIPQueue[bluedot_ip_queue].ip, 0, MAXIPBIT);
                    memcpy(SaganBluedotIPQueue[bluedot_ip_queue].ip, TmpSaganBluedotIPQueue[i].ip, MAXIPBIT);
                    bluedot_ip_queue++;
                }

            bluedot_ip_update = 0;
            pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);
            free(TmpSaganBluedotIPQueue);
*/

        }

    else if ( type == BLUEDOT_LOOKUP_HASH )
        {

            struct _Sagan_Bluedot_Hash_Queue *TmpSaganBluedotHashQueue;
            TmpSaganBluedotHashQueue = malloc(sizeof(_Sagan_Bluedot_Hash_Queue));

            if ( TmpSaganBluedotHashQueue  == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
                }

            for (i=0; i<bluedot_hash_queue; i++)
                {
                    if (!strcmp(data, SaganBluedotHashQueue[i].hash))
                        {
                            TmpSaganBluedotHashQueue = (_Sagan_Bluedot_Hash_Queue *) realloc(TmpSaganBluedotHashQueue, (tmp_bluedot_queue_count+1) * sizeof(_Sagan_Bluedot_Hash_Queue));

                            if ( TmpSaganBluedotHashQueue == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotHashQueue[tmp_bluedot_queue_count].hash, data, sizeof(TmpSaganBluedotHashQueue[tmp_bluedot_queue_count].hash));
                            tmp_bluedot_queue_count++;
                        }
                }

            pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);

            bluedot_hash_update = 1;

            memset(SaganBluedotHashQueue, 0, sizeof(_Sagan_Bluedot_Hash_Queue));

            bluedot_hash_queue=0;

            for (i=0; i<tmp_bluedot_queue_count; i++)
                {
                    SaganBluedotHashQueue = (_Sagan_Bluedot_Hash_Queue *) realloc(SaganBluedotHashQueue, (bluedot_hash_queue+1) * sizeof(_Sagan_Bluedot_Hash_Queue));

                    if ( SaganBluedotHashQueue == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
                        }

                    strlcpy(SaganBluedotHashQueue[bluedot_hash_queue].hash, TmpSaganBluedotHashQueue[i].hash, sizeof(SaganBluedotHashQueue[bluedot_hash_queue].hash));

                    bluedot_hash_queue++;

                    if (debug->debugbluedot)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Going to query hash %s from Bluedot.", __FILE__, __LINE__, data);
                        }


                }

            bluedot_hash_update = 0;

            pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);
            free(TmpSaganBluedotHashQueue);


        }

    else if ( type == BLUEDOT_LOOKUP_URL )
        {

            struct _Sagan_Bluedot_URL_Queue *TmpSaganBluedotURLQueue;
            TmpSaganBluedotURLQueue = malloc(sizeof(_Sagan_Bluedot_URL_Queue));

            if ( TmpSaganBluedotURLQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotURLQueue. Abort!", __FILE__, __LINE__);
                }

            for (i=0; i<bluedot_url_queue; i++)
                {
                    if (!strcmp(data, SaganBluedotURLQueue[i].url))
                        {
                            TmpSaganBluedotURLQueue = (_Sagan_Bluedot_URL_Queue *) realloc(TmpSaganBluedotURLQueue, (tmp_bluedot_queue_count+1) * sizeof(_Sagan_Bluedot_URL_Queue));

                            if ( TmpSaganBluedotURLQueue == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotURLQueue. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotURLQueue[tmp_bluedot_queue_count].url, data, sizeof(TmpSaganBluedotURLQueue[tmp_bluedot_queue_count].url));
                            tmp_bluedot_queue_count++;
                        }
                }

            pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);

            bluedot_url_update = 1;

            memset(SaganBluedotURLQueue, 0, sizeof(_Sagan_Bluedot_URL_Queue));

            bluedot_url_queue=0;

            for (i=0; i<tmp_bluedot_queue_count; i++)
                {
                    SaganBluedotURLQueue = (_Sagan_Bluedot_URL_Queue *) realloc(SaganBluedotURLQueue, (bluedot_url_queue+1) * sizeof(_Sagan_Bluedot_URL_Queue));

                    if ( SaganBluedotURLQueue == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotURLQueue. Abort!", __FILE__, __LINE__);
                        }

                    strlcpy(SaganBluedotURLQueue[bluedot_url_queue].url, TmpSaganBluedotURLQueue[i].url, sizeof(SaganBluedotURLQueue[bluedot_url_queue].url));
                    bluedot_url_queue++;
                }

            bluedot_url_update = 0;

            pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);
            free(TmpSaganBluedotURLQueue);


        }

    else if ( type == BLUEDOT_LOOKUP_FILENAME )
        {

            struct _Sagan_Bluedot_Filename_Queue *TmpSaganBluedotFilenameQueue;
            TmpSaganBluedotFilenameQueue = malloc(sizeof(_Sagan_Bluedot_Filename_Queue));

            if ( TmpSaganBluedotFilenameQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
                }

            for (i=0; i<bluedot_filename_queue; i++)
                {
                    if (!strcmp(data, SaganBluedotFilenameQueue[i].filename))
                        {
                            TmpSaganBluedotFilenameQueue = (_Sagan_Bluedot_Filename_Queue *) realloc(TmpSaganBluedotFilenameQueue, (tmp_bluedot_queue_count+1) * sizeof(_Sagan_Bluedot_Filename_Queue));

                            if ( TmpSaganBluedotFilenameQueue == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for TmpSaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
                                }

                            strlcpy(TmpSaganBluedotFilenameQueue[tmp_bluedot_queue_count].filename, data, sizeof(TmpSaganBluedotFilenameQueue[tmp_bluedot_queue_count].filename));
                            tmp_bluedot_queue_count++;
                        }
                }

            pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);

            bluedot_filename_update = 1;

            memset(SaganBluedotFilenameQueue, 0, sizeof(_Sagan_Bluedot_Filename_Queue));

            bluedot_filename_queue=0;

            for (i=0; i<tmp_bluedot_queue_count; i++)
                {
                    SaganBluedotFilenameQueue = (_Sagan_Bluedot_Filename_Queue *) realloc(SaganBluedotFilenameQueue, (bluedot_filename_queue+1) * sizeof(_Sagan_Bluedot_Filename_Queue));

                    if ( SaganBluedotFilenameQueue == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
                        }

                    strlcpy(SaganBluedotFilenameQueue[bluedot_filename_queue].filename, TmpSaganBluedotFilenameQueue[i].filename, sizeof(SaganBluedotFilenameQueue[bluedot_filename_queue].filename));
                    bluedot_filename_queue++;
                }

            bluedot_filename_update = 0;

            pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);
            free(TmpSaganBluedotFilenameQueue);


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

                    pthread_mutex_lock(&CounterBluedotGenericMutex);
                    counters->bluedot_cat_count++;
                    pthread_mutex_unlock(&CounterBluedotGenericMutex);
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
            Sagan_Log(NORMAL, "Bluedot cache timeout reached %d minutes.  Cleaning up.", config->bluedot_timeout / 60);
            if ( bluedot_cache_clean_lock == 0 )
                {
                    Sagan_Bluedot_Clean_Cache();
                }
        }

    if ( counters->bluedot_ip_cache_count >= config->bluedot_ip_max_cache )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of IP cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

    if ( counters->bluedot_hash_cache_count >= config->bluedot_hash_max_cache )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of hash cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

    if ( counters->bluedot_url_cache_count >= config->bluedot_url_max_cache )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of URL cache space! Considering increasing cache size!", __FILE__, __LINE__);
        }

    if ( counters->bluedot_filename_cache_count >= config->bluedot_filename_max_cache )
        {
            Sagan_Log(NORMAL, "[%s, line %d] Out of URL cache space! Considering increasing cache size!", __FILE__, __LINE__);
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
    uint64_t timeint;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);
    timeint = atol(timet);

    struct _Sagan_Bluedot_IP_Cache *TmpSaganBluedotIPCache = NULL;
    struct _Sagan_Bluedot_Hash_Cache *TmpSaganBluedotHashCache = NULL;
    struct _Sagan_Bluedot_URL_Cache *TmpSaganBluedotURLCache = NULL;
    struct _Sagan_Bluedot_Filename_Cache *TmpSaganBluedotFilenameCache = NULL;

    if ( bluedot_cache_clean_lock == 0 )        /* So no two threads try to "clean up" */
        {

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);

            bluedot_cache_clean_lock = 1;

            /* Tmp IP cache */

//            TmpSaganBluedotIPCache = malloc(config->bluedot_ip_max_cache * sizeof(struct _Sagan_Bluedot_IP_Cache));

//            if ( TmpSaganBluedotIPCache == NULL )
//                {
//                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotIPCache. Abort!", __FILE__, __LINE__);
//                }

//            memset(TmpSaganBluedotIPCache, 0, sizeof(_Sagan_Bluedot_IP_Cache));

            /* Tmp Hash cache */

            TmpSaganBluedotHashCache = malloc(config->bluedot_hash_max_cache * sizeof(struct _Sagan_Bluedot_Hash_Cache));

            if ( TmpSaganBluedotHashCache == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotHashCache. Abort!", __FILE__, __LINE__);
                }

            memset(TmpSaganBluedotHashCache, 0, sizeof(_Sagan_Bluedot_Hash_Cache));

            /* Tmp URL cache */

            TmpSaganBluedotURLCache = malloc(config->bluedot_url_max_cache * sizeof(struct _Sagan_Bluedot_URL_Cache));

            if ( TmpSaganBluedotURLCache == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotURLCache. Abort!", __FILE__, __LINE__);
                }

            memset(TmpSaganBluedotURLCache, 0, sizeof(_Sagan_Bluedot_URL_Cache));

            /* Tmp Filename cache */

            TmpSaganBluedotFilenameCache = malloc(config->bluedot_filename_max_cache * sizeof(struct _Sagan_Bluedot_Filename_Cache));

            if ( TmpSaganBluedotFilenameCache == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for TmpSaganBluedotFilenameCache. Abort!", __FILE__, __LINE__);
                }

            memset(TmpSaganBluedotFilenameCache, 0, sizeof(_Sagan_Bluedot_Filename_Cache));


            if (debug->debugbluedot)
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Sagan/Bluedot cache clean time has been reached.", __FILE__, __LINE__);
                    Sagan_Log(DEBUG, "[%s, line %d] ----------------------------------------------------------------------", __FILE__, __LINE__);
                }

            config->bluedot_last_time = timeint;

	    deleted_count = 0; 
	    uint64_t new_bluedot_ip_max_cache = 0; 

 	    for (i=0; i < config->bluedot_ip_max_cache; i++ ) 
		{

		if ( ( timeint - SaganBluedotIPCache[i].cache_utime ) > config->bluedot_timeout )
			{

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] == Deleting IP address from cache -> %u",  __FILE__, __LINE__, SaganBluedotIPCache[i].ip); 
                                }

                        memset(SaganBluedotIPCache[i].ip, 0, MAXIPBIT);
                        SaganBluedotIPCache[i].mdate_utime = 0;
                        SaganBluedotIPCache[i].cdate_utime = 0;
                        SaganBluedotIPCache[i].cache_utime = 0;
                        SaganBluedotIPCache[i].alertid = 0;
                        
                        deleted_count++;
	
			} else {

			new_bluedot_ip_max_cache++; 
		
			}
		}
			
/*
            for (i=0; i<counters->bluedot_ip_cache_count; i++)
                {

                    if ( timeint - SaganBluedotIPCache[i].cache_utime > config->bluedot_timeout )
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] == Deleting IP address from cache -> %u",  __FILE__, __LINE__, SaganBluedotIPCache[i].ip);
                                }

                        }
                    else
                        {

                            memcpy(TmpSaganBluedotIPCache[timeout_count].ip, SaganBluedotIPCache[i].ip, sizeof(SaganBluedotIPCache[i].ip));
                            TmpSaganBluedotIPCache[timeout_count].cache_utime = SaganBluedotIPCache[i].cache_utime;
                            TmpSaganBluedotIPCache[timeout_count].mdate_utime = SaganBluedotIPCache[i].mdate_utime;
                            TmpSaganBluedotIPCache[timeout_count].cdate_utime = SaganBluedotIPCache[i].cdate_utime;
                            TmpSaganBluedotIPCache[timeout_count].alertid = SaganBluedotIPCache[i].alertid;

                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {
                    memcpy(SaganBluedotIPCache[i].ip, TmpSaganBluedotIPCache[i].ip, sizeof(TmpSaganBluedotIPCache[i].ip));
                    SaganBluedotIPCache[i].cache_utime = TmpSaganBluedotIPCache[i].cache_utime;
                    SaganBluedotIPCache[i].mdate_utime = TmpSaganBluedotIPCache[i].mdate_utime;
                    SaganBluedotIPCache[i].cdate_utime = TmpSaganBluedotIPCache[i].cdate_utime;
                    SaganBluedotIPCache[i].alertid = TmpSaganBluedotIPCache[i].alertid;
                }

*/

            //deleted_count = counters->bluedot_ip_cache_count - (uint64_t)timeout_count;

            pthread_mutex_lock(&CounterBluedotGenericMutex);
	    deleted_count = counters->bluedot_ip_cache_count - new_bluedot_ip_max_cache; 
//            counters->bluedot_ip_cache_count = (uint64_t)timeout_count;
    	    counters->bluedot_ip_cache_count = new_bluedot_ip_max_cache;
            pthread_mutex_unlock(&CounterBluedotGenericMutex);

            Sagan_Log(NORMAL, "[%s, line %d] Deleted %d IP addresses from Bluedot cache. New IP cache count is %d.",__FILE__, __LINE__, deleted_count, counters->bluedot_ip_cache_count);

            /* Clean hash cache */

            timeout_count = 0;

            for (i=0; i<counters->bluedot_hash_cache_count; i++)
                {

                    if ( timeint - SaganBluedotHashCache[i].cache_utime > config->bluedot_timeout )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] == Deleting hash from cache -> %s",  __FILE__, __LINE__, SaganBluedotHashCache[i].hash);
                                }
                        }
                    else
                        {

                            strlcpy(TmpSaganBluedotHashCache[timeout_count].hash, SaganBluedotHashCache[i].hash, sizeof(TmpSaganBluedotHashCache[timeout_count].hash));
                            TmpSaganBluedotHashCache[timeout_count].cache_utime = SaganBluedotHashCache[i].cache_utime;    /* store utime */
                            TmpSaganBluedotHashCache[timeout_count].alertid = SaganBluedotHashCache[i].alertid;
                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {

                    strlcpy(SaganBluedotHashCache[i].hash, TmpSaganBluedotHashCache[i].hash, sizeof(SaganBluedotHashCache[i].hash));
                    SaganBluedotHashCache[i].cache_utime = TmpSaganBluedotHashCache[i].cache_utime;
                    SaganBluedotHashCache[i].alertid = TmpSaganBluedotHashCache[i].alertid;
                }

            deleted_count = counters->bluedot_hash_cache_count - (uint64_t)timeout_count;

            pthread_mutex_lock(&CounterBluedotGenericMutex);
            counters->bluedot_hash_cache_count = (uint64_t)timeout_count;
            pthread_mutex_unlock(&CounterBluedotGenericMutex);

            Sagan_Log(NORMAL, "[%s, line %d] Deleted %d hashes from Bluedot cache.",__FILE__, __LINE__, deleted_count);

            /* Clean URL cache */

            timeout_count = 0;

            for (i=0; i<counters->bluedot_url_cache_count; i++)
                {

                    if ( timeint - SaganBluedotURLCache[i].cache_utime > config->bluedot_timeout )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] == Deleting URL from cache -> %s",  __FILE__, __LINE__, SaganBluedotURLCache[i].url);
                                }
                        }
                    else
                        {

                            strlcpy(TmpSaganBluedotURLCache[timeout_count].url, SaganBluedotURLCache[i].url, sizeof(TmpSaganBluedotURLCache[timeout_count].url));
                            TmpSaganBluedotURLCache[timeout_count].cache_utime = SaganBluedotURLCache[i].cache_utime;
                            TmpSaganBluedotURLCache[timeout_count].alertid = SaganBluedotURLCache[i].alertid;
                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {
                    strlcpy(SaganBluedotURLCache[i].url, TmpSaganBluedotURLCache[i].url, sizeof(SaganBluedotURLCache[i].url));
                    SaganBluedotURLCache[i].cache_utime = TmpSaganBluedotURLCache[i].cache_utime;
                    SaganBluedotURLCache[i].alertid = TmpSaganBluedotURLCache[i].alertid;
                }

            deleted_count = counters->bluedot_url_cache_count - (uint64_t)timeout_count;

            pthread_mutex_lock(&CounterBluedotGenericMutex);
            counters->bluedot_url_cache_count = (uint64_t)timeout_count;
            pthread_mutex_unlock(&CounterBluedotGenericMutex);

            Sagan_Log(NORMAL, "[%s, line %d] Deleted %d URLs from Bluedot cache.",__FILE__, __LINE__, deleted_count);

            /* Clean Filename cache */

            timeout_count = 0;

            for (i=0; i<counters->bluedot_filename_cache_count; i++)
                {
                    if ( timeint - SaganBluedotFilenameCache[i].cache_utime > config->bluedot_timeout )
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] == Deleting Filename from cache -> %s",  __FILE__, __LINE__, SaganBluedotFilenameCache[i].filename);
                                }
                        }
                    else
                        {

                            strlcpy(TmpSaganBluedotFilenameCache[timeout_count].filename, SaganBluedotFilenameCache[i].filename, sizeof(TmpSaganBluedotFilenameCache[timeout_count].filename));
                            TmpSaganBluedotFilenameCache[timeout_count].cache_utime = SaganBluedotFilenameCache[i].cache_utime;
                            TmpSaganBluedotFilenameCache[timeout_count].alertid = SaganBluedotFilenameCache[i].alertid;
                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {
                    strlcpy(SaganBluedotFilenameCache[i].filename, TmpSaganBluedotFilenameCache[i].filename, sizeof(SaganBluedotFilenameCache[i].filename));
                    SaganBluedotFilenameCache[i].cache_utime = TmpSaganBluedotFilenameCache[i].cache_utime;
                    SaganBluedotFilenameCache[i].alertid = TmpSaganBluedotFilenameCache[i].alertid;
                }

            deleted_count = counters->bluedot_filename_cache_count - (uint64_t)timeout_count;

            pthread_mutex_lock(&CounterBluedotGenericMutex);
            counters->bluedot_filename_cache_count = (uint64_t)timeout_count;
            pthread_mutex_unlock(&CounterBluedotGenericMutex);

            Sagan_Log(NORMAL, "[%s, line %d] Deleted %d filenames from Bluedot cache.",__FILE__, __LINE__, deleted_count);

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

unsigned char Sagan_Bluedot_Lookup(char *data,  unsigned char type, int rule_position, unsigned char *ip )
{

    unsigned char ip_convert[MAXIPBIT] = { 0 };
    memset(ip_convert, 0, MAXIPBIT);
    memcpy(ip_convert, ip, MAXIPBIT);

    char tmpurl[1024] = { 0 };
    char tmpdeviceid[64] = { 0 };

    CURL *curl;
    CURLcode res;

    struct curl_slist *headers = NULL;
    char *response=NULL;

    struct json_object *json_in = NULL;
    json_object *string_obj;

    const char *cat=NULL;
    const char *cdate_utime=NULL;
    const char *mdate_utime=NULL;

    uint64_t cdate_utime_u32;
    uint64_t mdate_utime_u32;

    char cattmp[64] = { 0 };
    char *saveptr=NULL;
    signed char bluedot_alertid = 0;		/* -128 to 127 */
    int i;

    char tmp[64] = { 0 };
    char ip_s[64] = { 0 };

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

            if ( is_notroutable(ip) )
                {

                    if ( debug->debugbluedot )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] %s is RFC1918, link local or invalid.", __FILE__, __LINE__, data);
                        }

                    return(false);
                }

            for (i=0; i<config->bluedot_ip_max_cache; i++)
                {

                    if (!memcmp( ip_convert, SaganBluedotIPCache[i].ip, MAXIPBIT ))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled %s from Bluedot cache with category of \"%d\". [cdate: %d / mdate: %d]", __FILE__, __LINE__, data, SaganBluedotIPCache[i].alertid, SaganBluedotIPCache[i].cdate_utime, SaganBluedotIPCache[i].mdate_utime);
                                }

                            bluedot_alertid = SaganBluedotIPCache[i].alertid;

                            if ( bluedot_alertid != 0 && rulestruct[rule_position].bluedot_mdate_effective_period != 0 )
                                {

                                    if ( ( epoch_time - SaganBluedotIPCache[i].mdate_utime ) > rulestruct[rule_position].bluedot_mdate_effective_period )
                                        {

                                            if ( debug->debugbluedot )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] From Bluedot Cache - qmdate for %s is over %d seconds.  Not alerting.", __FILE__, __LINE__, data, rulestruct[rule_position].bluedot_mdate_effective_period);
                                                }

                                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                                            counters->bluedot_mdate_cache++;
                                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                                            bluedot_alertid = 0;
                                        }
                                }

                            else if ( bluedot_alertid != 0 && rulestruct[rule_position].bluedot_cdate_effective_period != 0 )
                                {

                                    if ( ( epoch_time - SaganBluedotIPCache[i].cdate_utime ) > rulestruct[rule_position].bluedot_cdate_effective_period )
                                        {

                                            if ( debug->debugbluedot )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] qcdate for %s is over %d seconds.  Not alerting.", __FILE__, __LINE__, data, rulestruct[rule_position].bluedot_cdate_effective_period);
                                                }

                                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                                            counters->bluedot_cdate_cache++;
                                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                                            bluedot_alertid = 0;
                                        }
                                }


                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_ip_cache_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

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


            snprintf(tmpurl, sizeof(tmpurl), "http://%s/%s%s%s", config->bluedot_ip, config->bluedot_uri, BLUEDOT_IP_LOOKUP_URL, data);

        }  /* BLUEDOT_LOOKUP_IP */

    else if ( type == BLUEDOT_LOOKUP_HASH )
        {

            for (i=0; i<counters->bluedot_hash_cache_count; i++)
                {

                    pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);
                    bluedot_hash_update = 1;

                    if (!strcasecmp(data, SaganBluedotHashCache[i].hash))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled file hash '%s' from Bluedot hash cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotHashCache[i].alertid);
                                }

                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_hash_cache_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                            pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);
                            bluedot_hash_update = 0;

                            return(SaganBluedotHashCache[i].alertid);

                        }

                    pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);
                    bluedot_hash_update = 0;

                }

            /* Check Bluedot Hash Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < bluedot_hash_queue; i++)
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


            /* If not in Bluedot Hash queue,  add it */

            pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);
            SaganBluedotHashQueue = (_Sagan_Bluedot_Hash_Queue *) realloc(SaganBluedotHashQueue, (bluedot_hash_queue+1) * sizeof(_Sagan_Bluedot_Hash_Queue));

            if ( SaganBluedotHashQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotHashQueue. Abort!", __FILE__, __LINE__);
                }

            strlcpy(SaganBluedotHashQueue[bluedot_hash_queue].hash, data, sizeof(SaganBluedotHashQueue[bluedot_hash_queue].hash));
            bluedot_hash_queue++;
            pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);

            if (debug->debugbluedot)
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Going to query hash %s from Bluedot.", __FILE__, __LINE__, data);
                }



            snprintf(tmpurl, sizeof(tmpurl), "http://%s/%s%s%s", config->bluedot_ip, config->bluedot_uri, BLUEDOT_HASH_LOOKUP_URL, data);
        }

    else if ( type == BLUEDOT_LOOKUP_URL )
        {

            for (i=0; i<counters->bluedot_url_cache_count; i++)
                {

                    pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);
                    bluedot_url_update = 1;

                    if (!strcasecmp(data, SaganBluedotURLCache[i].url))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled file URL '%s' from Bluedot URL cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotURLCache[i].alertid);
                                }
                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_url_cache_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                            bluedot_url_update = 0;
                            pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);

                            return(SaganBluedotURLCache[i].alertid);

                        }

                    bluedot_url_update = 0;
                    pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);

                }

            /* Check Bluedot Hash Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < bluedot_url_queue; i++)
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

            pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);
            SaganBluedotURLQueue = (_Sagan_Bluedot_URL_Queue *) realloc(SaganBluedotURLQueue, (bluedot_url_queue+1) * sizeof(_Sagan_Bluedot_URL_Queue));

            if ( SaganBluedotURLQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotURLQueue. Abort!", __FILE__, __LINE__);
                }

            strlcpy(SaganBluedotURLQueue[bluedot_url_queue].url, data, sizeof(SaganBluedotURLQueue[bluedot_url_queue].url));
            bluedot_url_queue++;
            pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);

            if (debug->debugbluedot)
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Going to query url %s from Bluedot.", __FILE__, __LINE__, data);
                }


            snprintf(tmpurl, sizeof(tmpurl), "http://%s/%s%s%s", config->bluedot_ip, config->bluedot_uri, BLUEDOT_URL_LOOKUP_URL, data);

        }

    else if ( type == BLUEDOT_LOOKUP_FILENAME )
        {

            for (i=0; i<counters->bluedot_filename_cache_count; i++)
                {

                    pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);
                    bluedot_filename_update = 1;

                    if (!strcasecmp(data, SaganBluedotFilenameCache[i].filename))
                        {

                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] Pulled file filename '%s' from Bluedot filename cache with category of \"%d\".", __FILE__, __LINE__, data, SaganBluedotFilenameCache[i].alertid);
                                }

                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_filename_cache_hit++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);


                            bluedot_filename_update = 0;
                            pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);

                            return(SaganBluedotFilenameCache[i].alertid);

                        }

                    bluedot_filename_update = 0;
                    pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);

                }

            /* Check Bluedot File Queue,  make sure we aren't looking up something that is already being looked up */

            for (i=0; i < bluedot_filename_queue; i++)
                {
                    if ( !strcasecmp(data, SaganBluedotFilenameQueue[i].filename) )
                        {
                            if (debug->debugbluedot)
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] %s is already being looked up. Skipping....", __FILE__, __LINE__, data);
                                }

                            return(false);
                        }
                }


            /* If not in Bluedot Filename queue,  add it */

            pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);
            SaganBluedotFilenameQueue = (_Sagan_Bluedot_Filename_Queue *) realloc(SaganBluedotFilenameQueue, (bluedot_filename_queue+1) * sizeof(_Sagan_Bluedot_Filename_Queue));

            if ( SaganBluedotFilenameQueue == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for SaganBluedotFilenameQueue. Abort!", __FILE__, __LINE__);
                }

            strlcpy(SaganBluedotHashQueue[bluedot_filename_queue].hash, data, sizeof(SaganBluedotHashQueue[bluedot_filename_queue].hash));
            bluedot_filename_queue++;
            pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);

            if (debug->debugbluedot)
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Going to query filename %s from Bluedot.", __FILE__, __LINE__, data);
                }

            snprintf(tmpurl, sizeof(tmpurl), "http://%s/%s%s%s", config->bluedot_ip, config->bluedot_uri, BLUEDOT_FILENAME_LOOKUP_URL, data);
        }


    snprintf(tmpdeviceid, sizeof(tmpdeviceid), "X-BLUEDOT-DEVICEID: %s", config->bluedot_device_id);


    /* Do the Bluedot API call */

    curl = curl_easy_init();

    if (curl)
        {

            curl_easy_setopt(curl, CURLOPT_URL, tmpurl);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);    /* WIll send SIGALRM if not set */

            headers = curl_slist_append (headers, BLUEDOT_PROCESSOR_USER_AGENT);
            headers = curl_slist_append (headers, tmpdeviceid);
//	    headers = curl_slist_append (headers, "X-Bluedot-Verbose: 1");		/* For more verbose output */
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER , headers );
            res = curl_easy_perform(curl);
        }

    curl_easy_cleanup(curl);

    if ( response == NULL )
        {
            Sagan_Log(WARN, "[%s, line %d] Bluedot returned a empty \"response\".", __FILE__, __LINE__);

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
            counters->bluedot_error_count++;
            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

            Sagan_Bluedot_Clean_Queue(data, type, ip);

            return(false);
        }

    json_in = json_tokener_parse(response);

    if ( type == BLUEDOT_LOOKUP_IP )
        {
            json_object_object_get_ex(json_in, "qipcode", &string_obj);
            cat = json_object_get_string(string_obj);

            json_object_object_get_ex(json_in, "qcdate", &string_obj);
            cdate_utime = json_object_get_string(string_obj);

            if ( cdate_utime != NULL )
                {

                    snprintf(tmp, sizeof(tmp), "%s", cdate_utime);
                    strtok_r(tmp, "\"", &saveptr);
                    cdate_utime_u32 = atol(strtok_r(NULL, "\"", &saveptr));

                }
            else
                {

                    Sagan_Log(WARN, "Bluedot return a bad qcdate.");

                }

            json_object_object_get_ex(json_in, "qmdate", &string_obj);
            mdate_utime = json_object_get_string(string_obj);

            if ( mdate_utime != NULL )
                {

                    snprintf(tmp, sizeof(tmp), "%s", mdate_utime);
                    strtok_r(tmp, "\"", &saveptr);
                    mdate_utime_u32 = atol(strtok_r(NULL, "\"", &saveptr));

                }
            else
                {

                    Sagan_Log(WARN, "Bluedot return a bad qmdate.");

                }

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
            Sagan_Log(WARN, "Bluedot return a qipcode category.");

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
            counters->bluedot_error_count++;
            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

            Sagan_Bluedot_Clean_Queue(data, type, ip);

            return(false);
        }

    /* strtok_r() doesn't like const char *cat */

    snprintf(cattmp, sizeof(cattmp), "%s", cat);
    strtok_r(cattmp, "\"", &saveptr);

    bluedot_alertid  = atoi(strtok_r(NULL, "\"", &saveptr));

    if ( debug->debugbluedot)
        {
            Sagan_Log(DEBUG, "[%s, line %d] Bluedot return category \"%d\" for %s. [cdate: %d / mdate: %d]", __FILE__, __LINE__, bluedot_alertid, data, cdate_utime_u32, mdate_utime_u32);
        }

    if ( bluedot_alertid == -1 )
        {
            Sagan_Log(WARN, "Bluedot reports an invalid API key.  Lookup aborted!");
	    Sagan_Bluedot_Clean_Queue(data, type, ip);
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

//            bluedot_ip_update = 1;

            /* Store data into cache */

            memcpy(SaganBluedotIPCache[counters->bluedot_ip_cache_count].ip, ip_convert, MAXIPBIT);
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].cache_utime = epoch_time;                   /* store utime */
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].cdate_utime = cdate_utime_u32;
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].mdate_utime = mdate_utime_u32;
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].alertid = bluedot_alertid;

            counters->bluedot_ip_total++;
            counters->bluedot_ip_cache_count++;

 //           bluedot_ip_update = 0;

            pthread_mutex_unlock(&SaganProcBluedotIPWorkMutex);

            if ( bluedot_alertid != 0 && rulestruct[rule_position].bluedot_mdate_effective_period != 0 )
                {

                    if ( ( epoch_time - mdate_utime_u32 ) > rulestruct[rule_position].bluedot_mdate_effective_period )
                        {

                            if ( debug->debugbluedot )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] qmdate for %s is over %d seconds.  Not alerting.", __FILE__, __LINE__, data, rulestruct[rule_position].bluedot_mdate_effective_period);
                                }

                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_mdate++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                            bluedot_alertid = 0;
                        }
                }

            else if ( bluedot_alertid != 0 && rulestruct[rule_position].bluedot_cdate_effective_period != 0 )
                {

                    if ( ( epoch_time - cdate_utime_u32 ) > rulestruct[rule_position].bluedot_cdate_effective_period )
                        {

                            if ( debug->debugbluedot )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] qcdate for %s is over %d seconds.  Not alerting.", __FILE__, __LINE__, data, rulestruct[rule_position].bluedot_cdate_effective_period);
                                }

                            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                            counters->bluedot_cdate++;
                            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                            bluedot_alertid = 0;
                        }
                }

        }

    /* File hash lookup */

    else if ( type == BLUEDOT_LOOKUP_HASH )
        {

            pthread_mutex_lock(&SaganProcBluedotHashWorkMutex);

            bluedot_hash_update = 1;

            counters->bluedot_hash_total++;

            strlcpy(SaganBluedotHashCache[counters->bluedot_hash_cache_count].hash, data, sizeof(SaganBluedotHashCache[counters->bluedot_hash_cache_count].hash));
            SaganBluedotHashCache[counters->bluedot_hash_cache_count].cache_utime = epoch_time;
            SaganBluedotHashCache[counters->bluedot_hash_cache_count].alertid = bluedot_alertid;
            counters->bluedot_hash_cache_count++;

            bluedot_hash_update = 0;

            pthread_mutex_unlock(&SaganProcBluedotHashWorkMutex);

        }

    /* URL lookup */

    else if ( type == BLUEDOT_LOOKUP_URL )
        {
            pthread_mutex_lock(&SaganProcBluedotURLWorkMutex);

            bluedot_url_update = 1;

            counters->bluedot_url_total++;

            strlcpy(SaganBluedotURLCache[counters->bluedot_url_cache_count].url, data, sizeof(SaganBluedotURLCache[counters->bluedot_url_cache_count].url));
            SaganBluedotURLCache[counters->bluedot_url_cache_count].cache_utime = epoch_time;
            SaganBluedotURLCache[counters->bluedot_url_cache_count].alertid = bluedot_alertid;
            counters->bluedot_url_cache_count++;

            bluedot_url_update = 0;

            pthread_mutex_unlock(&SaganProcBluedotURLWorkMutex);

        }

    /* Filename Lookup */

    else if ( type == BLUEDOT_LOOKUP_FILENAME )
        {

            pthread_mutex_lock(&SaganProcBluedotFilenameWorkMutex);

            bluedot_filename_update = 1;

            counters->bluedot_filename_total++;

            strlcpy(SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].filename, data, sizeof(SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].filename));
            SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].cache_utime = epoch_time;
            SaganBluedotFilenameCache[counters->bluedot_filename_cache_count].alertid = bluedot_alertid;
            counters->bluedot_filename_cache_count++;

            bluedot_filename_update = 0;

            pthread_mutex_unlock(&SaganProcBluedotFilenameWorkMutex);
        }


    Sagan_Bluedot_Clean_Queue(data, type, ip);	/* Remove item for "queue" */

    json_object_put(json_in);       		/* Clear json_in as we're done with it */
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

int Sagan_Bluedot_IP_Lookup_All ( char *syslog_message, int rule_position, _Sagan_Lookup_Cache_Entry *lookup_cache, int lookup_cache_size )
{

    int i;
    int j;
    int port = 0;

    char ip[MAXIP] = { 0 };
    unsigned char bluedot_results;
    sbool bluedot_flag;

    for (i = 0; i < lookup_cache_size; i++)
        {

            bluedot_results = Sagan_Bluedot_Lookup(lookup_cache[i].ip, BLUEDOT_LOOKUP_IP, rule_position, lookup_cache[i].ip_bits);
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


                        }
                }

            if ( found == 0 )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Unknown Bluedot category '%s' found in %s at line %d. Abort!", __FILE__, __LINE__, tmp2, ruleset, linecount);
                }

            tmptoken = strtok_r(NULL, "," , &saveptrrule);

        }

}

#endif

