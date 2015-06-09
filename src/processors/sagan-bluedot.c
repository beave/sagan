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
#include <json/json.h>
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
struct _Sagan_Bluedot_Cat_List *SaganBluedotCatList;
struct _Rule_Struct *rulestruct;

pthread_mutex_t SaganProcBluedotWorkMutex=PTHREAD_MUTEX_INITIALIZER;

sbool bluedot_cache_clean_lock=0;
int bluedot_queue=0;

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

    SaganBluedotIPCache = malloc(config->bluedot_max_cache * sizeof(struct _Sagan_Bluedot_IP_Cache));
    memset(SaganBluedotIPCache, 0, sizeof(_Sagan_Bluedot_IP_Cache));

    SaganBluedotHashCache = malloc(config->bluedot_max_cache * sizeof(struct _Sagan_Bluedot_Hash_Cache));
    memset(SaganBluedotHashCache, 0, sizeof(_Sagan_Bluedot_Hash_Cache));

    SaganBluedotCatList = malloc(sizeof(_Sagan_Bluedot_Cat_List));
    memset(SaganBluedotCatList, 0, sizeof(_Sagan_Bluedot_Cat_List));

    config->bluedot_last_time = atol(timet);

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
    char *trash = NULL;

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
            if ( bluedot_cache_clean_lock == 0 ) Sagan_Bluedot_Clean_Cache();
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

            deleted_count = counters->bluedot_ip_cache_count - (uint64_t)timeout_count;
            counters->bluedot_ip_cache_count = (uint64_t)timeout_count;

            Sagan_Log(S_NORMAL, "[%s, line %d] Deleted %d IP addresses from Bluedot cache.",__FILE__, __LINE__, deleted_count);

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
                            strlcpy(TmpSaganBluedotHashCache[timeout_count].hash, SaganBluedotHashCache[i].hash, sizeof(TmpSaganBluedotHashCache[timeout_count].hash));
                            TmpSaganBluedotHashCache[timeout_count].utime = SaganBluedotHashCache[i].utime;                                                                                 /* store utime */
                            TmpSaganBluedotHashCache[timeout_count].alertid = SaganBluedotHashCache[i].alertid;
                            timeout_count++;
                        }
                }

            for (i=0; i<timeout_count; i++)
                {

                    strlcpy(SaganBluedotHashCache[i].hash, TmpSaganBluedotHashCache[i].hash, sizeof(SaganBluedotHashCache[i].hash));
                    SaganBluedotHashCache[i].utime = TmpSaganBluedotIPCache[i].utime;
                    SaganBluedotHashCache[i].alertid = TmpSaganBluedotIPCache[i].alertid;
                }

            deleted_count = counters->bluedot_hash_cache_count - (uint64_t)timeout_count;
            counters->bluedot_hash_cache_count = (uint64_t)timeout_count;

            Sagan_Log(S_NORMAL, "[%s, line %d] Deleted %d hashes addresses from Bluedot cache.",__FILE__, __LINE__, deleted_count);


            bluedot_cache_clean_lock = 0;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);
        }

    free(TmpSaganBluedotIPCache);
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
 */

int Sagan_Bluedot_Lookup(char *data,  int type)
{

    char tmpurl[1024] = { 0 };
//    char tmpauth[128] = { 0 };
    char tmpdeviceid[64] = { 0 };

    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char *response=NULL;

    struct json_object *json_in = NULL;

    const char *cat=NULL;
    char cattmp[128] = { 0 };
    char *saveptr=NULL;
    int bluedot_alertid = 0;
    int i;

    char  timet[20] = { 0 };
    time_t t;
    struct tm *now=NULL;

    uint64_t ip;

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
                            Sagan_Log(S_DEBUG, "[%s, line %d] %s is RFC1918.", __FILE__, __LINE__, data);
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

            snprintf(tmpurl, sizeof(tmpurl), "%s%s%s", config->bluedot_url, BLUEDOT_IP_LOOKUP_URL, data);

        }

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

    snprintf(tmpdeviceid, sizeof(tmpdeviceid), "X-BLUEDOT-DEVICEID: %s", config->bluedot_device_id);

    curl = curl_easy_init();

    if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, tmpurl);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback_func);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);   /* WIll send SIGALRM if not set */
            headers = curl_slist_append (headers, BLUEDOT_PROCESSOR_USER_AGENT);
//            headers = curl_slist_append (headers, tmpauth);
            headers = curl_slist_append (headers, tmpdeviceid);
//	    headers = curl_slist_append (headers, "X-Bluedot-Verbose: 1");		/* For more verbose output */
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER , headers );
            res = curl_easy_perform(curl);
        }

    curl_easy_cleanup(curl);

    if ( response != NULL )
        {

            if (!strcmp(response, "Authentication key is invalid"))
                {
                    Sagan_Log(S_WARN, "Got an \"invalid key\" from Bluedot! Processor disabled. ");
                    pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                    counters->bluedot_error_count++;
                    config->bluedot_flag = 0;
                    pthread_mutex_unlock(&SaganProcBluedotWorkMutex);
                    return(false);
                }

        }
    else
        {

            Sagan_Log(S_WARN, "[%s, line %d] Bluedot returned a empty \"response\".", __FILE__, __LINE__);
            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
            counters->bluedot_error_count++;
            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);
            return(false);
        }

    json_in = json_tokener_parse(response);

    if ( type == BLUEDOT_LOOKUP_IP )
        {
            cat  = json_object_get_string(json_object_object_get(json_in, "qipcode"));
        }

    if ( type == BLUEDOT_LOOKUP_HASH )
        {
            cat  = json_object_get_string(json_object_object_get(json_in, "qhashcode"));
        }

    if ( cat == NULL )
        {
            Sagan_Log(S_WARN, "Bluedot return a bad category.");
            pthread_mutex_lock(&SaganProcBluedotWorkMutex);
            counters->bluedot_error_count++;						// DEBUG <- Total error count
            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);
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



    /************************************************************************/
    /* Add entries to cache                                                 */
    /************************************************************************/

    /* IP Address lookup */

    if ( type == BLUEDOT_LOOKUP_IP )
        {

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);

            counters->bluedot_ip_total++;

            SaganBluedotIPCache = (_Sagan_Bluedot_IP_Cache *) realloc(SaganBluedotIPCache, (counters->bluedot_ip_cache_count+1) * sizeof(_Sagan_Bluedot_IP_Cache));
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].host = ip;
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].utime = atol(timet);                                                                                     /* store utime */
            SaganBluedotIPCache[counters->bluedot_ip_cache_count].alertid = bluedot_alertid;
            counters->bluedot_ip_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

        }

    if ( type == BLUEDOT_LOOKUP_HASH )
        {

            pthread_mutex_lock(&SaganProcBluedotWorkMutex);

            counters->bluedot_hash_total++;

            SaganBluedotHashCache = (_Sagan_Bluedot_Hash_Cache *) realloc(SaganBluedotHashCache, (counters->bluedot_hash_cache_count+1) * sizeof(_Sagan_Bluedot_Hash_Cache));
            strlcpy(SaganBluedotHashCache[counters->bluedot_hash_cache_count].hash, data, sizeof(SaganBluedotHashCache[counters->bluedot_hash_cache_count].hash));
            SaganBluedotHashCache[counters->bluedot_hash_cache_count].utime = atol(timet);                                                                                     /* store utime */
            SaganBluedotHashCache[counters->bluedot_hash_cache_count].alertid = bluedot_alertid;
            counters->bluedot_hash_cache_count++;

            pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

        }



    json_object_put(json_in);       /* Clear json_in as we're done with it */

    return(bluedot_alertid);
}

/***************************************************************************
 * Sagan_Bluedot_Cat_Compare - Takes the Bluedot query results and
 * compares to what the rule is looking for
 ***************************************************************************/

int Sagan_Bluedot_Cat_Compare ( int bluedot_results, int rule_position )
{

    int i;

    for ( i = 0; i < rulestruct[rule_position].bluedot_cat_count; i++ )
        {

            if ( bluedot_results == rulestruct[rule_position].bluedot_cats[i] )
                {

                    pthread_mutex_lock(&SaganProcBluedotWorkMutex);
                    counters->bluedot_ip_positive_hit++;
                    pthread_mutex_unlock(&SaganProcBluedotWorkMutex);

                    return(true);
                }

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

    int bluedot_results;
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
            bluedot_flag = Sagan_Bluedot_Cat_Compare( bluedot_results, rule_position );

            if ( bluedot_flag == 1 )
                {
                    return(true);
                }

        }

}

#endif
