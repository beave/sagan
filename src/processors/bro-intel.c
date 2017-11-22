/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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

/* bro-intel.c
*
* This allows Sagan to read in Bro Intel files,  like those from Critical
* Stack (https://intel.brointel.com).
*
*/

/* TODO:  needs stats and perfmon! */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>


#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "parsers/parsers.h"

#include "processors/bro-intel.h"

#define MAX_BROINTEL_LINE_SIZE 10240

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _SaganDebug *debug;

struct _Sagan_Processor_Info *processor_info_brointel = NULL;

struct _Sagan_BroIntel_Intel_Addr *Sagan_BroIntel_Intel_Addr;
struct _Sagan_BroIntel_Intel_Domain *Sagan_BroIntel_Intel_Domain;
struct _Sagan_BroIntel_Intel_File_Hash *Sagan_BroIntel_Intel_File_Hash;
struct _Sagan_BroIntel_Intel_URL *Sagan_BroIntel_Intel_URL;
struct _Sagan_BroIntel_Intel_Software *Sagan_BroIntel_Intel_Software;
struct _Sagan_BroIntel_Intel_Email *Sagan_BroIntel_Intel_Email;
struct _Sagan_BroIntel_Intel_User_Name *Sagan_BroIntel_Intel_User_Name;
struct _Sagan_BroIntel_Intel_File_Name *Sagan_BroIntel_Intel_File_Name;
struct _Sagan_BroIntel_Intel_Cert_Hash *Sagan_BroIntel_Intel_Cert_Hash;

pthread_mutex_t CounterBroIntelGenericMutex=PTHREAD_MUTEX_INITIALIZER;

/*****************************************************************************
 * Sagan_BroIntel_Init - Sets up globals.  Not really used yet.
 *****************************************************************************/

void Sagan_BroIntel_Init(void)
{

    /* Init memory for processor / storage of Bro Intel data */

    Sagan_BroIntel_Intel_Addr = malloc(sizeof(_Sagan_BroIntel_Intel_Addr));

    if ( Sagan_BroIntel_Intel_Addr == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_Addr. Abort!", __FILE__, __LINE__);
        }

    memset(Sagan_BroIntel_Intel_Addr, 0, sizeof(_Sagan_BroIntel_Intel_Addr));

    Sagan_BroIntel_Intel_Domain = malloc(sizeof(_Sagan_BroIntel_Intel_Domain));

    if ( Sagan_BroIntel_Intel_Domain == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_Domain. Abort!", __FILE__, __LINE__);
        }

    memset(Sagan_BroIntel_Intel_Domain, 0, sizeof(_Sagan_BroIntel_Intel_Domain));

    Sagan_BroIntel_Intel_File_Hash = malloc(sizeof(_Sagan_BroIntel_Intel_File_Hash));

    if ( Sagan_BroIntel_Intel_File_Hash == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_File_Hash. Abort!", __FILE__, __LINE__);
        }

    memset(Sagan_BroIntel_Intel_File_Hash, 0, sizeof(_Sagan_BroIntel_Intel_File_Hash));

    Sagan_BroIntel_Intel_URL = malloc(sizeof(_Sagan_BroIntel_Intel_URL));

    if ( Sagan_BroIntel_Intel_URL == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_URL. Abort!", __FILE__, __LINE__);
        }

    memset(Sagan_BroIntel_Intel_URL, 0, sizeof(_Sagan_BroIntel_Intel_URL));

    Sagan_BroIntel_Intel_Software = malloc(sizeof(_Sagan_BroIntel_Intel_Software));

    if ( Sagan_BroIntel_Intel_Software == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_Software. Abort!", __FILE__, __LINE__);
        }

    memset(Sagan_BroIntel_Intel_Software, 0, sizeof(_Sagan_BroIntel_Intel_Software));

    Sagan_BroIntel_Intel_Email = malloc(sizeof(_Sagan_BroIntel_Intel_Email));

    if ( Sagan_BroIntel_Intel_Email == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_Email. Abort!", __FILE__, __LINE__);
        }

    memset(Sagan_BroIntel_Intel_Email, 0, sizeof(_Sagan_BroIntel_Intel_Email));

    Sagan_BroIntel_Intel_User_Name = malloc(sizeof(_Sagan_BroIntel_Intel_User_Name));

    if ( Sagan_BroIntel_Intel_User_Name == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_User_Name. Abort!", __FILE__, __LINE__);
        }

    memset(Sagan_BroIntel_Intel_User_Name, 0, sizeof(_Sagan_BroIntel_Intel_User_Name));

    Sagan_BroIntel_Intel_File_Name = malloc(sizeof(_Sagan_BroIntel_Intel_File_Name));

    if ( Sagan_BroIntel_Intel_File_Name == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_File_Name. Abort!", __FILE__, __LINE__);
        }

    memset(Sagan_BroIntel_Intel_File_Name, 0, sizeof(_Sagan_BroIntel_Intel_File_Name));

    Sagan_BroIntel_Intel_Cert_Hash = malloc(sizeof(_Sagan_BroIntel_Intel_Cert_Hash));

    if ( Sagan_BroIntel_Intel_Cert_Hash == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to allocate memory for Sagan_BroIntel_Intel_Cert_Hash. Abort!", __FILE__, __LINE__);
        }

}

/*****************************************************************************
 * Sagan_BroIntel_Load_File - Loads BroIntel data and splits it up
 * into different arrays.
 * ***************************************************************************/

void Sagan_BroIntel_Load_File ( void )
{

    FILE *brointel_file;

    char *value;
    char *type;
    char *description;

    sbool found_flag;
    sbool found_flag_array;

    char *tok = NULL; ;
    char *ptmp = NULL;

    int line_count;
    int i;

    unsigned char bits_ip[MAXIPBIT] = {0};

    char *brointel_filename = NULL;
    char brointelbuf[MAX_BROINTEL_LINE_SIZE] = { 0 };

    pthread_mutex_lock(&CounterBroIntelGenericMutex);
    counters->brointel_dups = 0;
    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

    brointel_filename = strtok_r(config->brointel_files, ",", &ptmp);

    while ( brointel_filename != NULL )
        {

            Sagan_Log(S_NORMAL, "Bro Intel Processor Loading File: %s.", brointel_filename);

            if (( brointel_file = fopen(brointel_filename, "r")) == NULL )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Could not load Bro Intel file! (%s - %s)", __FILE__, __LINE__, brointel_filename, strerror(errno));
                }

            while(fgets(brointelbuf, MAX_BROINTEL_LINE_SIZE, brointel_file) != NULL)
                {

                    /* Skip comments and blank linkes */

                    if (brointelbuf[0] == '#' || brointelbuf[0] == 10 || brointelbuf[0] == ';' || brointelbuf[0] == 32 )
                        {
                            line_count++;
                            continue;
                        }
                    else
                        {

                            Remove_Return(brointelbuf);

                            value = strtok_r(brointelbuf, "\t", &tok);
                            type = strtok_r(NULL, "\t", &tok);
                            description = strtok_r(NULL, "\t", &tok);

                            if ( value == NULL || type == NULL || description == NULL )
                                {
                                    Sagan_Log(S_WARN, "[%s, line %d] Got invalid line at %d in %s", __FILE__, __LINE__, line_count, brointel_filename);
                                }

                            found_flag = 0;

                            if (!strcmp(type, "Intel::ADDR") && IP2Bit(value, bits_ip))
                                {

                                    found_flag = 1; 			/* Used to short circuit other 'type' lookups */
                                    found_flag_array = 0;		/* Used to short circuit/warn when dups are found.  This way we don't waste memory/CPU */

                                    /* Check for duplicates. */

                                    for (i=0; i < counters->brointel_addr_count; i++)
                                        {

                                            if ( !memcmp(Sagan_BroIntel_Intel_Addr[i].bits_ip, bits_ip, sizeof(bits_ip)) )
                                                {
                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::ADDR address %s in %s on line %d.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;
                                                }
                                        }

                                    if ( found_flag_array == 0 )
                                        {

                                            Sagan_BroIntel_Intel_Addr = (_Sagan_BroIntel_Intel_Addr *) realloc(Sagan_BroIntel_Intel_Addr, (counters->brointel_addr_count+1) * sizeof(_Sagan_BroIntel_Intel_Addr));

                                            if ( Sagan_BroIntel_Intel_Addr == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_Addr. Abort!", __FILE__, __LINE__);
                                                }

                                            pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                            memcpy( Sagan_BroIntel_Intel_Addr[counters->brointel_addr_count].bits_ip, bits_ip, sizeof(bits_ip) );
                                            counters->brointel_addr_count++;
                                            pthread_mutex_unlock(&CounterBroIntelGenericMutex);
                                        }

                                }

                            if (!strcmp(type, "Intel::DOMAIN") && found_flag == 0)
                                {
                                    To_LowerC(value);

                                    found_flag = 1;
                                    found_flag_array = 0;


                                    for (i=0; i < counters-> brointel_domain_count; i++)
                                        {
                                            if (!strcmp(Sagan_BroIntel_Intel_Domain[i].domain, value))
                                                {
                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::DOMAIN '%s' in %s on line %d.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;
                                                }
                                        }

                                    if ( found_flag_array == 0 )
                                        {
                                            Sagan_BroIntel_Intel_Domain = (_Sagan_BroIntel_Intel_Domain *) realloc(Sagan_BroIntel_Intel_Domain, (counters->brointel_domain_count+1) * sizeof(_Sagan_BroIntel_Intel_Domain));

                                            if ( Sagan_BroIntel_Intel_Domain == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_Domain. Abort!", __FILE__, __LINE__);
                                                }

                                            strlcpy(Sagan_BroIntel_Intel_Domain[counters->brointel_domain_count].domain, value, sizeof(Sagan_BroIntel_Intel_Domain[counters->brointel_domain_count].domain));

                                            pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                            counters->brointel_domain_count++;
                                            pthread_mutex_unlock(&CounterBroIntelGenericMutex);
                                        }

                                }

                            if (!strcmp(type, "Intel::FILE_HASH") && found_flag == 0)
                                {
                                    To_LowerC(value);

                                    found_flag = 1;
                                    found_flag_array = 0;

                                    for (i=0; i < counters->brointel_file_hash_count; i++)
                                        {

                                            if (!strcmp(Sagan_BroIntel_Intel_File_Hash[i].hash, value))
                                                {

                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::FILE_HASH '%s' in %s on line %d.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;
                                                }
                                        }

                                    if ( found_flag_array == 0 )
                                        {

                                            Sagan_BroIntel_Intel_File_Hash = (_Sagan_BroIntel_Intel_File_Hash *) realloc(Sagan_BroIntel_Intel_File_Hash, (counters->brointel_file_hash_count+1) * sizeof(_Sagan_BroIntel_Intel_File_Hash));

                                            if ( Sagan_BroIntel_Intel_File_Hash == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_File_Hash. Abort!", __FILE__, __LINE__);
                                                }

                                            strlcpy(Sagan_BroIntel_Intel_File_Hash[counters->brointel_file_hash_count].hash, value, sizeof(Sagan_BroIntel_Intel_File_Hash[counters->brointel_file_hash_count].hash));
                                            counters->brointel_file_hash_count++;

                                        }
                                }


                            if (!strcmp(type, "Intel::URL") && found_flag == 0)
                                {

                                    To_LowerC(value);

                                    found_flag = 1;
                                    found_flag_array = 0;

                                    for (i=0; i < counters->brointel_url_count; i++)
                                        {
                                            if (!strcmp(Sagan_BroIntel_Intel_URL[i].url, value))
                                                {
                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::URL '%s' in %s on line %d.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;
                                                }
                                        }


                                    if ( found_flag_array == 0 )
                                        {

                                            Sagan_BroIntel_Intel_URL = (_Sagan_BroIntel_Intel_URL *) realloc(Sagan_BroIntel_Intel_URL, (counters->brointel_url_count+1) * sizeof(_Sagan_BroIntel_Intel_URL));

                                            if ( Sagan_BroIntel_Intel_URL == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_URL. Abort!", __FILE__, __LINE__);
                                                }

                                            strlcpy(Sagan_BroIntel_Intel_URL[counters->brointel_url_count].url, value, sizeof(Sagan_BroIntel_Intel_URL[counters->brointel_url_count].url));

                                            pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                            counters->brointel_url_count++;
                                            pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                        }

                                }


                            if (!strcmp(type, "Intel::SOFTWARE") && found_flag == 0)
                                {


                                    To_LowerC(value);

                                    found_flag = 1;
                                    found_flag_array = 0;

                                    for (i=0; i < counters->brointel_software_count++; i++)
                                        {

                                            if (!strcmp(Sagan_BroIntel_Intel_Software[i].software, value))
                                                {

                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::SOFTWARE '%s' in %s on line %d.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;
                                                }
                                        }

                                    if ( found_flag_array == 0 )
                                        {

                                            Sagan_BroIntel_Intel_Software = (_Sagan_BroIntel_Intel_Software *) realloc(Sagan_BroIntel_Intel_Software, (counters->brointel_software_count+1) * sizeof(_Sagan_BroIntel_Intel_Software));

                                            if ( Sagan_BroIntel_Intel_Software == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_Software. Abort!", __FILE__, __LINE__);
                                                }

                                            strlcpy(Sagan_BroIntel_Intel_Software[counters->brointel_software_count].software, value, sizeof(Sagan_BroIntel_Intel_Software[counters->brointel_software_count].software));

                                            pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                            counters->brointel_software_count++;
                                            pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                        }
                                }

                            if (!strcmp(type, "Intel::EMAIL") && found_flag == 0)
                                {

                                    To_LowerC(value);

                                    found_flag_array = 0;

                                    for (i=0; i < counters->brointel_email_count; i++)
                                        {
                                            if (!strcmp(Sagan_BroIntel_Intel_Email[i].email, value))
                                                {
                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::EMAIL '%s' in %s on line %d.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;

                                                }
                                        }

                                    if ( found_flag_array == 0 )
                                        {

                                            Sagan_BroIntel_Intel_Email = (_Sagan_BroIntel_Intel_Email *) realloc(Sagan_BroIntel_Intel_Email, (counters->brointel_email_count+1) * sizeof(_Sagan_BroIntel_Intel_Email));

                                            if ( Sagan_BroIntel_Intel_Email == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_Email. Abort!", __FILE__, __LINE__);
                                                }

                                            strlcpy(Sagan_BroIntel_Intel_Email[counters->brointel_email_count].email, value, sizeof(Sagan_BroIntel_Intel_Email[counters->brointel_email_count].email));

                                            pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                            counters->brointel_email_count++;
                                            pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                            found_flag = 1;
                                        }

                                }


                            if (!strcmp(type, "Intel::USER_NAME") && found_flag == 0)
                                {
                                    To_LowerC(value);

                                    found_flag = 1;
                                    found_flag_array = 0;

                                    for (i=0; i < counters->brointel_user_name_count; i++)
                                        {
                                            if (!strcmp(Sagan_BroIntel_Intel_User_Name[i].username, value))
                                                {
                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::USER_NAME '%s' in %s on line %.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;
                                                }
                                        }

                                    if ( found_flag_array == 0 )
                                        {


                                            Sagan_BroIntel_Intel_User_Name = (_Sagan_BroIntel_Intel_User_Name *) realloc(Sagan_BroIntel_Intel_User_Name, (counters->brointel_user_name_count+1) * sizeof(_Sagan_BroIntel_Intel_User_Name));

                                            if ( Sagan_BroIntel_Intel_User_Name == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_User_Name. Abort!", __FILE__, __LINE__);
                                                }

                                            strlcpy(Sagan_BroIntel_Intel_User_Name[counters->brointel_user_name_count].username, value, sizeof(Sagan_BroIntel_Intel_User_Name[counters->brointel_user_name_count].username));

                                            pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                            counters->brointel_user_name_count++;
                                            pthread_mutex_unlock(&CounterBroIntelGenericMutex);
                                        }
                                }

                            if (!strcmp(type, "Intel::FILE_NAME") && found_flag == 0)
                                {

                                    To_LowerC(value);

                                    found_flag = 1;
                                    found_flag_array = 0;

                                    for (i=0; i < counters->brointel_file_name_count; i++)
                                        {

                                            if (!strcmp(Sagan_BroIntel_Intel_File_Name[i].file_name, value))
                                                {

                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::FILE_NAME '%s' in %s on line %d.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;
                                                }
                                        }


                                    if ( found_flag_array == 0 )
                                        {

                                            Sagan_BroIntel_Intel_File_Name = (_Sagan_BroIntel_Intel_File_Name *) realloc(Sagan_BroIntel_Intel_File_Name, (counters->brointel_file_name_count+1) * sizeof(_Sagan_BroIntel_Intel_File_Name));

                                            if ( Sagan_BroIntel_Intel_File_Name == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_File_Name. Abort!", __FILE__, __LINE__);
                                                }

                                            strlcpy(Sagan_BroIntel_Intel_File_Name[counters->brointel_file_name_count].file_name, value, sizeof(Sagan_BroIntel_Intel_File_Name[counters->brointel_file_name_count].file_name));

                                            pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                            counters->brointel_file_name_count++;
                                            pthread_mutex_unlock(&CounterBroIntelGenericMutex);
                                        }

                                }

                            if (!strcmp(type, "Intel::CERT_HASH") && found_flag == 0)
                                {
                                    To_LowerC(value);

                                    found_flag = 1;
                                    found_flag_array = 0;

                                    for (i=0; i < counters->brointel_cert_hash_count; i++)
                                        {
                                            if (!strcmp(Sagan_BroIntel_Intel_Cert_Hash[i].cert_hash, value))
                                                {
                                                    Sagan_Log(S_WARN, "[%s, line %d] Got duplicate Intel::CERT_HASH '%s' in %s on line %d.", __FILE__, __LINE__, value, brointel_filename, line_count + 1);

                                                    pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                                    counters->brointel_dups++;
                                                    pthread_mutex_unlock(&CounterBroIntelGenericMutex);

                                                    found_flag_array = 1;
                                                }
                                        }

                                    if ( found_flag_array == 0 )
                                        {
                                            Sagan_BroIntel_Intel_Cert_Hash = (_Sagan_BroIntel_Intel_Cert_Hash *) realloc(Sagan_BroIntel_Intel_Cert_Hash, (counters->brointel_cert_hash_count+1) * sizeof(_Sagan_BroIntel_Intel_Cert_Hash));

                                            if ( Sagan_BroIntel_Intel_Cert_Hash == NULL )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for Sagan_BroIntel_Intel_Cert_Hash. Abort!", __FILE__, __LINE__);
                                                }

                                            strlcpy(Sagan_BroIntel_Intel_Cert_Hash[counters->brointel_cert_hash_count].cert_hash, value, sizeof(Sagan_BroIntel_Intel_Cert_Hash[counters->brointel_cert_hash_count].cert_hash));

                                            pthread_mutex_lock(&CounterBroIntelGenericMutex);
                                            counters->brointel_cert_hash_count++;
                                            pthread_mutex_unlock(&CounterBroIntelGenericMutex);
                                        }
                                }


                        }

                    line_count++;

                }
            fclose(brointel_file);
            brointel_filename = strtok_r(NULL, ",", &ptmp);
            line_count = 0;
        }

}

/*****************************************************************************
 * Sagan_BroIntel_IPADDR - Search array for blacklisted IP addresses
 *****************************************************************************/

sbool Sagan_BroIntel_IPADDR ( unsigned char *ip )
{

    int i;

    /* If RFC1918 and friends,  we can short circuit here */

    if ( !is_notroutable(ip))
        {

            if ( debug->debugbrointel )
                {
                    Sagan_Log(S_DEBUG, "[%s, line %d] %u is RFC1918, link local or invalid.", __FILE__, __LINE__, ip);
                }

            return(false);
        }

    /* Search array for for the IP address */

    for ( i = 0; i < counters->brointel_addr_count; i++)
        {

            if ( !memcmp(Sagan_BroIntel_Intel_Addr[i].bits_ip, ip, sizeof(Sagan_BroIntel_Intel_Addr[i].bits_ip)) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found IP %u.", __FILE__, __LINE__, ip);
                        }

                    return(true);
                }

        }

    return(false);

}

/*****************************************************************************
 * Sagan_BroIntel_IPADDR_All - Search and tests _all_ IP addresses within
 * a syslog_message (reguardless of lognorm/parse ip)!
 *****************************************************************************/

sbool Sagan_BroIntel_IPADDR_All ( char *syslog_message, _Sagan_Lookup_Cache_Entry *lookup_cache, size_t cache_size)
{

    int i;
    int b;

    unsigned char ip[MAXIPBIT] = {0};

    for (i = 0; i < cache_size; i++)
        {

            /* Failed to find next IP,  short circuit the process */
            if ((lookup_cache[i].searched && 0 == lookup_cache[i].offset) || !Parse_IP(syslog_message, i+1, NULL, sizeof(lookup_cache[i].ip), lookup_cache, cache_size))
                {
                    return(false);
                }

            if (!IP2Bit(lookup_cache[i].ip, ip))
                {
                    continue;
                }

            for ( b = 0; b < counters->brointel_addr_count; b++ )
                {

                    if ( !memcmp(Sagan_BroIntel_Intel_Addr[b].bits_ip, ip, sizeof(ip)))
                        {
                            return(true);
                        }
                }

        }

    return(false);
}

/*****************************************************************************
 * Sagan_BroIntel_DOMAIN - Search DOMAIN array
 *****************************************************************************/

sbool Sagan_BroIntel_DOMAIN ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_domain_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_Domain[i].domain, false) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found domain %s.", __FILE__, __LINE__, Sagan_BroIntel_Intel_Domain[i].domain);
                        }

                    return(true);
                }

        }

    return(false);

}

/*****************************************************************************
 * Sagan_BroIntel_FILE_HASH - Search FILE_HASH array
 *****************************************************************************/

sbool Sagan_BroIntel_FILE_HASH ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_file_hash_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_File_Hash[i].hash, false) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found file hash %s.", __FILE__, __LINE__, Sagan_BroIntel_Intel_File_Hash[i].hash);
                        }

                    return(true);
                }

        }

    return(false);

}

/*****************************************************************************
 * Sagan_BroIntel_URL - Search URL array
 *****************************************************************************/

sbool Sagan_BroIntel_URL ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_url_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_URL[i].url, false) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found URL \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_URL[i].url);
                        }

                    return(true);
                }

        }

    return(false);
}

/*****************************************************************************
 * Sagan_BroIntel_SOFTWARE - Search SOFTWARE array
 ****************************************************************************/

sbool Sagan_BroIntel_SOFTWARE ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_software_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_Software[i].software, false) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found software \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_Software[i].software);
                        }

                    return(true);
                }

        }

    return(false);
}

/*****************************************************************************
 * Sagan_BroIntel_EMAIL - Search EMAIL array
 *****************************************************************************/

sbool Sagan_BroIntel_EMAIL ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_email_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_Email[i].email, false) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found e-mail address \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_Email[i].email);
                        }

                    return(true);
                }

        }

    return(false);
}

/*****************************************************************************
 * Sagan_BroIntel_USER_NAME - Search USER_NAME array
 ****************************************************************************/

sbool Sagan_BroIntel_USER_NAME ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_user_name_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_User_Name[i].username, false) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found the username \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_User_Name[i].username);
                        }

                    return(true);
                }

        }

    return(false);
}

/****************************************************************************
 * Sagan_BroIntel_FILE_NAME - Search FILE_NAME array
 ****************************************************************************/

sbool Sagan_BroIntel_FILE_NAME ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_file_name_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_File_Name[i].file_name, false) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found the file name \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_File_Name[i].file_name);
                        }

                    return(true);
                }

        }

    return(false);
}

/***************************************************************************
 * Sagan_BroIntel_CERT_HASH - Search CERT_HASH array
 ***************************************************************************/

sbool Sagan_BroIntel_CERT_HASH ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_cert_hash_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_Cert_Hash[i].cert_hash, false) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found the CERT_HASH \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_Cert_Hash[i].cert_hash);
                        }

                    return(true);
                }

        }

    return(false);
}

