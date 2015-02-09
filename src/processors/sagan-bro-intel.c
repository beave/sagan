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

/* sagan-bro-intel.c
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


#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "parsers/parsers.h"

#include "processors/sagan-bro-intel.h"

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

/*****************************************************************************
 * Sagan_BroIntel_Init - Sets up globals.  Not really used yet.
 *****************************************************************************/

void Sagan_BroIntel_Init(void)
{

    processor_info_brointel = malloc(sizeof(struct _Sagan_Processor_Info));
    memset(processor_info_brointel, 0, sizeof(_Sagan_Processor_Info));

    /* This really isn't being used (yet)? */

    processor_info_brointel->processor_name          =       BROINTEL_PROCESSOR_NAME;
    processor_info_brointel->processor_generator_id  =       BROINTEL_PROCESSOR_GENERATOR_ID;
    processor_info_brointel->processor_name          =       BROINTEL_PROCESSOR_NAME;
    processor_info_brointel->processor_facility      =       BROINTEL_PROCESSOR_FACILITY;
    processor_info_brointel->processor_priority      =       BROINTEL_PROCESSOR_PRIORITY;
    processor_info_brointel->processor_pri           =       BROINTEL_PROCESSOR_PRI;
    processor_info_brointel->processor_class         =       BROINTEL_PROCESSOR_CLASS;
    processor_info_brointel->processor_tag           =       BROINTEL_PROCESSOR_TAG;
    processor_info_brointel->processor_rev           =       BROINTEL_PROCESSOR_REV;

}

/*****************************************************************************
 * Sagan_BroIntel_Load_File - Loads BroIntel data and splits it up
 * into different arrays.
 * ***************************************************************************/

void Sagan_BroIntel_Load_File(void)
{

    FILE *brointel_file;

    char *value;
    char *type;
    char *description;

    sbool found_flag;

    char *tok;

    int line_count;

    char brointelbuf[MAX_BROINTEL_LINE_SIZE] = { 0 };

    if (( brointel_file = fopen(config->brointel_file, "r")) == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Could not load Bro Intel file! (%s)", __FILE__, __LINE__, config->brointel_file);
        }

    while(fgets(brointelbuf, MAX_BROINTEL_LINE_SIZE, brointel_file) != NULL)
        {

            /* Skip comments and blank linkes */

            if (brointelbuf[0] == '#' || brointelbuf[0] == 10 || brointelbuf[0] == ';' || brointelbuf[0] == 32 )
                {
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
                            Sagan_Log(S_WARN, "[%s, line %d] Got invalid line at %d in %s", __FILE__, __LINE__, line_count, config->brointel_file);
                        }

                    found_flag = 0;

                    if (!strcmp(type, "Intel::ADDR"))
                        {
                            Sagan_BroIntel_Intel_Addr = (_Sagan_BroIntel_Intel_Addr *) realloc(Sagan_BroIntel_Intel_Addr, (counters->brointel_addr_count+1) * sizeof(_Sagan_BroIntel_Intel_Addr));
                            Sagan_BroIntel_Intel_Addr[counters->brointel_addr_count].u32_ip = IP2Bit(value);
                            counters->brointel_addr_count++;
                            found_flag = 1;
                        }

                    if (!strcmp(type, "Intel::DOMAIN") && found_flag == 0)
                        {
                            Sagan_BroIntel_Intel_Domain = (_Sagan_BroIntel_Intel_Domain *) realloc(Sagan_BroIntel_Intel_Domain, (counters->brointel_domain_count+1) * sizeof(_Sagan_BroIntel_Intel_Domain));
                            To_LowerC(value);
                            strlcpy(Sagan_BroIntel_Intel_Domain[counters->brointel_domain_count].domain, value, sizeof(Sagan_BroIntel_Intel_Domain[counters->brointel_domain_count].domain));
                            counters->brointel_domain_count++;
                            found_flag = 1;
                        }

                    if (!strcmp(type, "Intel::FILE_HASH") && found_flag == 0)
                        {
                            Sagan_BroIntel_Intel_File_Hash = (_Sagan_BroIntel_Intel_File_Hash *) realloc(Sagan_BroIntel_Intel_File_Hash, (counters->brointel_file_hash_count+1) * sizeof(_Sagan_BroIntel_Intel_File_Hash));
                            To_LowerC(value);
                            strlcpy(Sagan_BroIntel_Intel_File_Hash[counters->brointel_file_hash_count].hash, value, sizeof(Sagan_BroIntel_Intel_File_Hash[counters->brointel_file_hash_count].hash));
                            counters->brointel_file_hash_count++;
                            found_flag = 1;
                        }


                    if (!strcmp(type, "Intel::URL") && found_flag == 0)
                        {
                            Sagan_BroIntel_Intel_URL = (_Sagan_BroIntel_Intel_URL *) realloc(Sagan_BroIntel_Intel_URL, (counters->brointel_url_count+1) * sizeof(_Sagan_BroIntel_Intel_URL));
                            To_LowerC(value);
                            strlcpy(Sagan_BroIntel_Intel_URL[counters->brointel_url_count].url, value, sizeof(Sagan_BroIntel_Intel_URL[counters->brointel_url_count].url));
                            counters->brointel_url_count++;
                            found_flag = 1;
                        }


                    if (!strcmp(type, "Intel::SOFTWARE") && found_flag == 0)
                        {
                            Sagan_BroIntel_Intel_Software = (_Sagan_BroIntel_Intel_Software *) realloc(Sagan_BroIntel_Intel_Software, (counters->brointel_software_count+1) * sizeof(_Sagan_BroIntel_Intel_Software));
                            To_LowerC(value);
                            strlcpy(Sagan_BroIntel_Intel_Software[counters->brointel_software_count].software, value, sizeof(Sagan_BroIntel_Intel_Software[counters->brointel_software_count].software));
                            counters->brointel_software_count++;
                            found_flag = 1;
                        }

                    if (!strcmp(type, "Intel::EMAIL") && found_flag == 0)
                        {
                            Sagan_BroIntel_Intel_Email = (_Sagan_BroIntel_Intel_Email *) realloc(Sagan_BroIntel_Intel_Email, (counters->brointel_email_count+1) * sizeof(_Sagan_BroIntel_Intel_Email));
                            To_LowerC(value);
                            strlcpy(Sagan_BroIntel_Intel_Email[counters->brointel_email_count].email, value, sizeof(Sagan_BroIntel_Intel_Email[counters->brointel_email_count].email));
                            counters->brointel_email_count++;
                            found_flag = 1;
                        }


                    if (!strcmp(type, "Intel::USER_NAME") && found_flag == 0)
                        {
                            Sagan_BroIntel_Intel_User_Name = (_Sagan_BroIntel_Intel_User_Name *) realloc(Sagan_BroIntel_Intel_User_Name, (counters->brointel_user_name_count+1) * sizeof(_Sagan_BroIntel_Intel_User_Name));
                            To_LowerC(value);
                            strlcpy(Sagan_BroIntel_Intel_User_Name[counters->brointel_user_name_count].username, value, sizeof(Sagan_BroIntel_Intel_User_Name[counters->brointel_user_name_count].username));
                            counters->brointel_user_name_count++;
                            found_flag = 1;
                        }

                    if (!strcmp(type, "Intel::FILE_NAME") && found_flag == 0)
                        {
                            Sagan_BroIntel_Intel_File_Name = (_Sagan_BroIntel_Intel_File_Name *) realloc(Sagan_BroIntel_Intel_File_Name, (counters->brointel_file_name_count+1) * sizeof(_Sagan_BroIntel_Intel_File_Name));
                            To_LowerC(value);
                            strlcpy(Sagan_BroIntel_Intel_File_Name[counters->brointel_file_name_count].file_name, value, sizeof(Sagan_BroIntel_Intel_File_Name[counters->brointel_file_name_count].file_name));
                            counters->brointel_file_name_count++;
                            found_flag = 1;
                        }

                    if (!strcmp(type, "Intel::CERT_HASH") && found_flag == 0)
                        {
                            Sagan_BroIntel_Intel_Cert_Hash = (_Sagan_BroIntel_Intel_Cert_Hash *) realloc(Sagan_BroIntel_Intel_Cert_Hash, (counters->brointel_cert_hash_count+1) * sizeof(_Sagan_BroIntel_Intel_Cert_Hash));
                            To_LowerC(value);
                            strlcpy(Sagan_BroIntel_Intel_Cert_Hash[counters->brointel_cert_hash_count].cert_hash, value, sizeof(Sagan_BroIntel_Intel_Cert_Hash[counters->brointel_cert_hash_count].cert_hash));
                            counters->brointel_cert_hash_count++;
                            found_flag = 1;
                        }


                }

            line_count++;

        }
    fclose(brointel_file);

}

/*****************************************************************************
 * Sagan_BroIntel_IPADDR - Search array for blacklisted IP addresses
 *****************************************************************************/

int Sagan_BroIntel_IPADDR ( uint32_t ip )
{

    int i;

    /* If RFC1918,  we can short circuit here */

    if ( is_rfc1918(ip))
        {

            if ( debug->debugbrointel )
                {
                    Sagan_Log(S_DEBUG, "[%s, line %d] %u is RFC1918.", __FILE__, __LINE__, ip);
                }

            return(FALSE);
        }

    /* Search array for for the IP address */

    for ( i = 0; i < counters->brointel_addr_count; i++)
        {

            if ( Sagan_BroIntel_Intel_Addr[i].u32_ip == ip )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found IP %u.", __FILE__, __LINE__, ip);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);

}

/*****************************************************************************
 * Sagan_BroIntel_DOMAIN - Search DOMAIN array
 *****************************************************************************/

int Sagan_BroIntel_DOMAIN ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_domain_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_Domain[i].domain, FALSE) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found domain %s.", __FILE__, __LINE__, Sagan_BroIntel_Intel_Domain[i].domain);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);

}

/*****************************************************************************
 * Sagan_BroIntel_FILE_HASH - Search FILE_HASH array
 *****************************************************************************/

int Sagan_BroIntel_FILE_HASH ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_file_hash_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_File_Hash[i].hash, FALSE) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found file hash %s.", __FILE__, __LINE__, Sagan_BroIntel_Intel_File_Hash[i].hash);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);

}

/*****************************************************************************
 * Sagan_BroIntel_URL - Search URL array
 *****************************************************************************/

int Sagan_BroIntel_URL ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_url_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_URL[i].url, FALSE) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found URL \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_URL[i].url);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);
}

/*****************************************************************************
 * Sagan_BroIntel_SOFTWARE - Search SOFTWARE array
 ****************************************************************************/

int Sagan_BroIntel_SOFTWARE ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_software_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_Software[i].software, FALSE) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found software \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_Software[i].software);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);
}

/*****************************************************************************
 * Sagan_BroIntel_EMAIL - Search EMAIL array
 *****************************************************************************/

int Sagan_BroIntel_EMAIL ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_email_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_Email[i].email, FALSE) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found e-mail address \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_Email[i].email);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);
}

/*****************************************************************************
 * Sagan_BroIntel_USER_NAME - Search USER_NAME array
 ****************************************************************************/

int Sagan_BroIntel_USER_NAME ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_user_name_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_User_Name[i].username, FALSE) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found the username \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_User_Name[i].username);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);
}

/****************************************************************************
 * Sagan_BroIntel_FILE_NAME - Search FILE_NAME array
 ****************************************************************************/

int Sagan_BroIntel_FILE_NAME ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_file_name_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_File_Name[i].file_name, FALSE) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found the file name \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_File_Name[i].file_name);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);
}

/***************************************************************************
 * Sagan_BroIntel_CERT_HASH - Search CERT_HASH array
 ***************************************************************************/

int Sagan_BroIntel_CERT_HASH ( char *syslog_message )
{

    int i;

    for ( i = 0; i < counters->brointel_cert_hash_count; i++)
        {

            if ( Sagan_stristr(syslog_message, Sagan_BroIntel_Intel_Cert_Hash[i].cert_hash, FALSE) )
                {
                    if ( debug->debugbrointel )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Found the CERT_HASH \"%s\".", __FILE__, __LINE__, Sagan_BroIntel_Intel_Cert_Hash[i].cert_hash);
                        }

                    return(TRUE);
                }

        }

    return(FALSE);
}

