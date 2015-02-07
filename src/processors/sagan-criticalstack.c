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

#include <stdio.h>
#include <unistd.h>
#include <string.h>


#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "parsers/parsers.h"

#include "processors/sagan-criticalstack.h"

#define MAX_CRITICALSTACK_LINE_SIZE 10240

struct _SaganConfig *config;
struct _SaganCounters *counters;
struct _SaganDebug *debug;

struct _Sagan_Processor_Info *processor_info_criticalstack = NULL;

struct _Sagan_CriticalStack_Intel_Addr *Sagan_CriticalStack_Intel_Addr;
struct _Sagan_CriticalStack_Intel_Domain *Sagan_CriticalStack_Intel_Domain;
struct _Sagan_CriticalStack_Intel_File_Hash *Sagan_CriticalStack_Intel_File_Hash;
struct _Sagan_CriticalStack_Intel_URL *Sagan_CriticalStack_Intel_URL;
struct _Sagan_CriticalStack_Intel_Software *Sagan_CriticalStack_Intel_Software;
struct _Sagan_CriticalStack_Intel_Email *Sagan_CriticalStack_Intel_Email;
struct _Sagan_CriticalStack_Intel_User_Name *Sagan_CriticalStack_Intel_User_Name;
struct _Sagan_CriticalStack_Intel_File_Name *Sagan_CriticalStack_Intel_File_Name;
struct _Sagan_CriticalStack_Intel_Cert_Hash *Sagan_CriticalStack_Intel_Cert_Hash;

/*****************************************************************************
 * Sagan_CriticalStack_Init - Sets up globals.  Not really used yet. 
 *****************************************************************************/

void Sagan_CriticalStack_Init(void) 
{ 

    processor_info_criticalstack = malloc(sizeof(struct _Sagan_Processor_Info));
    memset(processor_info_criticalstack, 0, sizeof(_Sagan_Processor_Info));

    /* This really isn't being used (yet)? */
    
    processor_info_criticalstack->processor_name          =       CRITICALSTACK_PROCESSOR_NAME;
    processor_info_criticalstack->processor_generator_id  =       CRITICALSTACK_PROCESSOR_GENERATOR_ID;
    processor_info_criticalstack->processor_name          =       CRITICALSTACK_PROCESSOR_NAME;
    processor_info_criticalstack->processor_facility      =       CRITICALSTACK_PROCESSOR_FACILITY;
    processor_info_criticalstack->processor_priority      =       CRITICALSTACK_PROCESSOR_PRIORITY;
    processor_info_criticalstack->processor_pri           =       CRITICALSTACK_PROCESSOR_PRI;
    processor_info_criticalstack->processor_class         =       CRITICALSTACK_PROCESSOR_CLASS;
    processor_info_criticalstack->processor_tag           =       CRITICALSTACK_PROCESSOR_TAG;
    processor_info_criticalstack->processor_rev           =       CRITICALSTACK_PROCESSOR_REV;
    
} 

/*****************************************************************************
 * Sagan_CriticalStack_Load_File - Loads CriticalStack data and splits it up
 * into different arrays.
 * ***************************************************************************/

void Sagan_CriticalStack_Load_File(void)
{

FILE *criticalstack_file;

char *value;
char *type; 
char *description;

sbool found_flag; 

char *tok;

int line_count;

char criticalstackbuf[MAX_CRITICALSTACK_LINE_SIZE] = { 0 }; 

	if (( criticalstack_file = fopen(config->criticalstack_file, "r")) == NULL ) 
		{
			Sagan_Log(S_ERROR, "[%s, line %d] Could not load Critical Threats file! (%s)", __FILE__, __LINE__, config->criticalstack_file);
		}

	while(fgets(criticalstackbuf, MAX_CRITICALSTACK_LINE_SIZE, criticalstack_file) != NULL)
		{
		
		/* Skip comments and blank linkes */

		if (criticalstackbuf[0] == '#' || criticalstackbuf[0] == 10 || criticalstackbuf[0] == ';' || criticalstackbuf[0] == 32 )
			{
			continue;
			} else { 

			Remove_Return(criticalstackbuf); 

			value = strtok_r(criticalstackbuf, "\t", &tok); 
			type = strtok_r(NULL, "\t", &tok);
			description = strtok_r(NULL, "\t", &tok);

			if ( value == NULL || type == NULL || description == NULL ) { 
				Sagan_Log(S_WARN, "[%s, line %d] Got invalid line at %d in %s", __FILE__, __LINE__, line_count, config->criticalstack_file); 
				}

			found_flag = 0; 

			if (!strcmp(type, "Intel::ADDR")) 
				{
				Sagan_CriticalStack_Intel_Addr = (_Sagan_CriticalStack_Intel_Addr *) realloc(Sagan_CriticalStack_Intel_Addr, (counters->criticalstack_addr_count+1) * sizeof(_Sagan_CriticalStack_Intel_Addr));
				Sagan_CriticalStack_Intel_Addr[counters->criticalstack_addr_count].u32_ip = IP2Bit(value); 
				counters->criticalstack_addr_count++; 
				found_flag = 1; 
				}

			if (!strcmp(type, "Intel::DOMAIN") && found_flag == 0) 
				{ 
                                Sagan_CriticalStack_Intel_Domain = (_Sagan_CriticalStack_Intel_Domain *) realloc(Sagan_CriticalStack_Intel_Domain, (counters->criticalstack_domain_count+1) * sizeof(_Sagan_CriticalStack_Intel_Domain));
				To_LowerC(value);
				strlcpy(Sagan_CriticalStack_Intel_Domain[counters->criticalstack_domain_count].domain, value, sizeof(Sagan_CriticalStack_Intel_Domain[counters->criticalstack_domain_count].domain)); 
				counters->criticalstack_domain_count++; 
				found_flag = 1;
				}

			if (!strcmp(type, "Intel::FILE_HASH") && found_flag == 0) 
				{
				Sagan_CriticalStack_Intel_File_Hash = (_Sagan_CriticalStack_Intel_File_Hash *) realloc(Sagan_CriticalStack_Intel_File_Hash, (counters->criticalstack_file_hash_count+1) * sizeof(_Sagan_CriticalStack_Intel_File_Hash));
				To_LowerC(value); 
				strlcpy(Sagan_CriticalStack_Intel_File_Hash[counters->criticalstack_file_hash_count].hash, value, sizeof(Sagan_CriticalStack_Intel_File_Hash[counters->criticalstack_file_hash_count].hash)); 
				counters->criticalstack_file_hash_count++; 
				found_flag = 1; 
				}
				

			if (!strcmp(type, "Intel::URL") && found_flag == 0) 
				{ 
                                Sagan_CriticalStack_Intel_URL = (_Sagan_CriticalStack_Intel_URL *) realloc(Sagan_CriticalStack_Intel_URL, (counters->criticalstack_url_count+1) * sizeof(_Sagan_CriticalStack_Intel_URL));
				To_LowerC(value); 
				strlcpy(Sagan_CriticalStack_Intel_URL[counters->criticalstack_url_count].url, value, sizeof(Sagan_CriticalStack_Intel_URL[counters->criticalstack_url_count].url));
				counters->criticalstack_url_count++;
				found_flag = 1; 
				}


                        if (!strcmp(type, "Intel::SOFTWARE") && found_flag == 0)                                  
				{
                                Sagan_CriticalStack_Intel_Software = (_Sagan_CriticalStack_Intel_Software *) realloc(Sagan_CriticalStack_Intel_Software, (counters->criticalstack_software_count+1) * sizeof(_Sagan_CriticalStack_Intel_Software));
				To_LowerC(value);
				strlcpy(Sagan_CriticalStack_Intel_Software[counters->criticalstack_software_count].software, value, sizeof(Sagan_CriticalStack_Intel_Software[counters->criticalstack_software_count].software));
				counters->criticalstack_software_count++;                                  
				found_flag = 1;
				}

			if (!strcmp(type, "Intel::EMAIL") && found_flag == 0)
				{
				Sagan_CriticalStack_Intel_Email = (_Sagan_CriticalStack_Intel_Email *) realloc(Sagan_CriticalStack_Intel_Email, (counters->criticalstack_email_count+1) * sizeof(_Sagan_CriticalStack_Intel_Email));
				To_LowerC(value);
				strlcpy(Sagan_CriticalStack_Intel_Email[counters->criticalstack_email_count].email, value, sizeof(Sagan_CriticalStack_Intel_Email[counters->criticalstack_email_count].email));
				counters->criticalstack_email_count++;
				found_flag = 1; 
				}

			
			if (!strcmp(type, "Intel::USER_NAME") && found_flag == 0)
				{
				Sagan_CriticalStack_Intel_User_Name = (_Sagan_CriticalStack_Intel_User_Name *) realloc(Sagan_CriticalStack_Intel_User_Name, (counters->criticalstack_user_name_count+1) * sizeof(_Sagan_CriticalStack_Intel_User_Name));
				To_LowerC(value); 
				strlcpy(Sagan_CriticalStack_Intel_User_Name[counters->criticalstack_user_name_count].username, value, sizeof(Sagan_CriticalStack_Intel_User_Name[counters->criticalstack_user_name_count].username));
				counters->criticalstack_user_name_count++;
				found_flag = 1; 
				}

			if (!strcmp(type, "Intel::FILE_NAME") && found_flag == 0)
				{
				Sagan_CriticalStack_Intel_File_Name = (_Sagan_CriticalStack_Intel_File_Name *) realloc(Sagan_CriticalStack_Intel_File_Name, (counters->criticalstack_file_name_count+1) * sizeof(_Sagan_CriticalStack_Intel_File_Name));
				To_LowerC(value); 
				strlcpy(Sagan_CriticalStack_Intel_File_Name[counters->criticalstack_file_name_count].file_name, value, sizeof(Sagan_CriticalStack_Intel_File_Name[counters->criticalstack_file_name_count].file_name));
				counters->criticalstack_file_name_count++;
				found_flag = 1; 
				}

			if (!strcmp(type, "Intel::CERT_HASH") && found_flag == 0)
				{
				Sagan_CriticalStack_Intel_Cert_Hash = (_Sagan_CriticalStack_Intel_Cert_Hash *) realloc(Sagan_CriticalStack_Intel_Cert_Hash, (counters->criticalstack_cert_hash_count+1) * sizeof(_Sagan_CriticalStack_Intel_Cert_Hash));
				To_LowerC(value);
				strlcpy(Sagan_CriticalStack_Intel_Cert_Hash[counters->criticalstack_cert_hash_count].cert_hash, value, sizeof(Sagan_CriticalStack_Intel_Cert_Hash[counters->criticalstack_cert_hash_count].cert_hash));
				counters->criticalstack_cert_hash_count++;
				found_flag = 1; 
				}

			
			}

		line_count++; 

		}
	fclose(criticalstack_file);

}

/*****************************************************************************
 * Sagan_CriticalStack_IPADDR - Search array for blacklisted IP addresses
 *****************************************************************************/

int Sagan_CriticalStack_IPADDR ( uint32_t ip )
{

int i; 

/* If RFC1918,  we can short circuit here */

if ( is_rfc1918(ip)) { 
        
	if ( debug->debugcriticalstack )
	   {
	   Sagan_Log(S_DEBUG, "[%s, line %d] %u is RFC1918.", __FILE__, __LINE__, ip);
	   }

	return(0); 
	}

/* Search array for for the IP address */

for ( i = 0; i < counters->criticalstack_addr_count; i++) 
	{ 
	
	if ( Sagan_CriticalStack_Intel_Addr[i].u32_ip == ip ) 
		{
		if ( debug->debugcriticalstack ) 
			{
			Sagan_Log(S_DEBUG, "[%s, line %d] Found IP %u.", __FILE__, __LINE__, ip);
			}	

		return(1); 
		}
	
	}

return(0);

}

/*****************************************************************************
 * Sagan_CriticalStack_DOMAIN - Search DOMAIN array
 *****************************************************************************/

int Sagan_CriticalStack_DOMAIN ( char *syslog_message ) 
{

int i; 

for ( i = 0; i < counters->criticalstack_domain_count; i++) 
	{
	
	if ( Sagan_stristr(syslog_message, Sagan_CriticalStack_Intel_Domain[i].domain, FALSE) ) 
		{
		if ( debug->debugcriticalstack )
			{
			Sagan_Log(S_DEBUG, "[%s, line %d] Found domain %s.", __FILE__, __LINE__, Sagan_CriticalStack_Intel_Domain[i].domain);
			}

		return(1); 
		}

	}

return(0);

}

/*****************************************************************************
 * Sagan_CriticalStack_FILE_HASH - Search FILE_HASH array
 *****************************************************************************/

int Sagan_CriticalStack_FILE_HASH ( char *syslog_message )
{

int i; 

for ( i = 0; i < counters->criticalstack_file_hash_count; i++)
        {

        if ( Sagan_stristr(syslog_message, Sagan_CriticalStack_Intel_File_Hash[i].hash, FALSE) )
                {
                if ( debug->debugcriticalstack )
                        {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Found file hash %s.", __FILE__, __LINE__, Sagan_CriticalStack_Intel_File_Hash[i].hash);
                        }

                return(1);
                }

        }

return(0);

}

/*****************************************************************************
 * Sagan_CriticalStack_URL - Search URL array
 *****************************************************************************/

int Sagan_CriticalStack_URL ( char *syslog_message )
{

int i;

for ( i = 0; i < counters->criticalstack_url_count; i++)
        {

        if ( Sagan_stristr(syslog_message, Sagan_CriticalStack_Intel_URL[i].url, FALSE) )
                {
                if ( debug->debugcriticalstack )
                        {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Found URL \"%s\".", __FILE__, __LINE__, Sagan_CriticalStack_Intel_URL[i].url);
                        }

                return(1);
                }

        }

return(0);
}

/*****************************************************************************
 * Sagan_CriticalStack_SOFTWARE - Search SOFTWARE array
 ****************************************************************************/

int Sagan_CriticalStack_SOFTWARE ( char *syslog_message )
{

int i;

for ( i = 0; i < counters->criticalstack_software_count; i++)
        {

        if ( Sagan_stristr(syslog_message, Sagan_CriticalStack_Intel_Software[i].software, FALSE) )
                {
                if ( debug->debugcriticalstack )
                        {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Found software \"%s\".", __FILE__, __LINE__, Sagan_CriticalStack_Intel_Software[i].software);
                        }

                return(1);
                }

        }

return(0);
}

/*****************************************************************************
 * Sagan_CriticalStack_EMAIL - Search EMAIL array
 *****************************************************************************/

int Sagan_CriticalStack_EMAIL ( char *syslog_message )
{

int i;

for ( i = 0; i < counters->criticalstack_email_count; i++)
        {

        if ( Sagan_stristr(syslog_message, Sagan_CriticalStack_Intel_Email[i].email, FALSE) )
                {
                if ( debug->debugcriticalstack )
                        {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Found e-mail address \"%s\".", __FILE__, __LINE__, Sagan_CriticalStack_Intel_Email[i].email);
                        }

                return(1);
                }

        }

return(0);
}

/*****************************************************************************
 * Sagan_CriticalStack_USER_NAME - Search USER_NAME array
 ****************************************************************************/

int Sagan_CriticalStack_USER_NAME ( char *syslog_message )
{

int i;

for ( i = 0; i < counters->criticalstack_user_name_count; i++)
        {

        if ( Sagan_stristr(syslog_message, Sagan_CriticalStack_Intel_User_Name[i].username, FALSE) )
                {
                if ( debug->debugcriticalstack )
                        {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Found the username \"%s\".", __FILE__, __LINE__, Sagan_CriticalStack_Intel_User_Name[i].username);
                        }

                return(1);
                }

        }

return(0);
}

/****************************************************************************
 * Sagan_CriticalStack_FILE_NAME - Search FILE_NAME array
 ****************************************************************************/

int Sagan_CriticalStack_FILE_NAME ( char *syslog_message )
{

int i;

for ( i = 0; i < counters->criticalstack_file_name_count; i++)
        {

        if ( Sagan_stristr(syslog_message, Sagan_CriticalStack_Intel_File_Name[i].file_name, FALSE) )
                {
                if ( debug->debugcriticalstack )
                        {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Found the file name \"%s\".", __FILE__, __LINE__, Sagan_CriticalStack_Intel_File_Name[i].file_name);
                        }

                return(1);
                }

        }

return(0);
}

/***************************************************************************
 * Sagan_CriticalStack_CERT_HASH - Search CERT_HASH array
 ***************************************************************************/

int Sagan_CriticalStack_CERT_HASH ( char *syslog_message )
{

int i;

for ( i = 0; i < counters->criticalstack_cert_hash_count; i++)
        {

        if ( Sagan_stristr(syslog_message, Sagan_CriticalStack_Intel_Cert_Hash[i].cert_hash, FALSE) )
                {
                if ( debug->debugcriticalstack )
                        {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Found the CERT_HASH \"%s\".", __FILE__, __LINE__, Sagan_CriticalStack_Intel_Cert_Hash[i].cert_hash);
                        }

                return(1);
                }

        }

return(0);
}

