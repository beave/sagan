/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-geoip.c
 *
 * Functions that handle GeoIP lookup's via the Maxmind database.   For more
 * information, please see:
 *
 * http://www.maxmind.com/en/country
 * http://dev.maxmind.com/geoip/geoip2/geolite2/
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBGEOIP

#include <stdio.h>
#include <GeoIP.h>
#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-geoip.h"


struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;

void Sagan_Open_GeoIP_Database( void ) { 
	
config->geoip = NULL; 

/* May want to provide option for GEOIP_STANDARD, GEOIP_MEMORY_CACHE,
 * GEOIP_CHECK_CACHE, GEOIP_INDEX_CACHE and GEOIP_MMAP_CACHE? */

config->geoip = GeoIP_open(config->geoip_country_file, GEOIP_MEMORY_CACHE);

if ( config->geoip == NULL ) Sagan_Log(S_ERROR, "[%s, line %d] Cannot open GeoIP datbase : %s", __FILE__, __LINE__, config->geoip_country_file);

}

int Sagan_GeoIP_Lookup_Country( char *ipaddr, int rule_position )  { 


char *ptmp = NULL;
char *tok = NULL; 
char tmp[512] = { 0 }; 
const char *str = NULL;

str = GeoIP_country_code_by_addr(config->geoip, ipaddr);
strlcpy(tmp, rulestruct[rule_position].geoip_country_codes, sizeof(tmp)); 

if ( str == NULL ) { 
	if (debug->debuggeoip) Sagan_Log(S_DEBUG, "Country code for %s not found in GeoIP DB", ipaddr); 
	return(0); 		/* GeoIP of the IP address not found */
	}

if (debug->debuggeoip) {
        Sagan_Log(S_DEBUG, "GeoIP Lookup IP  : %s", ipaddr);
        Sagan_Log(S_DEBUG, "Country Codes    : %s", rulestruct[rule_position].geoip_country_codes);
	Sagan_Log(S_DEBUG, "Found in GeoIP DB: %s", str);
        }

ptmp = strtok_r(tmp, ",", &tok);

while (ptmp != NULL ) {
	if (debug->debuggeoip) Sagan_Log(S_DEBUG, "GeoIP rule string parsing %s|%s", ptmp, str);
	if (!strcmp(ptmp, str)) {
		if (debug->debuggeoip) Sagan_Log(S_DEBUG, "GeoIP Status: Found [%s]", str);
		return(1);	/* GeoIP was found / there was a hit */
		}
	ptmp = strtok_r(NULL, ",", &tok);
	}

if (debug->debuggeoip) Sagan_Log(S_DEBUG, "GeoIP Status: Not found"); 

return(0);
}


#endif

