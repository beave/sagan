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

/* geoip2.c
 *
 * Functions that handle GeoIP2 lookup's via the Maxmind database.   For more
 * information, please see:
 *
 * https://www.maxmind.com/en/geoip2-country-database  (For free/pay databases)
 * http://dev.maxmind.com/geoip/geoip2/geolite2/ (free database)
 *
 * You _must_ use the GeoIP2 database and not the legacy GeoIP databases!
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBMAXMINDDB

#include <stdio.h>
#include <string.h>
#include <maxminddb.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "geoip2.h"
#include "sagan-config.h"

struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganCounters *counters;

pthread_mutex_t CountGeoIP2MissMutex=PTHREAD_MUTEX_INITIALIZER;

void Open_GeoIP2_Database( void )
{

    int status;

    /*
     * The GeoIP library gives a really vague error when it cannot load
     * the GeoIP database.  We give the user more information here so
     * that they might fix the issue.  This also serves as a test when
     * Sagan is reloading (SIGHUP) - Champ Clark III (04/20/2015)
     */

    status = access(config->geoip2_country_file, R_OK);

    if ( status != 0 )
        {
            Sagan_Log(WARN, "Cannot open '%s' [%s]!",  config->geoip2_country_file, strerror(errno));
            Sagan_Log(WARN, "Make sure the GeoIP database '%s' is readable by '%s'.", config->geoip2_country_file, config->sagan_runas);
            Sagan_Log(ERROR, "Sagan is NOT loading the GeoIP database data! Abort!");
        }

    status = MMDB_open(config->geoip2_country_file, MMDB_MODE_MMAP, &config->geoip2);

    if ( status != 0 )
        {
            Sagan_Log(ERROR, "Error loading Maxmind GeoIP2 data (%s).  Are you trying to load an older, non-GeoIP2 database?", config->geoip2_country_file);
        }

}

/*****************************************************************************
 * GeoIP2_Lookup_Country - Looks up the country and determines if
 * it is in/out of HOME_COUNTRY
 ****************************************************************************/

int GeoIP2_Lookup_Country( char *ipaddr, unsigned char *ip_bits, int rule_position )
{


    int gai_error;
    int mmdb_error;
    int res;

    char *ptmp = NULL;
    char *tok = NULL;

    char country[2];
    char tmp[1024];

    if ( is_notroutable(ip_bits) )
        {
            if (debug->debuggeoip2)
                {
                    Sagan_Log(DEBUG, "[%s, line %d] IP address %s is not routable. Skipping GeoIP2 lookup.", __FILE__, __LINE__, ipaddr);
                }

            return(false);
        }

    MMDB_lookup_result_s result = MMDB_lookup_string(&config->geoip2, ipaddr, &gai_error, &mmdb_error);
    MMDB_entry_data_s entry_data;

    res = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

    if (res != MMDB_SUCCESS)
        {
            pthread_mutex_lock(&CountGeoIP2MissMutex);
            counters->geoip2_miss++;
            pthread_mutex_unlock(&CountGeoIP2MissMutex);

            Sagan_Log(WARN, "Country code MMDB_get_value failure (%s) for %s.", MMDB_strerror(res), ipaddr);
            return(false);

        }

    if (!entry_data.has_data || entry_data.type != MMDB_DATA_TYPE_UTF8_STRING)
        {

            pthread_mutex_lock(&CountGeoIP2MissMutex);
            counters->geoip2_miss++;
            pthread_mutex_unlock(&CountGeoIP2MissMutex);

            if ( debug->debuggeoip2 )
                {
                    Sagan_Log(DEBUG, "Country code for %s not found in GeoIP2 DB", ipaddr);
                }
            return(false);
        }

    strlcpy(country, entry_data.utf8_string, 3);
    strlcpy(tmp, rulestruct[rule_position].geoip2_country_codes, sizeof(tmp));

    if (debug->debuggeoip2)
        {
            Sagan_Log(DEBUG, "GeoIP Lookup IP  : %s", ipaddr);
            Sagan_Log(DEBUG, "Country Codes    : |%s|", rulestruct[rule_position].geoip2_country_codes);
            Sagan_Log(DEBUG, "Found in GeoIP DB: %s", country);
        }


    ptmp = strtok_r(tmp, ",", &tok);

    while (ptmp != NULL )
        {
            if (debug->debuggeoip2)
                {
                    Sagan_Log(DEBUG, "GeoIP2 rule string parsing %s|%s", ptmp, country);
                }

            if (!strcmp(ptmp, country))
                {
                    if (debug->debuggeoip2)
                        {
                            Sagan_Log(DEBUG, "GeoIP Status: Found in user defined values [%s].", country);
                        }

                    return(true);  /* GeoIP was found / there was a hit */
                }

            ptmp = strtok_r(NULL, ",", &tok);
        }

    if (debug->debuggeoip2) Sagan_Log(DEBUG, "GeoIP Status: Not found in user defined values.");

    return(false);
}

#endif

