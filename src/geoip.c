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

/* geoip.c
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
#include "geoip.h"
#include "sagan-config.h"

struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganCounters *counters;
struct _Sagan_GeoIP_Skip *GeoIP_Skip;

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
            Sagan_Log(ERROR, "Error loading Maxmind GeoIP data (%s).  Are you trying to load an older, non-GeoIP database?", config->geoip2_country_file);
        }

}

/*****************************************************************************
 * GeoIP2_Lookup_Country - Looks up the country and determines if
 * it is in/out of HOME_COUNTRY
 ****************************************************************************/

int GeoIP2_Lookup_Country( char *ipaddr, int rule_position, struct _GeoIP *GeoIP )
{

    int gai_error;
    int mmdb_error;
    int res;

    char *ptmp = NULL;
    char *tok = NULL;

    char tmp[1024] = { 0 };

    unsigned char ip_convert[MAXIPBIT] = { 0 };

    int i = 0;

    IP2Bit(ipaddr, ip_convert);

    if ( is_notroutable(ip_convert) || !strcmp( ipaddr, "0.0.0.0" ) )
        {
            if (debug->debuggeoip2)
                {
                    Sagan_Log(DEBUG, "[%s, line %d] IP address %s is not routable. Skipping GeoIP lookup.", __FILE__, __LINE__, ipaddr);
                }

            snprintf(GeoIP->country, sizeof(GeoIP->country), "%s", "NON_ROUTABLE");
            GeoIP->results = GEOIP_SKIP;
            return(GEOIP_SKIP);

        }

    for ( i = 0; i < counters->geoip_skip_count; i++ )
        {

            if ( is_inrange(ip_convert, (unsigned char *)&GeoIP_Skip[i].range, 1) )
                {

                    if (debug->debuggeoip2)
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] IP address %s is in GeoIP 'skip_networks'. Skipping lookup.", __FILE__, __LINE__, ipaddr);
                        }

                    snprintf(GeoIP->country, sizeof(GeoIP->country), "%s", "SKIP");
                    GeoIP->results = GEOIP_SKIP;
                    return(GEOIP_SKIP);
                }

        }

    MMDB_lookup_result_s result = MMDB_lookup_string(&config->geoip2, ipaddr, &gai_error, &mmdb_error);
    MMDB_entry_data_s entry_data;

    res = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

    __atomic_add_fetch(&counters->geoip2_lookup, 1, __ATOMIC_SEQ_CST);

    if (res != MMDB_SUCCESS)
        {

            Sagan_Log(WARN, "Country code MMDB_get_value failure (%s) for %s.", MMDB_strerror(res), ipaddr);

            __atomic_add_fetch(&counters->geoip2_error, 1, __ATOMIC_SEQ_CST);

            snprintf(GeoIP->country, sizeof(GeoIP->country), "%s", "LOOKUP_FAILURE");
            GeoIP->results = GEOIP_SKIP;
            return(GEOIP_SKIP);

        }

    if ( !entry_data.has_data || entry_data.type != MMDB_DATA_TYPE_UTF8_STRING )
        {

            if ( debug->debuggeoip2 )
                {
                    Sagan_Log(DEBUG, "Country code for %s not found in GeoIP DB", ipaddr);
                }

            snprintf(GeoIP->country, sizeof(GeoIP->country), "%s", "NOT_FOUND");
            GeoIP->results = GEOIP_SKIP;
            return(GEOIP_SKIP);
        }

    strlcpy(GeoIP->country, entry_data.utf8_string, 3);
    strlcpy(tmp, rulestruct[rule_position].geoip2_country_codes, sizeof(tmp));

    MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL);

    if ( entry_data.has_data )
        {
            strlcpy(GeoIP->city, entry_data.utf8_string, entry_data.data_size+1);
        }

    MMDB_get_value(&result.entry, &entry_data, "subdivisions", "0", "iso_code", NULL);

    if ( entry_data.has_data )
        {
            strlcpy(GeoIP->subdivision, entry_data.utf8_string, entry_data.data_size+1);
        }

    MMDB_get_value(&result.entry, &entry_data, "postal", "code", NULL);

    if ( entry_data.has_data )
        {
            strlcpy(GeoIP->postal, entry_data.utf8_string, entry_data.data_size+1);
        }

    MMDB_get_value(&result.entry, &entry_data, "location", "time_zone", NULL);

    if ( entry_data.has_data )
        {
            strlcpy(GeoIP->timezone, entry_data.utf8_string, entry_data.data_size+1);
        }

    MMDB_get_value(&result.entry, &entry_data, "location", "latitude", NULL);

    if ( entry_data.has_data )
        {
            snprintf(GeoIP->latitude, sizeof(GeoIP->latitude), "%f", entry_data.double_value);
            GeoIP->latitude[ sizeof(GeoIP->latitude) - 1 ] = '\0';
        }

    MMDB_get_value(&result.entry, &entry_data, "location", "longitude", NULL);

    if ( entry_data.has_data )
        {
            snprintf(GeoIP->longitude, sizeof(GeoIP->longitude), "%f", entry_data.double_value);
            GeoIP->longitude[ sizeof(GeoIP->longitude) - 1 ] = '\0';
        }

    if (debug->debuggeoip2)
        {
            Sagan_Log(DEBUG, "----------------------------------------------------------------");
            Sagan_Log(DEBUG, "GeoIP Lookup IP               : %s", ipaddr);
            Sagan_Log(DEBUG, "Country                       : %s", GeoIP->country);
            Sagan_Log(DEBUG, "City                          : %s", GeoIP->city);
            Sagan_Log(DEBUG, "Subdivision                   : %s", GeoIP->subdivision);
            Sagan_Log(DEBUG, "Postal Code                   : %s", GeoIP->postal);
            Sagan_Log(DEBUG, "Timezone                      : %s", GeoIP->timezone);
            Sagan_Log(DEBUG, "Longitude                     : %s", GeoIP->longitude);
            Sagan_Log(DEBUG, "Latitude                      : %s", GeoIP->latitude);
            Sagan_Log(DEBUG, "User Defined Country Codes    : %s", rulestruct[rule_position].geoip2_country_codes);
        }


    ptmp = strtok_r(tmp, ",", &tok);

    while (ptmp != NULL )
        {
            if (debug->debuggeoip2)
                {
                    Sagan_Log(DEBUG, "GeoIP rule string parsing     : %s|%s", ptmp, GeoIP->country);
                }

            if (!strcmp(ptmp, GeoIP->country))
                {
                    if (debug->debuggeoip2)
                        {
                            Sagan_Log(DEBUG, "GeoIP Status: Found in user defined values [%s].", GeoIP->country);
                        }

                    GeoIP->results = GEOIP_HIT;

                    return(GEOIP_HIT);  /* GeoIP was found / there was a hit */
                }

            ptmp = strtok_r(NULL, ",", &tok);
        }

    if (debug->debuggeoip2) Sagan_Log(DEBUG, "GeoIP Status: Not found in user defined values.");

    GeoIP->results = GEOIP_MISS;
    return(GEOIP_MISS);
}

#endif

