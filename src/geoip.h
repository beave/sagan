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

/* geoip.h
 *
 * Sagan GeoIP prototypes
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

//#ifdef HAVE_LIBMAXMINDDB

#define GEOIP_MISS	0
#define GEOIP_HIT	1
#define GEOIP_SKIP	2

typedef struct _GeoIP _GeoIP;
struct _GeoIP
{

    unsigned char results;

    char city[32];
    char country[32];
    char subdivision[3];
    char postal[16];
    char timezone[32];
    char latitude[16];
    char longitude[16];

};


typedef struct _Sagan_GeoIP_Skip _Sagan_GeoIP_Skip;
struct _Sagan_GeoIP_Skip
{

    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;

};

void Open_GeoIP2_Database( void );
int GeoIP2_Lookup_Country( char *ipaddr, int rule_position, struct _GeoIP *GeoIP );


//#endif

