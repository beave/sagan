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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBLOGNORM

#include <json.h>

#include "sagan-defs.h"

/* liblognorm struct */
typedef struct liblognorm_struct liblognorm_struct;
struct liblognorm_struct
{
    char type[50];
    char filepath[MAXPATH];
};

typedef struct liblognorm_toload_struct liblognorm_toload_struct;
struct liblognorm_toload_struct
{
    char type[50];
    char filepath[MAXPATH];
};

typedef struct _SaganNormalizeLiblognorm
{

    bool status;

    char ip_src[MAXIP];
    char ip_dst[MAXIP];

    char src_host[MAXHOST];
    char dst_host[MAXHOST];

    int  src_port;
    int  dst_port;

    char username[MAX_USERNAME_SIZE];
    char filename[MAX_FILENAME_SIZE];

    char hash_md5[MD5_HASH_SIZE+1];
    char hash_sha1[SHA1_HASH_SIZE+1];
    char hash_sha256[SHA256_HASH_SIZE+1];

    char http_uri[MAX_URL_SIZE];
    char http_hostname[MAX_HOSTNAME_SIZE];

    char ja3[MD5_HASH_SIZE+1];
    char event_id[32];

    char json_normalize[JSON_MAX_SIZE];

} _SaganNormalizeLiblognorm;
#endif


void Liblognorm_Load( char * );
void Normalize_Liblognorm(char *, struct _SaganNormalizeLiblognorm *);
