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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBLOGNORM

#include "sagan-defs.h"

//#ifdef WITH_BLUEDOT
//#include "processors/sagan-bluedot.h"
//#endif

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
    char ip_src[MAXIP];
    char ip_dst[MAXIP];

    char src_host[MAXHOST];
    char dst_host[MAXHOST];

    int  src_port;
    int  dst_port;

    char username[MAX_USERNAME_SIZE];
    char filename[MAX_FILENAME_SIZE];
    char filehash_md5[MAX_HASH_SIZE];		
    char url[MAX_URL_SIZE];

} _SaganNormalizeLiblognorm;
#endif


void Sagan_Liblognorm_Load( void );
void Sagan_Normalize_Liblognorm( char *);
