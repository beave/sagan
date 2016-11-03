/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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

/*
 * parse-hash.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>


#include "sagan.h"
#include "sagan-defs.h"
#include "version.h"
#include "sagan-config.h"
#include "parsers/parsers.h"

struct _SaganConfig *config;

char *Sagan_Parse_Hash(char *syslogmessage, int type)
{
    char tmpmsg[MAX_SYSLOGMSG];
    char *ptmp=NULL;
    char *tok=NULL;
    char *tmp = NULL;

    static __thread char ret[SHA256_HASH_SIZE+1];		/* Largest Hash */

    snprintf(tmpmsg, sizeof(tmpmsg), "%s", syslogmessage);

    ptmp = strtok_r(tmpmsg, " ", &tok);

    while (ptmp != NULL ) {

        tmp = Sagan_Parse_Hash_Cleanup(ptmp);

        if ( type == PARSE_HASH_MD5 || type == PARSE_HASH_ALL ) {
            if ( strlen(tmp) == MD5_HASH_SIZE ) {
                if ( Sagan_Validate_HEX(tmp) == true ) {
                    return(tmp);
                }
            }

        }

        else if ( type == PARSE_HASH_SHA1 || type == PARSE_HASH_ALL ) {
            if ( strlen(tmp) == SHA1_HASH_SIZE ) {
                if ( Sagan_Validate_HEX(tmp) == true ) {
                    strlcpy(ret, tmp, sizeof(ret));
                    return(ret);
                }
            }
        }

        else if ( type == PARSE_HASH_SHA256 || type == PARSE_HASH_ALL ) {
            if ( strlen(tmp) == SHA256_HASH_SIZE ) {
                if ( Sagan_Validate_HEX(tmp) == true ) {
                    strlcpy(ret, tmp, sizeof(ret));
                    return(tmp);
                }
            }
        }


        ptmp = strtok_r(NULL, " ", &tok);

    }

    return("\0");
}


char *Sagan_Parse_Hash_Cleanup(char *string)
{

    char tmp[512];
    int i;
    static __thread char in[512] = { 0 };
    char tmp2[2];

    strlcpy(in, string, sizeof(in));

    int len = strlen(in);

    if ( ( in[strlen(in) - 1] ) == ',' || ( in[strlen(in) - 1] ) == '\'' ) {
        strlcpy(tmp, in, len-1 );
        strlcpy(in, tmp, sizeof(in));
    }

    if ( in[0] == ',' || in[0] == '\'' || in[0] == ':' ) {

        tmp[0] = '\0';

        for(i=1; i < strlen(in); i++) {
            snprintf(tmp2, sizeof(tmp2), "%c", in[i]);
            strcat(tmp, tmp2);
        }

        strlcpy(in, tmp, sizeof(in));
    }

    return(in);

}


