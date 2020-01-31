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

/* util.c
 *
 * Various re-usable functions.
 *
 */


#include <stdio.h>
#include <stdlib.h>

#include "util-base64.h"

static const char *b64codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/********************************************************************************
 * Base64Encode - Returns a base64 encoded string.  This was taken from
 * Suricata.  I believe it was derived from Jouni Malinen work from:
 *
 * http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
 * http://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c
 *
 ********************************************************************************/

int Base64Encode(const unsigned char *in,  unsigned long inlen,
                 unsigned char *out, unsigned long *outlen)
{
    unsigned long i, len2, leven;
    unsigned char *p;
    if(in == NULL || out == NULL || outlen == NULL)
        {
            return -1;
        }
    /* valid output size ? */
    len2 = 4 * ((inlen + 2) / 3);
    if (*outlen < len2 + 1)
        {
            *outlen = len2 + 1;
            return -1;
        }
    p = out;
    leven = 3*(inlen / 3);
    for (i = 0; i < leven; i += 3)
        {
            *p++ = b64codes[(in[0] >> 2) & 0x3F];
            *p++ = b64codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
            *p++ = b64codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
            *p++ = b64codes[in[2] & 0x3F];
            in += 3;
        }

    /* Pad it if necessary...  */
    if (i < inlen)
        {
            unsigned a = in[0];
            unsigned b = (i+1 < inlen) ? in[1] : 0;

            *p++ = b64codes[(a >> 2) & 0x3F];
            *p++ = b64codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
            *p++ = (i+1 < inlen) ? b64codes[(((b & 0xf) << 2)) & 0x3F] : '=';
            *p++ = '=';
        }
    /* append a NULL byte */
    *p = '\0';
    /* return ok */
    *outlen = p - out;

    return 0;

}
