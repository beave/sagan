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

/* sagan-strstr-hook.c
 *
 * This "hooks" in the "Sagan_strstr" function for CPUs supporting SSE2.
 * This code is based on work by Ondra Bílk and the glibc projects.
 *
 * His code/original post can be found at:
 *
 * http://comments.gmane.org/gmane.comp.lib.glibc.alpha/34531
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "parsers/strstr-asm/strstr-hook.h"

#ifndef WITH_SYSSTRSTR 		/* If NOT using system built in strstr */

#if defined(HAVE_SSE2) && SIZEOF_SIZE_T == 8  	/* And our CPU supports SSE2 & is the CPU 64 bit */

static void* function_func[]= {  __strstr_sse2_unaligned, __strstr_sse42, NULL};

/* This function takes advantage of CPUs with SSE2 */

char *Sagan_strstr(const char *_x,const char *_y)
{
    char *x= (char*) _x, *y=(char*)_y;
    char* (*fn)(char *,char *) = function_func[0];
    char * p=fn(x,y);
    return p;
}

#else

/*
 * Non-SSE2 CPUs get to use the pure C function.  This code is based
 * off Dale Moore mine3a.  Information can be found at:
 *
 * http://computer-programming-forum.com/47-c-language/69de641587bbb919.htm
 *
 */

char *Sagan_strstr(const char *_x, const char *_y)
{

    size_t    len = strlen (_y);
    if (!*_y) return (char *) _x;
    for (;;) {
        if (!(_x = strchr (_x, *_y))) return NULL;
        if (!strncmp (_x, _y, len)) return (char *) _x;
        _x++;
    }
}

#endif

/* This works similar to "strcasestr".  The "needle" (_y) is assumed to
 * already be converted to lowercase if "needle_lower" is FALSE.
 *
 * 0/FALSE == Don't convert needle
 * 1/TRUE  == Convert needle
 */

char *Sagan_stristr(const char *_x, const char *_y, bool needle_lower )
{

    char *p = NULL;
    char haystack_string[MAX_SYSLOGMSG] = { 0 };
    char needle_string[512] = { 0 };

    strlcpy(haystack_string, _x, sizeof(haystack_string));
    To_LowerC(haystack_string);

    strlcpy(needle_string, _y, sizeof(needle_string));

    if ( needle_lower ) {
        To_LowerC(needle_string);
    }

    p = Sagan_strstr( haystack_string, needle_string);

    return p;

}

#else

/****************************************************************************
 * To use the system standard strstr()
 ****************************************************************************/

char *Sagan_strstr(const char *_x, const char *_y)
{
    return (strstr(_x, _y));
}

char *Sagan_stristr(const char *_x, const char *_y, bool needle_lower )
{
    return (strcasestr(_x, _y));
}
#endif
