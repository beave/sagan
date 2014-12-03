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

#include <string.h>
#include "sagan-strstr-hook.h"

#ifdef HAVE_SSE2

/* This function takes advantage of CPUs with SSE2 */

char *Sagan_strstr(const char *_x,const char *_y) 
{
	char *x= (char*) _x, *y=(char*)_y;
	char* (*fn)(char *,char *) = function_func[0];
	char * p=fn(x,y);
  	return p;
}

#else

/* Non-SSE2 CPUs get to use the pure C function */

char *Sagan_strstr(const char *_x, const char *_y) {
        size_t    len = strlen (_y);
        if (!*_y) return (char *) _x;
        for (;;) {
                if (!(_x = strchr (_x, *_y))) return NULL;
                if (!strncmp (_x, _y, len)) return (char *) _x;
                _x++;
        }
}

#endif
