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
 * This code is based on work by Ondra B�lk and the glibc projects.
 *
 * His code/original post can be found at:
 *
 * http://comments.gmane.org/gmane.comp.lib.glibc.alpha/34531
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_SSE2
#ifndef WITH_SYSSTRSTR

int __strstr_sse2_unaligned();
int __strstr_sse42();

#endif
#endif

char *Sagan_strstr(const char *, const char *);
char *Sagan_stristr(const char *, const char *, bool);

