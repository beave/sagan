/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>
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
 * xbit.c - Functions used for tracking events over multiple log
 * lines.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "xbit.h"
#include "xbit-mmap.h"

#ifdef HAVE_LIBHIREDIS

#include "redis.h"
#include "xbit-redis.h"

#endif

struct _SaganConfig *config;

bool Xbit_Condition(int rule_position, char *ip_src_char, char *ip_dst_char, int src_port, int dst_port, char *selector )
{

#ifdef HAVE_LIBHIREDIS

    if ( config->redis_flag && config->xbit_storage == XBIT_STORAGE_REDIS )
        {

            return(Xbit_Condition_Redis(rule_position, ip_src_char, ip_dst_char, src_port, dst_port, selector));
        }

#endif

    return(Xbit_Condition_MMAP(rule_position, ip_src_char, ip_dst_char, src_port, dst_port, selector));

}


bool Xbit_Count( int rule_position, char *ip_src_char, char *ip_dst_char, char *selector )
{

    return(Xbit_Count_MMAP(rule_position, ip_src_char, ip_dst_char, selector ));

}

void Xbit_Set(int rule_position, char *ip_src_char, char *ip_dst_char, int src_port, int dst_port, char *selector, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

#ifdef HAVE_LIBHIREDIS

    if ( config->redis_flag && config->xbit_storage == XBIT_STORAGE_REDIS )
        {

            Xbit_Set_Redis(rule_position, ip_src_char, ip_dst_char, src_port, dst_port, selector, SaganProcSyslog_LOCAL );
            return;
        }

#endif

    Xbit_Set_MMAP(rule_position, ip_src_char, ip_dst_char, src_port, dst_port, selector, SaganProcSyslog_LOCAL->syslog_message );

}


int Xbit_Type ( char *type, int linecount, const char *ruleset )
{

    if (!strcmp(type, "none"))
        {
            return(0);
        }

    if (!strcmp(type, "both"))
        {
            return(1);
        }

    if (!strcmp(type, "by_src"))
        {
            return(2);
        }

    if (!strcmp(type, "by_dst"))
        {
            return(3);
        }

    if (!strcmp(type, "reverse"))
        {
            return(4);
        }

    if (!strcmp(type, "src_xbitdst"))
        {
            return(5);
        }

    if (!strcmp(type, "dst_xbitsrc"))
        {
            return(6);
        }

    if (!strcmp(type, "both_p"))
        {
            return(7);
        }

    if (!strcmp(type, "by_src_p"))
        {
            return(8);
        }

    if (!strcmp(type, "by_dst_p"))
        {
            return(9);
        }

    if (!strcmp(type, "reverse_p"))
        {
            return(10);
        }

    if (!strcmp(type, "src_xbitdst_p"))
        {
            return(11);
        }

    if (!strcmp(type, "dst_xbitsrc_p"))
        {
            return(12);
        }

    Sagan_Log(ERROR, "[%s, line %d] Expected 'none', 'both', by_src', 'by_dst', 'reverse', 'src_xbitdst', 'dst_xbitsrc','both_p', by_src_p', 'by_dst_p', 'reverse_p', 'src_xbitdst_p', or 'dst_xbitsrc_p'.  Got '%s' at line %d.", __FILE__, __LINE__, type, linecount, ruleset);

    return(0); 	/* Should never make it here */

}

