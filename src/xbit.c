/* $Id$ */
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

/* xbit.c - Handles and routes requests for xbits via mmap() or redir */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "rules.h"

#include "xbit.h"
#include "xbit-mmap.h"

#ifdef HAVE_LIBHIREDIS

#include "redis.h"
#include "xbit-redis.h"

#endif

extern struct _Rule_Struct *rulestruct;
extern struct _SaganConfig *config;


/***************************************************/
/* Xbit_Set - "set", "unset" and "toggle" and xbit */
/***************************************************/

void Xbit_Set(int rule_position, char *ip_src_char, char *ip_dst_char, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

#ifdef HAVE_LIBHIREDIS

    if ( config->redis_flag && config->xbit_storage == XBIT_STORAGE_REDIS )
        {
            Xbit_Set_Redis(rule_position, ip_src_char, ip_dst_char, SaganProcSyslog_LOCAL );
            return;
        }

#endif

    Xbit_Set_MMAP(rule_position, ip_src_char, ip_dst_char, SaganProcSyslog_LOCAL->syslog_message );

}

/*********************************************************************************/
/* Xbit_Return_Tracking_Hash - Used by mmap() xbit tracking. This is used to     */
/* determine the direction an xbit and returns a hash for association            */
/*********************************************************************************/

uint32_t Xbit_Return_Tracking_Hash ( int rule_position, int xbit_position, char *ip_src_char, char *ip_dst_char )
{

    char hash_pair[MAXIP*2] = { 0 };

    if ( rulestruct[rule_position].xbit_direction[xbit_position] == 1 )
        {
            return(Djb2_Hash(ip_src_char));
        }

    else if ( rulestruct[rule_position].xbit_direction[xbit_position] == 2 )
        {
            return(Djb2_Hash(ip_dst_char));
        }

    else if (  rulestruct[rule_position].xbit_direction[xbit_position] == 3 )
        {
            snprintf(hash_pair, sizeof(hash_pair), "%s:%s",  ip_src_char, ip_dst_char);
            return(Djb2_Hash(hash_pair));
        }


    /* Should never get here */

    Sagan_Log(WARN, "[%s, line %d] Bad xbit_direction for sid %" PRIu64 "", __FILE__, __LINE__, rulestruct[rule_position].s_sid);
    return(0);

}

/****************************************************************************/
/* Xbit_Condition - This handles xbit conditions like "isset", "issnotset". */
/****************************************************************************/

bool Xbit_Condition(int rule_position, char *ip_src_char, char *ip_dst_char)
{

#ifdef HAVE_LIBHIREDIS

    if ( config->redis_flag && config->xbit_storage == XBIT_STORAGE_REDIS )
        {
            return(Xbit_Condition_Redis(rule_position, ip_src_char, ip_dst_char));
        }

#endif

    return(Xbit_Condition_MMAP(rule_position, ip_src_char, ip_dst_char));

}

