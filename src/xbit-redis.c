/* $Id$ */
/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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

/* xbit-redis.c - Redis stored xbit support a la 'Suricata' style */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "ipc.h"
#include "xbit.h"
#include "xbit-redis.h"
#include "rules.h"
#include "sagan-config.h"
//#include "util-time.h"

#define 	REDIS_PREFIX	"sagan"

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct _Sagan_Redis *SaganRedis;

pthread_cond_t SaganRedisDoWork;
pthread_mutex_t SaganRedisWorkMutex;

int redis_msgslot;

void Xbit_Set_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, char *syslog_message )
{

    int r;
    uint32_t hash;

    for (r = 0; r < rulestruct[rule_position].xbit_set_count; r++)
        {

            if ( rulestruct[rule_position].xbit_type[r] == XBIT_SET )
                {

                    hash = Xbit_Direction( rule_position, r, ip_src_char, ip_dst_char );

                    snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                             "SET %s:%s:%u \"TESTING\" EX %d", REDIS_PREFIX, rulestruct[rule_position].xbit_name, hash, rulestruct[rule_position].xbit_expire[r]);

                    redis_msgslot++;

                    pthread_cond_signal(&SaganRedisDoWork);
                    pthread_mutex_unlock(&SaganRedisWorkMutex);

                }
            else
                {


                    Sagan_Log(WARN, "Out of Redis 'writer' threads for 'set'.  Skipping!");
                    __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);
                }

        }


}

