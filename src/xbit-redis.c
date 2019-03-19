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

#define 	REDIS_PREFIX	"sagan"

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

struct _Sagan_Redis *SaganRedis;

pthread_cond_t SaganRedisDoWork;
pthread_mutex_t SaganRedisWorkMutex;

int redis_msgslot;

/*******************************************************/
/* Xbit_Set_Redis - set/unset xbit in Redis (threaded) */
/*******************************************************/

void Xbit_Set_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, char *syslog_message )
{

    int r;
    uint32_t hash;


    for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
        {

            if ( rulestruct[rule_position].xbit_type[r] == XBIT_SET )
                {

                    hash = Xbit_Direction( rule_position, r, ip_src_char, ip_dst_char );

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' set in Redis for %d seconds [hash: %u]", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], rulestruct[rule_position].xbit_expire[r], hash);
                        }

                    snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                             "SET %s:%s:%u \"sensor:%s,expire:%d\" EX %d", REDIS_PREFIX, rulestruct[rule_position].xbit_name[r], hash, config->sagan_sensor_name, rulestruct[rule_position].xbit_expire[r], rulestruct[rule_position].xbit_expire[r]);

                    redis_msgslot++;

                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {

                            pthread_cond_signal(&SaganRedisDoWork);
                            pthread_mutex_unlock(&SaganRedisWorkMutex);

                        }
                    else
                        {

                            Sagan_Log(WARN, "[%s, line %d] Out of Redis 'writer' threads for 'set'.  Skipping!", __FILE__, __LINE__);
                            __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);
                        }

                }

            else if ( rulestruct[rule_position].xbit_type[r] == XBIT_UNSET )
                {

                    hash = Xbit_Direction( rule_position, r, ip_src_char, ip_dst_char );

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' unset in Redis [hash: %u]", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], hash);
                        }

                    snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                             "DEL %s:%s:%u \"sensor:%s,expire:%d\"", REDIS_PREFIX, rulestruct[rule_position].xbit_name[r], hash, config->sagan_sensor_name, rulestruct[rule_position].xbit_expire[r]);

                    redis_msgslot++;

                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {
                            pthread_cond_signal(&SaganRedisDoWork);
                            pthread_mutex_unlock(&SaganRedisWorkMutex);
                        }
                    else
                        {
                            Sagan_Log(WARN, "[%s, line %d] Out of Redis 'writer' threads for 'set'.  Skipping!", __FILE__, __LINE__);
                            __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);
                        }
                }
        }
}

/****************************************************************/
/* Xbit_Condition_Redis - Tests for Redis xbit (isset/isnotset) */
/****************************************************************/

bool Xbit_Condition_Redis(int rule_position, char *ip_src_char, char *ip_dst_char )
{

    int r;
    uint32_t hash;
    char redis_command[64] = { 0 };
    char redis_results[32] = { 0 };
    bool xbit_match = false;

    for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
        {

            if ( rulestruct[rule_position].xbit_type[r] == XBIT_ISSET ||
                    rulestruct[rule_position].xbit_type[r] == XBIT_ISNOTSET )
                {
                    hash = Xbit_Direction( rule_position, r, ip_src_char, ip_dst_char );

                    snprintf(redis_command, sizeof(redis_command),
                             "GET %s:%s:%u", REDIS_PREFIX, rulestruct[rule_position].xbit_name[r], hash);

                    Redis_Reader ( (char *)redis_command, redis_results, sizeof(redis_results) );

                    if ( redis_results[0] == ' ' && rulestruct[rule_position].xbit_type[r] == XBIT_ISSET )
                        {

                            if ( debug->debugxbit )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] '%s' was not found for isset. Returning false. [hash: %u]", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], hash);
                                }

                            return(false);
                        }

                    if ( redis_results[0] != ' ' && rulestruct[rule_position].xbit_type[r] == XBIT_ISNOTSET )
                        {

                            if ( debug->debugxbit )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] '%s' was found for isnotset. Returning false. [hash: %u]", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], hash);
                                }


                            return(false);
                        }

                }
        }

    if ( debug->debugxbit )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Rule matches all xbit conditions. Returning true.", __FILE__, __LINE__);
        }


    return(true);

}

