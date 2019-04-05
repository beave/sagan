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

#ifdef HAVE_LIBHIREDIS

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

void Xbit_Set_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{


    int r = 0;
    int i = 0;
    uint32_t hash;
    char redis_results[32] = { 0 };
    char redis_command[64] = { 0 };
    char fullsyslog_orig[MAX_SYSLOGMSG] = { 0 };
    char tmp_date[32] = { 0 };
    char tmp_time[32] = { 0 };

    strlcpy(fullsyslog_orig,  SaganProcSyslog_LOCAL->syslog_message, sizeof(fullsyslog_orig));
    strlcpy(tmp_date,  SaganProcSyslog_LOCAL->syslog_date, sizeof(tmp_date));
    strlcpy(tmp_time,  SaganProcSyslog_LOCAL->syslog_time, sizeof(tmp_time));

    /* Because of the way we use Redis, spaces end up being a issue :(  With this
       in mind, we build our JSON with spaces replaced */

    for ( i = 0; i < strlen(fullsyslog_orig); i++ )
        {

            switch(fullsyslog_orig[i])
                {

                case ' ':
                    fullsyslog_orig[i] = '_';
                    break;

                case ';':
                    fullsyslog_orig[i] = ':';
                    break;

                }
        }

    for ( i = 0; i < strlen(tmp_date); i++ )
        {

            switch(tmp_date[i])
                {

                case ' ':
                    tmp_date[i] = '_';
                    break;

                case ';':
                    tmp_date[i] = ':';
                    break;

                }
        }

    for ( i = 0; i < strlen(tmp_time); i++ )
        {

            switch(tmp_time[i])
                {

                case ' ':
                    tmp_time[i] = '_';
                    break;

                case ';':
                    tmp_time[i] = ':';
                    break;

                }
        }


    for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
        {

            if ( rulestruct[rule_position].xbit_type[r] == XBIT_SET )
                {

                    hash = Xbit_Direction( rule_position, r, ip_src_char, ip_dst_char );

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' set in Redis for %d seconds [hash: %u]", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], rulestruct[rule_position].xbit_expire[r], hash);
                        }

                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {

                            pthread_mutex_lock(&SaganRedisWorkMutex);

                            snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                                     "SET %s:%s:%u {\"sensor\":\"%s\",\"expire\":%d,\"src-ip\":\"%s\",\"priority\":\"%s\",\"level\":\"%s\",\"facility\":\"%s\",\"tag\":\"%s\",\"date\":\"%s\",\"time\":\"%s\",\"program\":\"%s\",\"message\":\"%s\"} EX %d", REDIS_PREFIX, rulestruct[rule_position].xbit_name[r], hash, config->sagan_sensor_name, rulestruct[rule_position].xbit_expire[r], SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level, SaganProcSyslog_LOCAL->syslog_facility, SaganProcSyslog_LOCAL->syslog_tag, tmp_date, tmp_time, SaganProcSyslog_LOCAL->syslog_program, fullsyslog_orig, rulestruct[rule_position].xbit_expire[r]);


                            redis_msgslot++;

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


                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {

                            pthread_mutex_lock(&SaganRedisWorkMutex);

                            snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                                     "DEL %s:%s:%u \"sensor:%s,expire:%d\"", REDIS_PREFIX, rulestruct[rule_position].xbit_name[r], hash, config->sagan_sensor_name, rulestruct[rule_position].xbit_expire[r]);

                            redis_msgslot++;

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

#endif
