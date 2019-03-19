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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"

#include "rules.h"

#include "flexbit.h"
#include "flexbit-mmap.h"
#include "flexbit-redis.h"
#include "parsers/parsers.h"
#include "redis.h"
#include "util-time.h"

struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganCounters *counters;

int redis_msgslot;
pthread_cond_t SaganRedisDoWork;
pthread_mutex_t SaganRedisWorkMutex;

struct _Sagan_Redis *SaganRedis;

/****************************************************************
   README * README * README * README * README * README * README
   README * README * README * README * README * README * README
 ****************************************************************

 This is very PoC (proof of concept) code and is NOT production
 ready.  This is to test the functionality of using Redis as a
 backend to store "flexbits" (making them "global" xbits).

 ****************************************************************/

/*****************************************************************************
 Flexbit_Condition_Redis - Test the condition of flexbits.  For example,  "isset"
 and "isnotset"
 *****************************************************************************/

bool Flexbit_Condition_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, int src_port, int dst_port )
{

    int i;
    int j;

    int flexbit_total_match = 0;

    time_t t;
    struct tm *now;
    char  timet[20];

    redisReply *reply;

    char redis_command[1024] = { 0 };
    char redis_reply[32] = { 0 };

    uint32_t djb2_hash;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    char *src_or_dst = NULL;
    char *src_or_dst_type = NULL;

    /*
        if ( debug->debugredis )
            {
                Sagan_Log(DEBUG, "[%s, line %d] Redis Xbit Condition.", __FILE__, __LINE__);
            }
    */

    /* Cycle through flexbits in the rule */

    for (i = 0; i < rulestruct[rule_position].flexbit_count; i++)
        {

            /* Only dealing with isset and isnotset */

            if ( rulestruct[rule_position].flexbit_type[i] == 3 || rulestruct[rule_position].flexbit_type[i] == 4 )
                {

                    if ( rulestruct[rule_position].flexbit_direction[i] == 0 )
                        {

                            {
                                Sagan_Log(WARN, "[%s, line %d] Call for \"isset\" or \"isnotset\" flexbit \"%s\" with Redis is not supported! \"unset\" needs an IP source or destination", __FILE__, __LINE__, rulestruct[rule_position].flexbit_name[i]);
                            }

                        }

                    /*****************************************************************/
                    /* direction: both - this is the easiest as we have all the data */
                    /*****************************************************************/

                    else if ( rulestruct[rule_position].flexbit_direction[i] == 1 )
                        {

                            if ( debug->debugflexbit )
                                {
                                    Sagan_Log(DEBUG, "[%s, line %d] \"isset\" flexbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, rulestruct[rule_position].flexbit_name[i], ip_src_char, ip_dst_char);
                                }


                            snprintf(redis_command, sizeof(redis_command),
                                     "ZRANGEBYLEX %s:both [%s:%s [%s:%s",
                                     rulestruct[rule_position].flexbit_name[i], ip_src_char, ip_dst_char, ip_src_char, ip_dst_char);

                            Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

                            /* If the flexbit is found ... */

                            if ( redis_reply[0] != ' ' )
                                {

                                    /* isset */

                                    if ( rulestruct[rule_position].flexbit_type[i] == 3 )
                                        {

                                            if ( debug->debugflexbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Found flexbit '%s' for 'isset'.", __FILE__, __LINE__, rulestruct[rule_position].flexbit_name[i] );
                                                }

                                            /* No | in the rule,  so increment the match counter */

                                            flexbit_total_match++;

                                        } /* End of rulestruct[rule_position].flexbit_type[i] == 3 */

                                }
                            else      /* End of reply->str != NULL */
                                {

                                    /* No match was found */

                                    /* isnotset */

                                    if ( rulestruct[rule_position].flexbit_type[i] == 4 )
                                        {

                                            if ( debug->debugflexbit )
                                                {
                                                    Sagan_Log(DEBUG, "[%s, line %d] Did not find flexbit '%s' for 'isnotset'.", __FILE__, __LINE__, rulestruct[rule_position].flexbit_name[i] );
                                                }

                                            flexbit_total_match++;

                                        } /* End of rulestruct[rule_position].flexbit_type[i] == 4 */
                                }

                        } /* End of else reply->str != NULL */

                } /* End of if (rulestruct[rule_position].flexbit_direction[i] == 1 || both ) */

            /*******************************/
            /* direction: by_src || by_dst */
            /*******************************/

            /* Since by_src and by_dst similar Redis queries,  we handle both here */

            if ( rulestruct[rule_position].flexbit_direction[i] == 2 ||
                    rulestruct[rule_position].flexbit_direction[i] == 3 )
                {

                    if ( rulestruct[rule_position].flexbit_direction[i] == 2 )
                        {

                            src_or_dst = ip_src_char;
                            src_or_dst_type = "by_src";

                        }
                    else
                        {

                            src_or_dst = ip_dst_char;
                            src_or_dst_type = "by_dst";

                        }


                    snprintf(redis_command, sizeof(redis_command),
                             "ZRANGEBYLEX %s:%s [%s [%s",
                             rulestruct[rule_position].flexbit_name[i], src_or_dst_type,  src_or_dst, src_or_dst);

                    Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

                    /**************************************************************/
                    /* If nothing is found,  we can stop a lot of processing here.*/
                    /**************************************************************/

                    if ( redis_reply[0] != ' ' )
                        {

                            /* "isset" - If nothing is found then no need to continue */

                            if ( rulestruct[rule_position].flexbit_type[i] == 3 )
                                {
                                    flexbit_total_match++;
                                }

                        }
                    else
                        {

                            /* isnotset .... */

                            if ( rulestruct[rule_position].flexbit_type[i] == 4 )
                                {

                                    flexbit_total_match++;
                                }

                        } /* if ( redis_reply[0] ) */

                } /* rulestruct[rule_position].flexbit_direction[i] == 2 || 3 */

        } /* for (i = 0; .... */

    /* IF we match all criteria for isset/isnotset
     *
     * If we match the flexbit_conditon_count (number of concurrent flexbits)
     * we trigger.  It it's an "or" statement,  we trigger if any of the
     * flexbits are set.
     *
     */

    if ( rulestruct[rule_position].flexbit_condition_count == flexbit_total_match || flexbit_total_match != 0 )
        {

            if ( debug->debugflexbit)
                {
                    Sagan_Log(DEBUG, "[%s, line %d] Condition of flexbit returning TRUE. %d %d", __FILE__, __LINE__, rulestruct[rule_position].flexbit_condition_count, flexbit_total_match);
                }

            return(true);
        }

    /* isset/isnotset failed. */

    if ( debug->debugflexbit)
        {
            Sagan_Log(DEBUG, "[%s, line %d] Condition of flexbit returning FALSE. Needed %d but got %d.", __FILE__, __LINE__, rulestruct[rule_position].flexbit_condition_count, flexbit_total_match);
        }

    return(false);
}

/*****************************************************************************
 * Flexbit_Set_Redis - This will "set" and "unset" flexbits in Redis
 *****************************************************************************/

void Flexbit_Set_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, int src_port, int dst_port, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    time_t t;
    struct tm *now;
    char  timet[20];
    int i;
    int j;

    redisReply *reply;
    redisReply *reply_2;

    char redis_command[16384] = { 0 };

    char fullsyslog_orig[400 + MAX_SYSLOGMSG] = { 0 };

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    uint32_t djb2_hash;
    uint32_t djb2_hash_src;
    uint32_t djb2_hash_dst;

    uint32_t utime = atoi(timet);
    uint32_t utime_plus_timeout;

    if ( debug->debugredis )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Flexbit_Set_Redis()", __FILE__, __LINE__);
        }

    snprintf(fullsyslog_orig, sizeof(fullsyslog_orig), "%s|%s|%s|%s|%s|%s|%s|%s|%s",
             SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_facility,
             SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level,
             SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->syslog_date,
             SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog_LOCAL->syslog_program,
             SaganProcSyslog_LOCAL->syslog_message );

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

    for (i = 0; i < rulestruct[rule_position].flexbit_count; i++)
        {

            /* xbit SET */

            if ( rulestruct[rule_position].flexbit_type[i] == 1 )
                {

                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {

                            /* First, clean up */

                            Flexbit_Cleanup_Redis(rulestruct[rule_position].flexbit_name[i], utime, ip_src_char, ip_dst_char);

                            utime_plus_timeout = utime + rulestruct[rule_position].flexbit_timeout[i];

                            snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                                     "ZADD %s:by_src %lu %s;"
                                     "ZADD %s:by_dst %lu %s;"
                                     "ZADD %s:both %lu %s:%s;"
                                     "ZADD %s:%s:%s:set_log %lu %s",
                                     rulestruct[rule_position].flexbit_name[i], utime_plus_timeout, ip_src_char,
                                     rulestruct[rule_position].flexbit_name[i], utime_plus_timeout, ip_dst_char,
                                     rulestruct[rule_position].flexbit_name[i], utime_plus_timeout, ip_src_char, ip_dst_char,
                                     rulestruct[rule_position].flexbit_name[i], ip_src_char, ip_dst_char, utime_plus_timeout, fullsyslog_orig );

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

            /* xbit UNSET */

            else if ( rulestruct[rule_position].flexbit_type[i] == 2 )
                {

                    /* direction: none */

                    if ( rulestruct[rule_position].flexbit_direction[i] == 0 )
                        {

                            {
                                Sagan_Log(WARN, "[%s, line %d] Call for \"unset\" flexbit \"%s\" with Redis is not supported! \"unset\" needs an IP source or destination", __FILE__, __LINE__, rulestruct[rule_position].flexbit_name[i]);
                            }

                        }

                    /* direction: both - This should be easiest since we have all
                       the data we need */

                    else if ( rulestruct[rule_position].flexbit_direction[i] == 1 )
                        {

                            if ( redis_msgslot < config->redis_max_writer_threads )
                                {

                                    Flexbit_Cleanup_Redis(rulestruct[rule_position].flexbit_name[i], utime, ip_src_char, ip_dst_char);

                                    snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),

                                             "ZREM %s:by_src %s;"
                                             "ZREM %s:by_dst %s;"
                                             "ZREM %s:both %s:%s"
                                             "ZREM %s:%s:%s:set_log",
                                             rulestruct[rule_position].flexbit_name[i], ip_src_char,
                                             rulestruct[rule_position].flexbit_name[i], ip_dst_char,
                                             rulestruct[rule_position].flexbit_name[i], ip_src_char, ip_dst_char,
                                             rulestruct[rule_position].flexbit_name[i], ip_src_char, ip_dst_char );


                                    redis_msgslot++;

                                    pthread_cond_signal(&SaganRedisDoWork);
                                    pthread_mutex_unlock(&SaganRedisWorkMutex);

                                }
                            else
                                {

                                    Sagan_Log(WARN, "Out of Redis 'writer' threads for 'unset' by 'both'.  Skipping!");
                                    __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);

                                }
                        }

                    else if ( rulestruct[rule_position].flexbit_direction[i] == 2 )
                        {


                            if ( redis_msgslot < config->redis_max_writer_threads )
                                {

                                    Flexbit_Cleanup_Redis(rulestruct[rule_position].flexbit_name[i], utime, ip_src_char, ip_dst_char);

                                    snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                                             "ZREM %s:by_src %s", rulestruct[rule_position].flexbit_name[i], ip_src_char );

                                    redis_msgslot++;

                                    pthread_cond_signal(&SaganRedisDoWork);
                                    pthread_mutex_unlock(&SaganRedisWorkMutex);


                                }
                            else
                                {

                                    Sagan_Log(WARN, "Out of Redis 'writer' threads for 'unset' by 'ip_src'.  Skipping!");
                                    __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);

                                }

                        }


                    /* direction: ip_dst */

                    else if ( rulestruct[rule_position].flexbit_direction[i] == 3 )
                        {


                            if ( redis_msgslot < config->redis_max_writer_threads )
                                {

                                    Flexbit_Cleanup_Redis(rulestruct[rule_position].flexbit_name[i], utime, ip_src_char, ip_dst_char);

                                    snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                                             "ZREM %s:by_dst %s",
                                             rulestruct[rule_position].flexbit_name[i], ip_dst_char );


                                    redis_msgslot++;

                                    pthread_cond_signal(&SaganRedisDoWork);
                                    pthread_mutex_unlock(&SaganRedisWorkMutex);

                                }
                            else
                                {

                                    Sagan_Log(WARN, "Out of Redis 'writer' threads for 'unset' by 'ip_dst'.  Skipping!");
                                    __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);

                                }

                        }

                } /* else if ( rulestruct[rule_position].xbit_type[i] == 2 ) UNSET */
        } /* for (i = 0; i < rulestruct[rule_position].xbit_count; i++) */
}

/*****************************************************************************
 * Flexbit_Cleanup_Redis - Cleans up old/stale xbits from Redis
 *****************************************************************************/

void Flexbit_Cleanup_Redis( char *flexbit_name, uint32_t utime, char *ip_src_char, char *ip_dst_char )
{

    if ( redis_msgslot < config->redis_max_writer_threads )
        {


            snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                     "ZREMRANGEBYSCORE %s:by_src -inf %lu;"
                     "ZREMRANGEBYSCORE %s:by_dst -inf %lu;"
                     "ZREMRANGEBYSCORE %s:both -inf %lu;"
                     "ZREMRANGEBYSCORE %s:%s:%s:set_log -inf %lu",
                     flexbit_name, utime,
                     flexbit_name, utime,
                     flexbit_name, utime,
                     flexbit_name, ip_src_char, ip_dst_char, utime );

            redis_msgslot++;

            pthread_cond_signal(&SaganRedisDoWork);
            pthread_mutex_unlock(&SaganRedisWorkMutex);

        }
    else
        {

            Sagan_Log(WARN, "Out of Redis 'writer' threads for 'unset' by 'ip_dst'.  Skipping!");
            __atomic_add_fetch(&counters->redis_writer_threads_drop, 1, __ATOMIC_SEQ_CST);

        }

}

#endif
