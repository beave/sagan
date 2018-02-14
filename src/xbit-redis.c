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

#include "xbit.h"
#include "xbit-mmap.h"
#include "xbit-redis.h"
#include "parsers/parsers.h"
#include "redis.h"

struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganCounters *counters;

pthread_mutex_t CounterRedisWriterThreadsDrop=PTHREAD_MUTEX_INITIALIZER;

int redis_msgslot = 0;
pthread_cond_t SaganRedisDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t SaganRedisWorkMutex=PTHREAD_MUTEX_INITIALIZER;

struct _Sagan_Redis *SaganRedis;

#define NONE 0
#define OR   1
#define AND  2

/****************************************************************
   README * README * README * README * README * README * README
   README * README * README * README * README * README * README
 ****************************************************************

 This is very PoC (proof of concept) code and is NOT production
 ready.  This is to test the functionality of using Redis as a
 backend to store "xbits" (making them "global" xbits).

 store what "Set" an xbit in redis?

 ****************************************************************/

/*****************************************************************************
 Xbit_Condition_Redis - Test the condition of xbits.  For example,  "isset"
 and "isnotset"
 *****************************************************************************/

sbool Xbit_Condition_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, int src_port, int dst_port, char *selector )
{

    int i;
    int j;

    int xbit_total_match = 0;

    time_t t;
    struct tm *now;
    char  timet[20];

    redisReply *reply;

    char redis_command[1024] = { 0 };
    char redis_reply[32] = { 0 };

    char tmp[128];
    char *tmp_xbit_name = NULL;
    char *tok = NULL;

    uint32_t djb2_hash;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    int and_or = NONE;  /* | == true, & == false */

    char *src_or_dst = NULL;
    char *src_or_dst_type = NULL;

    char notnull_selector[MAXSELECTOR] = { 0 };

    /* If "selector" is in use, make it ready for redis */

    if ( config->selector_flag )
        {
            snprintf(notnull_selector, sizeof(notnull_selector), "%s:", selector);
        }

/*
    if ( debug->debugredis )
        {
            Sagan_Log(S_DEBUG, "[%s, line %d] Redis Xbit Condition.", __FILE__, __LINE__);
        }
*/

    /* Cycle through xbits in the rule */

    for (i = 0; i < rulestruct[rule_position].xbit_count; i++)
        {

            /* Only dealing with isset and isnotset */

            if ( rulestruct[rule_position].xbit_type[i] == 3 || rulestruct[rule_position].xbit_type[i] == 4 )
                {

                    strlcpy(tmp, rulestruct[rule_position].xbit_name[i], sizeof(tmp));

                    /* Determine if there are any | or &. If so,  we'll cycle through
                           all xbits */

                    if (Sagan_strstr(rulestruct[rule_position].xbit_name[i], "|"))
                        {

                            tmp_xbit_name = strtok_r(tmp, "|", &tok);
                            and_or = OR;

                        }
                    else
                        {

                            tmp_xbit_name = strtok_r(tmp, "&", &tok);
                            and_or = AND;

                        }

                    /* Cycle through all xbits,  if needed */

                    while (tmp_xbit_name != NULL )
                        {

                            /* direction: none - may add support for this later. */

                            if ( rulestruct[rule_position].xbit_direction[i] == 0 )
                                {

                                    {
                                        Sagan_Log(S_WARN, "[%s, line %d] Call for \"isset\" or \"isnotset\" xbit \"%s\" with Redis is not supported! \"unset\" needs an IP source or destination", __FILE__, __LINE__, tmp_xbit_name);
                                    }

                                }

                            /*****************************************************************/
                            /* direction: both - this is the easiest as we have all the data */
                            /*****************************************************************/

                            else if ( rulestruct[rule_position].xbit_direction[i] == 1 )
                                {

                                    if ( debug->debugxbit )
                                        {
                                            Sagan_Log(S_DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, tmp_xbit_name, ip_src_char, ip_dst_char);
                                        }


                                    snprintf(redis_command, sizeof(redis_command),
                                             "ZRANGEBYLEX %s%s:both [%s:%s [%s:%s",
                                             notnull_selector, tmp_xbit_name, ip_src_char, ip_dst_char, ip_src_char, ip_dst_char);

                                    Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

                                    /* If the xbit is found ... */

                                    if ( redis_reply[0] != ' ' )
                                        {

                                            /* isset */

                                            if ( rulestruct[rule_position].xbit_type[i] == 3 )
                                                {

                                                    if ( debug->debugxbit )
                                                        {
                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Found xbit '%s' for 'isset'.", __FILE__, __LINE__, tmp_xbit_name );
                                                        }

                                                    /* The rule has a |, we can short circuit here */

                                                    if ( and_or == OR || and_or == NONE )
                                                        {

                                                            if ( debug->debugxbit )
                                                                {
                                                                    Sagan_Log(S_DEBUG, "[%s, line %d] '|' set or only one xbit used, returning TRUE", __FILE__, __LINE__, tmp_xbit_name );
                                                                }

                                                            return(true);
                                                        }

                                                    /* No | in the rule,  so increment the match counter */

                                                    xbit_total_match++;

                                                } /* End of rulestruct[rule_position].xbit_type[i] == 3 */

                                        }
                                    else      /* End of reply->str != NULL */
                                        {

                                            /* No match was found */

                                            /* isnotset */

                                            if ( rulestruct[rule_position].xbit_type[i] == 4 )
                                                {

                                                    if ( debug->debugxbit )
                                                        {
                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Did not find xbit '%s' for 'isnotset'.", __FILE__, __LINE__, tmp_xbit_name );
                                                        }

                                                    /* If the run contains &'s we can short circuit here */

                                                    if ( and_or == AND || and_or == NONE )
                                                        {

                                                            if ( debug->debugxbit )
                                                                {
                                                                    Sagan_Log(S_DEBUG, "[%s, line %d] AND in isnotset, returning TRUE.", __FILE__, __LINE__, tmp_xbit_name );
                                                                }

                                                            return(true);

                                                        }

                                                    /* The rule contain no &,  so increment the match counter */

                                                    xbit_total_match++;

                                                } /* End of rulestruct[rule_position].xbit_type[i] == 4 */

                                        } /* End of else reply->str != NULL */

                                } /* End of if (rulestruct[rule_position].xbit_direction[i] == 1 || both ) */

                            /*******************************/
                            /* direction: by_src || by_dst */
                            /*******************************/

                            /* Since by_src and by_dst similar Redis queries,  we handle both here */

                            if ( rulestruct[rule_position].xbit_direction[i] == 2 ||
                                    rulestruct[rule_position].xbit_direction[i] == 3 )
                                {

                                    if ( rulestruct[rule_position].xbit_direction[i] == 2 )
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
                                             tmp_xbit_name, src_or_dst_type,  src_or_dst, src_or_dst);

                                    Redis_Reader(redis_command, redis_reply, sizeof(redis_reply));

                                    /**************************************************************/
                                    /* If nothing is found,  we can stop a lot of processing here.*/
                                    /**************************************************************/

                                    if ( redis_reply[0] != ' ' )
                                        {

                                            /* "isset" - If nothing is found then no need to continue */

                                            if ( rulestruct[rule_position].xbit_type[i] == 3 )
                                                {

                                                    if ( and_or == OR || and_or == NONE )
                                                        {

                                                            if ( debug->debugxbit )
                                                                {

                                                                    Sagan_Log(S_DEBUG, "[%s, line %d] xbit found, return TRUE", __FILE__, __LINE__ );
                                                                }

                                                            return(true);
                                                        }

                                                    xbit_total_match++;

                                                }

                                        }
                                    else
                                        {

                                            /* isnotset .... */

                                            if ( rulestruct[rule_position].xbit_type[i] == 4 )
                                                {

                                                    /* If we are looking for flowbit1&flowbit2 and flowbit1 is
                                                       not set,  we can short circuit now */

                                                    if ( and_or == AND || and_or == NONE )
                                                        {

                                                            if ( debug->debugxbit )
                                                                {
                                                                    Sagan_Log(S_DEBUG, "[%s, line %d] Single xbit or '&' found in xbit set. Returning TRUE", __FILE__, __LINE__ );
                                                                }

                                                            return(true);

                                                        }

                                                    xbit_total_match++;
                                                }

                                        } /* if ( redis_reply[0] ) */

                                } /* rulestruct[rule_position].xbit_direction[i] == 2 || 3 */

                            /************************************/
                            /* If needed, move to the next xbit */
                            /************************************/

                            if ( and_or == OR )
                                {
                                    tmp_xbit_name = strtok_r(NULL, "|", &tok);
                                }
                            else
                                {
                                    tmp_xbit_name = strtok_r(NULL, "&", &tok);
                                }

                        } /* while (tmp_xbit_name != NULL */

                } /* rulestruct[rule_position].xbit_type[i] == 3 | 4 */

        } /* for (i = 0; .... */

    /* IF we match all criteria for isset/isnotset
     *
     * If we match the xbit_conditon_count (number of concurrent xbits)
     * we trigger.  It it's an "or" statement,  we trigger if any of the
     * xbits are set.
     *
     */

    if ( ( rulestruct[rule_position].xbit_condition_count == xbit_total_match ) || ( and_or == OR && xbit_total_match != 0 ) )
        {

            if ( debug->debugxbit)
                {
                    Sagan_Log(S_DEBUG, "[%s, line %d] Condition of xbit returning TRUE. %d %d", __FILE__, __LINE__, rulestruct[rule_position].xbit_condition_count, xbit_total_match);
                }

            return(true);
        }

    /* isset/isnotset failed. */

    if ( debug->debugxbit)
        {
            Sagan_Log(S_DEBUG, "[%s, line %d] Condition of xbit returning FALSE. Needed %d but got %d.", __FILE__, __LINE__, rulestruct[rule_position].xbit_condition_count, xbit_total_match);
        }

    return(false);
}

/*****************************************************************************
 * Xbit_Set_Redis - This will "set" and "unset" xbits in Redis
 *****************************************************************************/

void Xbit_Set_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, int src_port, int dst_port, char *selector, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    time_t t;
    struct tm *now;
    char  timet[20];
    int i;
    int j;

    char *tmp_xbit_name = NULL;
    char tmp[128] = { 0 };
    char *tok = NULL;

    redisReply *reply;
    redisReply *reply_2;

    char redis_command[16384] = { 0 };

    char fullsyslog_orig[400 + MAX_SYSLOGMSG] = { 0 };
//    char altered_syslog[ (400*2) + (MAX_SYSLOGMSG*2)] = { 0 };

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    uint32_t djb2_hash;
    uint32_t djb2_hash_src;
    uint32_t djb2_hash_dst;

    uint32_t utime = atoi(timet);
    uint32_t utime_plus_timeout;

    char notnull_selector[MAXSELECTOR] = { 0 };

    if ( debug->debugredis )
        {
            Sagan_Log(S_DEBUG, "[%s, line %d] Redis Xbit Xbit_Set_Redis()", __FILE__, __LINE__);
        }

    snprintf(fullsyslog_orig, sizeof(fullsyslog_orig), "%s|%s|%s|%s|%s|%s|%s|%s|%s",
             SaganProcSyslog_LOCAL->syslog_host, SaganProcSyslog_LOCAL->syslog_facility,
             SaganProcSyslog_LOCAL->syslog_priority, SaganProcSyslog_LOCAL->syslog_level,
             SaganProcSyslog_LOCAL->syslog_tag, SaganProcSyslog_LOCAL->syslog_date,
             SaganProcSyslog_LOCAL->syslog_time, SaganProcSyslog_LOCAL->syslog_program,
             SaganProcSyslog_LOCAL->syslog_message );

    for ( i = 0; i < strlen(fullsyslog_orig); i++ )
        {

		switch(fullsyslog_orig[i]) {

		case ' ':
			fullsyslog_orig[i] = '_';
			break;

		case ';':
			fullsyslog_orig[i] = ':'; 
			break;

		}
        }

    /* If "selector" is in use, make it ready for redis */

    if ( config->selector_flag )
        {
            snprintf(notnull_selector, sizeof(notnull_selector), "%s:", selector);
        }

    for (i = 0; i < rulestruct[rule_position].xbit_count; i++)
        {

            /* xbit SET */

            if ( rulestruct[rule_position].xbit_type[i] == 1 )
                {


                    strlcpy(tmp, rulestruct[rule_position].xbit_name[i], sizeof(tmp));
                    tmp_xbit_name = strtok_r(tmp, "&", &tok);

                    while( tmp_xbit_name != NULL )
                        {

                            if ( redis_msgslot < config->redis_max_writer_threads )
                                {

                                    /* First, clean up */

                                    Xbit_Cleanup_Redis(tmp_xbit_name, utime, notnull_selector, ip_src_char, ip_dst_char);

                                    utime_plus_timeout = utime + rulestruct[rule_position].xbit_timeout[i];

                                    snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                                             "ZADD %s%s:by_src %lu %s;"
                                             "ZADD %s%s:by_dst %lu %s;"
                                             "ZADD %s%s:both %lu %s:%s;"
                                             "ZADD %s%s:%s:%s:set_log %lu %s",
                                             notnull_selector, tmp_xbit_name, utime_plus_timeout, ip_src_char,
                                             notnull_selector, tmp_xbit_name, utime_plus_timeout, ip_dst_char,
                                             notnull_selector, tmp_xbit_name, utime_plus_timeout, ip_src_char, ip_dst_char,
                                             notnull_selector, tmp_xbit_name, ip_src_char, ip_dst_char, utime_plus_timeout, fullsyslog_orig );

                                    redis_msgslot++;

                                    pthread_cond_signal(&SaganRedisDoWork);
                                    pthread_mutex_unlock(&SaganRedisWorkMutex);

                                }
                            else
                                {

                                    Sagan_Log(S_WARN, "Out of Redis 'writer' threads for 'set'.  Skipping!");

                                    pthread_mutex_lock(&CounterRedisWriterThreadsDrop);
                                    counters->redis_writer_threads_drop++;
                                    pthread_mutex_unlock(&CounterRedisWriterThreadsDrop);

                                }

                            tmp_xbit_name = strtok_r(NULL, "&", &tok);
                        }
                }

            /* xbit UNSET */

            else if ( rulestruct[rule_position].xbit_type[i] == 2 )
                {

                    /* Xbits & (ie - bit1&bit2) */

                    strlcpy(tmp, rulestruct[rule_position].xbit_name[i], sizeof(tmp));
                    tmp_xbit_name = strtok_r(tmp, "&", &tok);

                    while( tmp_xbit_name != NULL )
                        {

                            /* direction: none */

                            if ( rulestruct[rule_position].xbit_direction[i] == 0 )
                                {

                                    {
                                        Sagan_Log(S_WARN, "[%s, line %d] Call for \"unset\" xbit \"%s\" with Redis is not supported! \"unset\" needs an IP source or destination", __FILE__, __LINE__, tmp_xbit_name);
                                    }

                                }

                            /* direction: both - This should be easiest since we have all
                               the data we need */

                            else if ( rulestruct[rule_position].xbit_direction[i] == 1 )
                                {

                                    if ( redis_msgslot < config->redis_max_writer_threads )
                                        {

                                            Xbit_Cleanup_Redis(tmp_xbit_name, utime, notnull_selector, ip_src_char, ip_dst_char);

                                            snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),

                                                     "ZREM %s%s:by_src %s;"
                                                     "ZREM %s%s:by_dst %s;"
                                                     "ZREM %s%s:both %s:%s"
                                                     "ZREM %s%s:%s:%s:set_log",
                                                     notnull_selector, tmp_xbit_name, ip_src_char,
                                                     notnull_selector, tmp_xbit_name, ip_dst_char,
                                                     notnull_selector, tmp_xbit_name, ip_src_char, ip_dst_char,
                                                     notnull_selector, tmp_xbit_name, ip_src_char, ip_dst_char );


                                            redis_msgslot++;

                                            pthread_cond_signal(&SaganRedisDoWork);
                                            pthread_mutex_unlock(&SaganRedisWorkMutex);

                                        }
                                    else
                                        {

                                            Sagan_Log(S_WARN, "Out of Redis 'writer' threads for 'unset' by 'both'.  Skipping!");

                                            pthread_mutex_lock(&CounterRedisWriterThreadsDrop);
                                            counters->redis_writer_threads_drop++;
                                            pthread_mutex_unlock(&CounterRedisWriterThreadsDrop);

                                        }
                                }

                            else if ( rulestruct[rule_position].xbit_direction[i] == 2 )
                                {


                                    if ( redis_msgslot < config->redis_max_writer_threads )
                                        {

                                            Xbit_Cleanup_Redis(tmp_xbit_name, utime, notnull_selector, ip_src_char, ip_dst_char);

                                            snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                                                     "ZREM %s%s:by_src %s",
                                                     notnull_selector, tmp_xbit_name, ip_src_char );

                                            redis_msgslot++;

                                            pthread_cond_signal(&SaganRedisDoWork);
                                            pthread_mutex_unlock(&SaganRedisWorkMutex);


                                        }
                                    else
                                        {

                                            Sagan_Log(S_WARN, "Out of Redis 'writer' threads for 'unset' by 'ip_src'.  Skipping!");

                                            pthread_mutex_lock(&CounterRedisWriterThreadsDrop);
                                            counters->redis_writer_threads_drop++;
                                            pthread_mutex_unlock(&CounterRedisWriterThreadsDrop);

                                        }

                                }


                            /* direction: ip_dst */

                            else if ( rulestruct[rule_position].xbit_direction[i] == 3 )
                                {


                                    if ( redis_msgslot < config->redis_max_writer_threads )
                                        {

                                            Xbit_Cleanup_Redis(tmp_xbit_name, utime, notnull_selector, ip_src_char, ip_dst_char);

                                            snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                                                     "ZREM %s%s:by_dst %s",
                                                     notnull_selector, tmp_xbit_name, ip_dst_char );


                                            redis_msgslot++;

                                            pthread_cond_signal(&SaganRedisDoWork);
                                            pthread_mutex_unlock(&SaganRedisWorkMutex);

                                        }
                                    else
                                        {

                                            Sagan_Log(S_WARN, "Out of Redis 'writer' threads for 'unset' by 'ip_dst'.  Skipping!");

                                            pthread_mutex_lock(&CounterRedisWriterThreadsDrop);
                                            counters->redis_writer_threads_drop++;
                                            pthread_mutex_unlock(&CounterRedisWriterThreadsDrop);

                                        }

                                }


                            tmp_xbit_name = strtok_r(NULL, "&", &tok);

                        } /* while( tmp_xbit_name != NULL ) */
                } /* else if ( rulestruct[rule_position].xbit_type[i] == 2 ) UNSET */
        } /* for (i = 0; i < rulestruct[rule_position].xbit_count; i++) */
}

/*****************************************************************************
 * Xbit_Cleanup_Redis - Cleans up old/stale xbits from Redis
 *****************************************************************************/


void Xbit_Cleanup_Redis( char *xbit_name, uint32_t utime, char *notnull_selector, char *ip_src_char, char *ip_dst_char )
{

    if ( redis_msgslot < config->redis_max_writer_threads )
        {


            snprintf(SaganRedis[redis_msgslot].redis_command, sizeof(SaganRedis[redis_msgslot].redis_command),
                     "ZREMRANGEBYSCORE %s%s:by_src -inf %lu;"
                     "ZREMRANGEBYSCORE %s%s:by_dst -inf %lu;"
                     "ZREMRANGEBYSCORE %s%s:both -inf %lu;"
                     "ZREMRANGEBYSCORE %s%s:%s:%s:set_log -inf %lu",
                     notnull_selector, xbit_name, utime,
                     notnull_selector, xbit_name, utime,
                     notnull_selector, xbit_name, utime,
                     notnull_selector, xbit_name, ip_src_char, ip_dst_char, utime );

            redis_msgslot++;

            pthread_cond_signal(&SaganRedisDoWork);
            pthread_mutex_unlock(&SaganRedisWorkMutex);

        }
    else
        {

            Sagan_Log(S_WARN, "Out of Redis 'writer' threads for 'unset' by 'ip_dst'.  Skipping!");

            pthread_mutex_lock(&CounterRedisWriterThreadsDrop);
            counters->redis_writer_threads_drop++;
            pthread_mutex_unlock(&CounterRedisWriterThreadsDrop);

        }


}

#endif
