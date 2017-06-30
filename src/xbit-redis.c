/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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
#include "redis.h"

struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;

pthread_mutex_t RedisMutex;

/****************************************************************
   README * README * README * README * README * README * README
   README * README * README * README * README * README * README
 ****************************************************************

 This is very PoC (proof of concept) code and is NOT production
 ready.  This is to test the functionality of using Redis as a
 backend to store "xbits" (making them "global" xbits.   This code
 WILL CAUSE thread blocking.

 NOTES:  Need some debugging for "--debug xbit" in here as well.
         Would likely want to deploy a thread pool for Redis ops

	 src/dst do not need to be part of the HMSET.
         Do we event need "active" in HMSET?

 ****************************************************************/

sbool Xbit_Condition_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, int src_port, int dst_port )
{

    int i;
    int a;

    time_t t;
    struct tm *now;
    char  timet[20];

    redisReply *reply;
    char redis_tmp[256] = { 0 };
    char redis_command[256] = { 0 };
    char tmp[128] = { 0 };
    char *tmp_xbit_name = NULL;
    char *tok = NULL;

    uint32_t ip_src = IP2Bit(ip_src_char);
    uint32_t ip_dst = IP2Bit(ip_dst_char);

    uint32_t djb2_hash;

    t = time(NULL);
    now=localtime(&t);
    strftime(timet, sizeof(timet), "%s",  now);

    int and_or = false;

    if ( debug->debugredis ) {
        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Xbit Condition", __FILE__, __LINE__);
    }

    for (i = 0; i < rulestruct[rule_position].xbit_count; i++) {

        if ( rulestruct[rule_position].xbit_type[i] == 3 ) {

            strlcpy(tmp, rulestruct[rule_position].xbit_name[i], sizeof(tmp));

            if (Sagan_strstr(rulestruct[rule_position].xbit_name[i], "|")) {
                tmp_xbit_name = strtok_r(tmp, "|", &tok);
                and_or = true;
            } else {
                tmp_xbit_name = strtok_r(tmp, "&", &tok);
                and_or = false;
            }

            while (tmp_xbit_name != NULL ) {


                /* direction: both - this is the easiest as we have all the data */

                if ( rulestruct[rule_position].xbit_direction[i] == 1 ) {


                    if ( debug->debugxbit ) {
                        Sagan_Log(S_DEBUG, "[%s, line %d] \"isset\" xbit \"%s\" (direction: \"both\"). (%s -> %s)", __FILE__, __LINE__, tmp_xbit_name, ip_src_char, ip_dst_char);
                    }

                    snprintf(redis_tmp, sizeof(redis_tmp), "%s-%u-%u", tmp_xbit_name, ip_src, ip_dst);
                    djb2_hash = Djb2_Hash(redis_tmp);

                    snprintf(redis_command, sizeof(redis_command), "HGET %u active", djb2_hash);

                    pthread_mutex_lock(&RedisMutex);

                    reply = redisCommand(config->c_redis, redis_command);

                    if ( debug->debugredis ) {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                    }

		    /* Not found */

		    if ( reply->str == NULL ) 
		       { 

                        if ( rulestruct[rule_position].xbit_type[i] == 3 ) 
                            {
                            
                            if ( debug->debugxbit ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Not found - Condition of xbit returning TRUE", __FILE__, __LINE__);
                            }

			    pthread_mutex_unlock(&RedisMutex);                            
                            return(false); /* isset */
                        
                        } else {
                            
                            if ( debug->debugxbit ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Not found - Condition of xbit returning FALSE", __FILE__, __LINE__);
                            }

			    pthread_mutex_unlock(&RedisMutex);
                            return(true); /* isnotset */
                        }

		    }

		    /* xbit was found and marked as "active" */

                    if ( atoi(reply->str) == true ) {

                        pthread_mutex_unlock(&RedisMutex);

			/* "isset" == 3, "isnotset" == 4 */

                        if ( rulestruct[rule_position].xbit_type[i] == 3 )
			    {

                            if ( debug->debugxbit ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Condition of xbit returning TRUE", __FILE__, __LINE__);
                            }

                            return(true); /* isset */

                        } else {

                            if ( debug->debugxbit ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Condition of xbit returning FALSE", __FILE__, __LINE__);
                            }
                            return(false); /* isnotset */
                        }

                    }

                    pthread_mutex_unlock(&RedisMutex);

                }

                if ( and_or == true ) {
                    tmp_xbit_name = strtok_r(NULL, "|", &tok);
                } else {
                    tmp_xbit_name = strtok_r(NULL, "&", &tok);
                }

            }

        }

    }

    /* "isset" == 3, "isnotset" == 4 */

    if ( rulestruct[rule_position].xbit_type[i] == 3 ) {

        if ( debug->debugxbit ) {
            Sagan_Log(S_DEBUG, "[%s, line %d] Condition of xbit returning TRUE", __FILE__, __LINE__);
        }

        return(true);		/* isset */

    } else {

        if ( debug->debugxbit ) {
            Sagan_Log(S_DEBUG, "[%s, line %d] Condition of xbit returning FALSE", __FILE__, __LINE__);
        }
        return(false);		/* isnotset */
    }

}


void Xbit_Set_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, int src_port, int dst_port )
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
    redisReply *reply_3;

    char redis_tmp[256] = { 0 };
    char redis_command[256] = { 0 };

    uint32_t ip_src = IP2Bit(ip_src_char);
    uint32_t ip_dst = IP2Bit(ip_dst_char);

    uint32_t djb2_hash;


    if ( debug->debugredis ) {
        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Xbit SET", __FILE__, __LINE__);
    }

    for (i = 0; i < rulestruct[rule_position].xbit_count; i++) {

        /* xbit SET */

        if ( rulestruct[rule_position].xbit_type[i] == 1 ) {

            t = time(NULL);
            now=localtime(&t);
            strftime(timet, sizeof(timet), "%s",  now);

            strlcpy(tmp, rulestruct[rule_position].xbit_name[i], sizeof(tmp));
            tmp_xbit_name = strtok_r(tmp, "&", &tok);

            while( tmp_xbit_name != NULL ) {

                snprintf(redis_tmp, sizeof(redis_tmp), "%s-%u-%u", tmp_xbit_name, ip_src, ip_dst);
                djb2_hash = Djb2_Hash(redis_tmp);

                /* Insert the array from SET */

                pthread_mutex_lock(&RedisMutex);

                snprintf(redis_command, sizeof(redis_command), "HMSET %u active 1 name %s src_ip %u dst_ip %u timestamp %s expire %d sensor %s", djb2_hash, tmp_xbit_name, ip_src, ip_dst,  timet, rulestruct[rule_position].xbit_timeout[i], config->sagan_sensor_name);

                reply = redisCommand(config->c_redis, redis_command);

                if ( debug->debugredis ) {
                    Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                    Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                }

                snprintf(redis_command, sizeof(redis_command), "EXPIRE %u %d", djb2_hash, rulestruct[rule_position].xbit_timeout[i]);

                reply = redisCommand(config->c_redis, redis_command);

                if ( debug->debugredis ) {
                    Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                    Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                }

                /* Insert source/destination in our index */

                snprintf(redis_command, sizeof(redis_command), "ZADD xbit_src_index %u %u", ip_src, djb2_hash);

                reply = redisCommand(config->c_redis, redis_command);

                if ( debug->debugredis ) {
                    Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                    Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                }

                snprintf(redis_command, sizeof(redis_command), "ZADD xbit_dst_index %u %u", ip_dst, djb2_hash);

                reply = redisCommand(config->c_redis, redis_command);

                if ( debug->debugredis ) {
                    Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                    Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                }

                pthread_mutex_unlock(&RedisMutex);


                tmp_xbit_name = strtok_r(NULL, "&", &tok);
            }
        }

        /* xbit UNSET */

        else if ( rulestruct[rule_position].xbit_type[i] == 2 ) {

            /* Xbits & (ie - bit1&bit2) */

            strlcpy(tmp, rulestruct[rule_position].xbit_name[i], sizeof(tmp));
            tmp_xbit_name = strtok_r(tmp, "&", &tok);

            while( tmp_xbit_name != NULL ) {

                /* direction: none */

                if ( rulestruct[rule_position].xbit_direction[i] == 0 ) {

                    {
                        Sagan_Log(S_WARN, "[%s, line %d] Call for \"unset\" xbit \"%s\" with Redis is not supported! \"unset\" needs an IP source or destination", __FILE__, __LINE__, tmp_xbit_name);
                    }

                }

                /* direction: both - This should be easiest since we have all
                   the data we need */

                else if ( rulestruct[rule_position].xbit_direction[i] == 1 ) {

                    snprintf(redis_tmp, sizeof(redis_tmp), "%s-%u-%u", tmp_xbit_name, ip_src, ip_dst);
                    djb2_hash = Djb2_Hash(redis_tmp);

                    pthread_mutex_lock(&RedisMutex);

                    snprintf(redis_command, sizeof(redis_command), "HMGET %u active", djb2_hash);

                    reply = redisCommand(config->c_redis, redis_command);

                    if ( debug->debugredis ) {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->element[0]->str);
                    }

                    /* If we get a NULL,  then there's no need to delete out of the
                     * src/dst index.  Short circuit here. */

                    if ( reply->element[0]->str == NULL ) {

                        if ( debug->debugxbit ) {
                            Sagan_Log(S_DEBUG, "[%s, line %d] \"unset\" by \"both\" returned NULL result from Redis.  Exit function", __FILE__, __LINE__);
                        }

                        pthread_mutex_unlock(&RedisMutex);
                        return;

                    }

                    snprintf(redis_command, sizeof(redis_command), "ZREMRANGEBYSCORE xbit_src_index %u %u", ip_src, ip_src);

                    reply = redisCommand(config->c_redis, redis_command);

                    if ( debug->debugredis ) {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                    }

                    snprintf(redis_command, sizeof(redis_command), "ZREMRANGEBYSCORE xbit_dst_index %u %u", ip_dst, ip_dst);

                    reply = redisCommand(config->c_redis, redis_command);

                    if ( debug->debugredis ) {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                    }

                    snprintf(redis_command, sizeof(redis_command), "DEL %u", djb2_hash);

                    reply = redisCommand(config->c_redis, redis_command);

                    if ( debug->debugredis ) {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                    }

                    pthread_mutex_unlock(&RedisMutex);


                } /* End of unset / both */


                /* direction: ip_src */

                else if ( rulestruct[rule_position].xbit_direction[i] == 2 ) {

                    pthread_mutex_lock(&RedisMutex);

                    snprintf(redis_command, sizeof(redis_command), "ZRANGEBYSCORE xbit_src_index %u %u", ip_src, ip_src);

                    reply = redisCommand(config->c_redis, redis_command);

                    if ( debug->debugredis ) {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                    }

                    if ( reply->elements == 0 ) {

                        if ( debug->debugxbit ) {
                            Sagan_Log(S_DEBUG, "[%s, line %d] \"unset\" by \"ip_src\" returned NULL result from Redis.  Exit function", __FILE__, __LINE__);
                        }

                        pthread_mutex_unlock(&RedisMutex);
                        return;
                    }


                    for (j = 0; j < reply->elements; j++) {

                        snprintf(redis_command, sizeof(redis_command), "HGET %s name", reply->element[j]->str);

                        reply_2 = redisCommand(config->c_redis, redis_command);

                        if ( debug->debugredis ) {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                            Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply_2->str);
                        }

                        if ( !strcmp(tmp_xbit_name, reply_2->str ) ) {

                            if ( debug->debugxbit ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Delete by 'ip_src' key %s", __FILE__, __LINE__, reply->element[j]->str);
                            }

                            snprintf(redis_command, sizeof(redis_command), "ZREM xbit_src_index %s", reply->element[j]->str );

                            reply_3 = redisCommand(config->c_redis, redis_command);

                            if ( debug->debugredis ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply_3->str);
                            }

                            snprintf(redis_command, sizeof(redis_command), "ZREM xbit_dst_index %s", reply->element[j]->str );

                            reply_3 = redisCommand(config->c_redis, redis_command);

                            if ( debug->debugredis ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply_3->str);
                            }

                            snprintf(redis_command, sizeof(redis_command), "DEL %s", reply->element[j]->str );

                            reply_3 = redisCommand(config->c_redis, redis_command);

                            if ( debug->debugredis ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply_3->str);
                            }

                            pthread_mutex_unlock(&RedisMutex);

                        }

                    }
                }


                /* direction: ip_dst */

                else if ( rulestruct[rule_position].xbit_direction[i] == 3 ) {

                    pthread_mutex_lock(&RedisMutex);

                    snprintf(redis_command, sizeof(redis_command), "ZRANGEBYSCORE xbit_dst_index %u %u", ip_dst, ip_dst);

                    reply = redisCommand(config->c_redis, redis_command);

                    if ( debug->debugredis ) {
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
                    }

                    if ( reply->elements == 0 ) {

                        if ( debug->debugxbit ) {
                            Sagan_Log(S_DEBUG, "[%s, line %d] \"unset\" by \"ip_dst\" returned NULL result from Redis.  Exit function", __FILE__, __LINE__);
                        }

                        pthread_mutex_unlock(&RedisMutex);
                        return;
                    }


                    for (j = 0; j < reply->elements; j++) {

                        snprintf(redis_command, sizeof(redis_command), "HGET %s name", reply->element[j]->str);

                        reply_2 = redisCommand(config->c_redis, redis_command);

                        if ( debug->debugredis ) {
                            Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                            Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply_2->str);
                        }

                        if ( !strcmp(tmp_xbit_name, reply_2->str ) ) {

                            if ( debug->debugxbit ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Delete by 'ip_dst' key %s", __FILE__, __LINE__, reply->element[j]->str);
                            }

                            snprintf(redis_command, sizeof(redis_command), "ZREM xbit_src_index %s", reply->element[j]->str );

                            reply_3 = redisCommand(config->c_redis, redis_command);

                            if ( debug->debugredis ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply_3->str);
                            }

                            snprintf(redis_command, sizeof(redis_command), "ZREM xbit_dst_index %s", reply->element[j]->str );

                            reply_3 = redisCommand(config->c_redis, redis_command);

                            if ( debug->debugredis ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply_3->str);
                            }

                            snprintf(redis_command, sizeof(redis_command), "DEL %s", reply->element[j]->str );

                            reply_3 = redisCommand(config->c_redis, redis_command);

                            if ( debug->debugredis ) {
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
                                Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply_3->str);
                            }

                            pthread_mutex_unlock(&RedisMutex);

                        } /* if ( !strcmp(tmp_xbit_name, reply_2->str ) */
                    } /* for (j = 0; j < reply->elements; j++) */
                } /* if ( rulestruct[rule_position].xbit_direction[i] == 3 ) */


                tmp_xbit_name = strtok_r(NULL, "&", &tok);

            } /* while( tmp_xbit_name != NULL ) */
        } /* else if ( rulestruct[rule_position].xbit_type[i] == 2 ) UNSET */
    } /* for (i = 0; i < rulestruct[rule_position].xbit_count; i++) */

}


#endif
