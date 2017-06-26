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

/* redis.c - Threads to write/read from redis databases */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <hiredis/hiredis.h>

#include "sagan.h"
#include "sagan-config.h"
#include "redis.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;

pthread_mutex_t RedisMutex;

void Redis_Connect ( void )
{

    redisReply *reply;

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    config->c_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

    if (config->c_redis == NULL || config->c_redis->err)
        {

            if (config->c_redis)
                {

                    Sagan_Log(S_ERROR, "[%s, line %d] Redis connection error - %s. Abort!", __FILE__, __LINE__, config->c_redis->errstr);
                    redisFree(config->c_redis);

                }
            else
                {

                    Sagan_Log(S_ERROR, "[%s, line %d] Redis connection error - Can't allocate Redis context", __FILE__, __LINE__);
                }
        }

}

/*

void Redis_Command ( char *redis_command, char *str, size_t size )
{

    redisReply *reply;

    if ( debug->debugredis )
        {
            Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
        }

    pthread_mutex_lock(&RedisMutex);
    reply = redisCommand(config->c_redis, redis_command);
    memcpy(redis_reply, reply, sizeof(reply));
    pthread_mutex_unlock(&RedisMutex);


    /* This is a pretty simple function.  We can only return one element back from a
     * redis command at this time.   If the reply->elements is > than 0,  we only return
     * the first element */
/*
    if ( reply->elements == 0 )
	{
        snprintf(str, size, "%s", reply->str);
	} else {
	snprintf(str, size, "%s", reply->element[0]->str);
	}

    if ( debug->debugredis )
        {
            Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, str);
        }

    freeReplyObject(reply);
    return(redis_reply);

}
*/


#endif
