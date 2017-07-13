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

int redis_msgslot;

pthread_cond_t SaganRedisDoWork;
pthread_mutex_t SaganRedisWorkMutex;

pthread_mutex_t RedisReaderMutex=PTHREAD_MUTEX_INITIALIZER;

struct _Sagan_Redis *SaganRedis = NULL;

void Redis_Writer_Init ( void )
{

    SaganRedis = malloc(config->redis_max_writer_threads * sizeof(struct _Sagan_Redis));

}


void Redis_Reader_Connect ( void )
{

    redisReply *reply;

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    config->c_reader_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

    if (config->c_reader_redis == NULL || config->c_reader_redis->err) {

        if (config->c_reader_redis) {

            Sagan_Log(S_ERROR, "[%s, line %d] Redis connection error - %s. Abort!", __FILE__, __LINE__, config->c_reader_redis->errstr);
            redisFree(config->c_reader_redis);

        } else {

            Sagan_Log(S_ERROR, "[%s, line %d] Redis connection error - Can't allocate Redis context", __FILE__, __LINE__);
        }
    }

}

void Redis_Writer ( void )
{

    redisReply *reply;
    redisContext *c_writer_redis;

    char *tok = NULL;
    char *split_redis_command = NULL;
    char tmp_redis_command[2048] = { 0 };
    char tmp_reply[8] = { 0 };

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    c_writer_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

    if (c_writer_redis == NULL || c_writer_redis->err) {

        if (c_writer_redis) {

            redisFree(c_writer_redis);
            Sagan_Log(S_ERROR, "[%s, line %d] Redis 'writer' connection error - %s. Abort!", __FILE__, __LINE__, c_writer_redis->errstr);

        } else {

            Sagan_Log(S_ERROR, "[%s, line %d] Redis 'writer' connection error - Can't allocate Redis context", __FILE__, __LINE__);

        }
    }

    /******************/
    /* Log into Redis */
    /******************/

    if ( config->redis_password[0] != '\0' ) {

        reply = redisCommand(c_writer_redis, "AUTH %s", config->redis_password);

        if (!strcmp(reply->str, "OK")) {

            if ( debug->debugredis ) {

                Sagan_Log( S_DEBUG, "Authentication success for 'writer' to Redis server at %s:%d (pthread ID: %lu).", config->redis_server, config->redis_port, pthread_self() );

            }

        } else {

            Remove_Lock_File();
            Sagan_Log(S_ERROR, "Authentication failure for 'writer' to to Redis server at %s:%d (pthread ID: %lu). Abort!", config->redis_server, config->redis_port, pthread_self() );

        }
    }

    for (;;) {

        pthread_mutex_lock(&SaganRedisWorkMutex);

        while ( redis_msgslot == 0 ) pthread_cond_wait(&SaganRedisDoWork, &SaganRedisWorkMutex);

        redis_msgslot--;

        strlcpy(tmp_redis_command, SaganRedis[redis_msgslot].redis_command, sizeof(tmp_redis_command));

        pthread_mutex_unlock(&SaganRedisWorkMutex);

        if ( debug->debugredis ) {

            Sagan_Log(S_DEBUG, "Thread %u received the following work: '%s'", pthread_self(), tmp_redis_command);
        }

        split_redis_command = strtok_r(tmp_redis_command, ";", &tok);

        while ( split_redis_command != NULL ) {

            if ( debug->debugredis ) {

                Sagan_Log(S_DEBUG, "Thread %u executing Redis command: '%s'", pthread_self(), split_redis_command);

            }

            reply = redisCommand(c_writer_redis, split_redis_command);

            if ( debug->debugredis ) {

                Sagan_Log(S_DEBUG, "Thread %u reply-str: '%s'", pthread_self(), reply->str);

            }

            freeReplyObject(reply);

            split_redis_command = strtok_r(NULL, ";", &tok);
        }

    }

}


void Redis_Reader ( char *redis_command, char *str, size_t size )
{

    redisReply *reply;

    pthread_mutex_lock(&RedisReaderMutex);
    reply = redisCommand(config->c_reader_redis, redis_command);
    pthread_mutex_unlock(&RedisReaderMutex);

    if ( debug->debugredis ) {
        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
        Sagan_Log(S_DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
    }


    snprintf(str, size, reply->str);
    freeReplyObject(reply);

}

#endif
