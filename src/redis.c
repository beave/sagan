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

/* redis.c - Function that access/write to Redis database */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBHIREDIS

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <hiredis/hiredis.h>

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "sagan.h"
#include "sagan-config.h"
#include "lockfile.h"
#include "redis.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;

int redis_msgslot = 0;

pthread_cond_t SaganRedisDoWork=PTHREAD_COND_INITIALIZER;
pthread_mutex_t SaganRedisWorkMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t RedisReaderMutex=PTHREAD_MUTEX_INITIALIZER;

struct _Sagan_Redis *SaganRedis = NULL;
struct _Sagan_Redis_Write *Sagan_Redis_Write = NULL; 

/*****************************************************************************
 * Redis_Writer_Init - Redis "writer" threads initialization.
 *****************************************************************************/

void Redis_Writer_Init ( void )
{

    SaganRedis = malloc(config->redis_max_writer_threads * sizeof(struct _Sagan_Redis));

    Sagan_Redis_Write = malloc(config->redis_max_writer_threads * sizeof(struct _Sagan_Redis_Write));

    if ( Sagan_Redis_Write == NULL )
       {
       Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for Sagan_Redis_Write. Abort!", __FILE__, __LINE__);
       }

    memset(Sagan_Redis_Write, 0, sizeof(struct _Sagan_Redis_Write));

}

/*****************************************************************************
 * Redis_Reader_Connect - Connectin for "read" operations
 *****************************************************************************/

void Redis_Reader_Connect ( void )
{

    struct timeval timeout = { 1, 500000 }; // 5.5 seconds
    config->c_reader_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

    if (config->c_reader_redis == NULL || config->c_reader_redis->err)
        {

            if (config->c_reader_redis)
                {

                    Sagan_Log(ERROR, "[%s, line %d] Redis connection error - %s. Abort!", __FILE__, __LINE__, config->c_reader_redis->errstr);
                    redisFree(config->c_reader_redis);

                }
            else
                {

                    Sagan_Log(ERROR, "[%s, line %d] Redis connection error - Can't allocate Redis context", __FILE__, __LINE__);
                }
        }

}

/*****************************************************************************
 * Redis_Writer - Threads that "write" to Redis.  We spawn up several to
 * avoid blocking.  Writer accepts "stacked" commands seperated by ;
 *****************************************************************************/

void Redis_Writer ( void )
{

    (void)SetThreadName("SaganRedisWriter");

    redisReply *reply;
    redisContext *c_writer_redis;

    char *tok = NULL;
//    char *split_redis_command = NULL;
//    char tmp_redis_command[16384] = { 0 };

    char command[16] = { 0 }; 
    char key[128] = { 0 };
    char value[MAX_SYSLOGMSG*2];
    int expire = 0;

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds
    c_writer_redis = redisConnectWithTimeout(config->redis_server, config->redis_port, timeout);

    if (c_writer_redis == NULL || c_writer_redis->err)
        {

            if (c_writer_redis)
                {

                    redisFree(c_writer_redis);
                    Sagan_Log(ERROR, "[%s, line %d] Redis 'writer' connection error - %s. Abort!", __FILE__, __LINE__, c_writer_redis->errstr);

                }
            else
                {

                    Sagan_Log(ERROR, "[%s, line %d] Redis 'writer' connection error - Can't allocate Redis context", __FILE__, __LINE__);

                }
        }

    /******************/
    /* Log into Redis */
    /******************/


    if ( config->redis_password[0] != '\0' )
        {

            reply = redisCommand(c_writer_redis, "AUTH %s", config->redis_password);

            if (!strcmp(reply->str, "OK"))
                {

                    if ( debug->debugredis )
                        {

                            Sagan_Log( DEBUG, "Authentication success for 'writer' to Redis server at %s:%d (pthread ID: %lu).", config->redis_server, config->redis_port, pthread_self() );

                        }

                }
            else
                {

                    Remove_Lock_File();
                    Sagan_Log(ERROR, "Authentication failure for 'writer' to to Redis server at %s:%d (pthread ID: %lu). Abort!", config->redis_server, config->redis_port, pthread_self() );

                }
        }


    /* Redis "threaded" operations */

    for (;;)
        {

            pthread_mutex_lock(&SaganRedisWorkMutex);

            while ( redis_msgslot == 0 ) pthread_cond_wait(&SaganRedisDoWork, &SaganRedisWorkMutex);

            redis_msgslot--;

	    strlcpy(command, Sagan_Redis_Write[redis_msgslot].command, sizeof(command));
 	    strlcpy(key, Sagan_Redis_Write[redis_msgslot].key, sizeof(key));
 	    strlcpy(value, Sagan_Redis_Write[redis_msgslot].value, sizeof(value));
	    expire = Sagan_Redis_Write[redis_msgslot].expire;

            pthread_mutex_unlock(&SaganRedisWorkMutex);

            if ( debug->debugredis )
                {

                    Sagan_Log(DEBUG, "Thread %u received the following work: '%s %s %s EX %d'", pthread_self(), command, key, value, expire);
                }

		    reply = redisCommand(c_writer_redis, "%s %s %s EX %d", command, key, value, expire);

                    if ( debug->debugredis )
                        {

                            Sagan_Log(DEBUG, "Thread %u reply-str: '%s'", pthread_self(), reply->str);

                        }

                    freeReplyObject(reply);

        }

}

/*****************************************************************************
 * Redis_Reader - This is _not_ a threaded operation and can't be :( This
 * function only returns _one_ result (not an array), even if they query
 * returns more than one result.
 *****************************************************************************/

void Redis_Reader ( char *redis_command, char *str, size_t size )
{

    redisReply *reply;

    pthread_mutex_lock(&RedisReaderMutex);
    reply = redisCommand(config->c_reader_redis, redis_command);

    if ( debug->debugredis )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Redis Command: \"%s\"", __FILE__, __LINE__, redis_command);
            Sagan_Log(DEBUG, "[%s, line %d] Redis Reply: \"%s\"", __FILE__, __LINE__, reply->str);
        }

    if ( reply->elements == 0 )
        {

            /* strlcpy doesn't like to pass str as a \0.  This
               "works" around that issue (causes segfault otherwise) */

            if ( reply->str != '\0' )
                {
                    strlcpy(str, reply->str, size);
                }
            else
                {
                    strlcpy(str, " ", size);
                }

        }
    else
        {

            strlcpy(str, reply->element[0]->str, size);

        }


    pthread_mutex_unlock(&RedisReaderMutex);
    freeReplyObject(reply);

}

#endif
