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
#include "redis.h"
#include "sagan-config.h"

#define 	REDIS_PREFIX	"sagan"

extern struct _SaganCounters *counters;
extern struct _Rule_Struct *rulestruct;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;

struct _Sagan_Redis_Write *Sagan_Redis_Write;

pthread_cond_t SaganRedisDoWork;
pthread_mutex_t SaganRedisWorkMutex;

int redis_msgslot;

/*******************************************************/
/* Xbit_Set_Redis - set/unset xbit in Redis (threaded) */
/*******************************************************/

void Xbit_Set_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    struct json_object *jobj;

    int r = 0;
    char tmp_ip[MAXIP] = { 0 };
    char tmp_data[MAX_SYSLOGMSG*2] = { 0 };

    for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
        {

            if ( rulestruct[rule_position].xbit_type[r] == XBIT_SET )
                {

                    Xbit_Return_Tracking_IP( rule_position, r, ip_src_char, ip_dst_char, tmp_ip, sizeof(tmp_ip));

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' set in Redis for %s for %d seconds", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], tmp_ip, rulestruct[rule_position].xbit_expire[r]);
                        }

                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {

                            jobj = json_object_new_object();

                            json_object *jsensor = json_object_new_string(config->sagan_sensor_name);
                            json_object_object_add(jobj,"sensor", jsensor);

                            json_object *jexpire = json_object_new_int(rulestruct[rule_position].xbit_expire[r]);
                            json_object_object_add(jobj,"expire", jexpire);

                            json_object *jsrc_ip = json_object_new_string(SaganProcSyslog_LOCAL->syslog_host);
                            json_object_object_add(jobj,"src-ip", jsrc_ip);

                            json_object *jpriority = json_object_new_string(SaganProcSyslog_LOCAL->syslog_priority);
                            json_object_object_add(jobj,"priority", jpriority);

                            json_object *jfacility = json_object_new_string(SaganProcSyslog_LOCAL->syslog_facility);
                            json_object_object_add(jobj,"facility", jfacility);

                            json_object *jlevel = json_object_new_string(SaganProcSyslog_LOCAL->syslog_level);
                            json_object_object_add(jobj,"level", jlevel);

                            json_object *jprogram = json_object_new_string(SaganProcSyslog_LOCAL->syslog_program);
                            json_object *jtag = json_object_new_string(SaganProcSyslog_LOCAL->syslog_tag);
                            json_object_object_add(jobj,"tag", jtag);

                            json_object *jdate = json_object_new_string(SaganProcSyslog_LOCAL->syslog_date);
                            json_object_object_add(jobj,"date", jdate);

                            json_object *jtime = json_object_new_string(SaganProcSyslog_LOCAL->syslog_time);
                            json_object_object_add(jobj,"time", jtime);

                            json_object_object_add(jobj,"program", jprogram);

                            json_object *jmessage = json_object_new_string(SaganProcSyslog_LOCAL->syslog_message);
                            json_object_object_add(jobj,"message", jmessage);

                            json_object *jsignature = json_object_new_string(rulestruct[rule_position].s_msg);
                            json_object_object_add(jobj,"signature", jsignature);

                            json_object *jsid = json_object_new_int64(rulestruct[rule_position].s_sid);
                            json_object_object_add(jobj,"sid", jsid);

                            json_object *jrev = json_object_new_int(rulestruct[rule_position].s_rev);
                            json_object_object_add(jobj,"rev", jrev);

                            snprintf(tmp_data, sizeof(tmp_data), "%s", json_object_to_json_string(jobj));
                            tmp_data[sizeof(tmp_data) - 1] = '\0';

                            /* Send to redis */

                            pthread_mutex_lock(&SaganRedisWorkMutex);

                            strlcpy(Sagan_Redis_Write[redis_msgslot].command, "SET", sizeof(Sagan_Redis_Write[redis_msgslot].command));
                            snprintf(Sagan_Redis_Write[redis_msgslot].key, sizeof(Sagan_Redis_Write[redis_msgslot].key), "%s:%s:%s:%s", REDIS_PREFIX, config->sagan_cluster_name, rulestruct[rule_position].xbit_name[r], tmp_ip);

                            strlcpy(Sagan_Redis_Write[redis_msgslot].value, tmp_data, sizeof(Sagan_Redis_Write[redis_msgslot].value));
                            Sagan_Redis_Write[redis_msgslot].expire = rulestruct[rule_position].xbit_expire[r];

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

                    Xbit_Return_Tracking_IP( rule_position, r, ip_src_char, ip_dst_char, tmp_ip, sizeof(tmp_ip));

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' for %s unset in Redis", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], tmp_ip);
                        }

                    if ( redis_msgslot < config->redis_max_writer_threads )
                        {

                            pthread_mutex_lock(&SaganRedisWorkMutex);

                            strlcpy(Sagan_Redis_Write[redis_msgslot].command, "DEL", sizeof(Sagan_Redis_Write[redis_msgslot].command));
                            snprintf(Sagan_Redis_Write[redis_msgslot].key, sizeof(Sagan_Redis_Write[redis_msgslot].key), "%s:%s:%s:%s", REDIS_PREFIX, config->sagan_cluster_name, rulestruct[rule_position].xbit_name[r], tmp_ip);
                            Sagan_Redis_Write[redis_msgslot].value[0] = '\0';
                            Sagan_Redis_Write[redis_msgslot].expire = 0;

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
    char redis_command[64] = { 0 };
    char redis_results[32] = { 0 };
    char tmp_ip[MAXIP] = { 0 };

    for (r = 0; r < rulestruct[rule_position].xbit_count; r++)
        {

            Xbit_Return_Tracking_IP( rule_position, r, ip_src_char, ip_dst_char, tmp_ip, sizeof(tmp_ip));

            snprintf(redis_command, sizeof(redis_command),
                     "GET %s:%s:%s:%s", REDIS_PREFIX, config->sagan_cluster_name, rulestruct[rule_position].xbit_name[r], tmp_ip);

            Redis_Reader ( (char *)redis_command, redis_results, sizeof(redis_results) );

            if ( redis_results[0] == '\0' && rulestruct[rule_position].xbit_type[r] == XBIT_ISSET )
                {

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' was not found IP address %s for isset. Returning false.", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], tmp_ip);
                        }

                    return(false);
                }

            else if ( redis_results[0] != '\0' && rulestruct[rule_position].xbit_type[r] == XBIT_ISNOTSET )
                {

                    if ( debug->debugxbit )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] Xbit '%s' was found for IP address %s for isnotset. Returning false.", __FILE__, __LINE__, rulestruct[rule_position].xbit_name[r], tmp_ip);
                        }


                    return(false);
                }
        }

    if ( debug->debugxbit )
        {
            Sagan_Log(DEBUG, "[%s, line %d] Rule matches all xbit conditions. Returning true.", __FILE__, __LINE__);
        }

    return(true);

}

/******************************************************************************************
 * Xbit_Return_Tracking_IP - We don't use tracking hashes with Redis.  We use the actual
 * Actual IP addresses so that it's easier to "see" in Redis.
 ******************************************************************************************/

void Xbit_Return_Tracking_IP ( int rule_position, int xbit_position, char *ip_src_char, char *ip_dst_char, char *str, size_t size )
{

    /* These 1,2,3 values should really be defined */

    if ( rulestruct[rule_position].xbit_direction[xbit_position] == 1 )
        {
            snprintf(str, size, "%s", ip_src_char);
        }

    else if ( rulestruct[rule_position].xbit_direction[xbit_position] == 2 )
        {
            snprintf(str, size, "%s", ip_dst_char);
        }

    else if (  rulestruct[rule_position].xbit_direction[xbit_position] == 3 )
        {
            snprintf(str, size, "%s:%s",  ip_src_char, ip_dst_char);
        }

}

#endif
