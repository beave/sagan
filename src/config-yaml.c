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

/* config-yaml.c
 *
 * Loads the sagan.yaml configuration file into memory.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "version.h"
#include "sagan.h"
#include "sagan-defs.h"
#include "config-yaml.h"
#include "rules.h"
#include "sagan-config.h"
#include "classifications.h"
#include "gen-msg.h"
#include "protocol-map.h"
#include "references.h"
#include "parsers/parsers.h"

/* Processors */

#include "processors/blacklist.h"
#include "processors/perfmon.h"
#include "processors/bro-intel.h"

#ifdef HAVE_LIBYAML
#include <yaml.h>
#endif


#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"

sbool bluedot_load;

#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/unified2.h"
#endif

#ifdef HAVE_LIBLOGNORM
#include <liblognorm.h>
#include "liblognormalize.h"
struct liblognorm_struct *liblognormstruct;
int liblognorm_count;
#endif

#ifdef HAVE_LIBMAXMINDDB
#include "geoip2.h"
#endif

struct _SaganConfig *config;
struct _SaganDebug *debug;
struct _SaganVar *var;
struct _SaganCounters *counters;
struct _Rules_Loaded *rules_loaded;
struct _Rule_Struct *rulestruct;

#ifndef HAVE_LIBYAML
** You must of LIBYAML installed! **
#endif

sbool reload_rules;

pthread_mutex_t SaganRulesLoadedMutex;
pthread_mutex_t CounterLoadConfigGenericMutex=PTHREAD_MUTEX_INITIALIZER;


#ifdef HAVE_LIBYAML

void Load_YAML_Config( char *yaml_file )
{

    struct stat filecheck;

    yaml_parser_t parser;
    yaml_event_t  event;

    sbool done = 0;

    int check = 0;

    unsigned char type = 0;
    unsigned char sub_type = 0;
    unsigned char toggle = 0;

    char *tok = NULL;

    char tmp[CONFBUF] = { 0 };

    char last_pass[128] = { 0 };

    int a;

    reload_rules = true;

    /* Set some system defaults */

    if (!strcmp(config->sagan_config, yaml_file))
        {

            strlcpy(config->sagan_sensor_name, SENSOR_NAME, sizeof(config->sagan_sensor_name));
            strlcpy(config->sagan_lockfile, LOCKFILE, sizeof(config->sagan_lockfile));
            strlcpy(config->sagan_log_path, SAGANLOGPATH, sizeof(config->sagan_log_path));
            strlcpy(config->sagan_rule_path, RULE_PATH, sizeof(config->sagan_rule_path));
            strlcpy(config->ipc_directory, IPC_DIRECTORY, sizeof(config->ipc_directory));
            strlcpy(config->external_net, EXTERNAL_NET, sizeof(config->external_net));
            strlcpy(config->home_net, HOME_NET, sizeof(config->home_net));

            config->sagan_host[0] = '\0';
            config->sagan_port = 514;

            config->max_threshold_by_src = DEFAULT_IPC_THRESH_BY_SRC;
            config->max_threshold_by_dst = DEFAULT_IPC_THRESH_BY_DST;
            config->max_threshold_by_srcport = DEFAULT_IPC_THRESH_BY_SRC_PORT;
            config->max_threshold_by_dstport = DEFAULT_IPC_THRESH_BY_DST_PORT;
            config->max_threshold_by_username = DEFAULT_IPC_THRESH_BY_USERNAME;

            config->max_after_by_src = DEFAULT_IPC_AFTER_BY_SRC;
            config->max_after_by_dst = DEFAULT_IPC_AFTER_BY_DST;
            config->max_after_by_srcport = DEFAULT_IPC_AFTER_BY_SRC_PORT;
            config->max_after_by_dstport = DEFAULT_IPC_AFTER_BY_DST_PORT;
            config->max_after_by_username = DEFAULT_IPC_AFTER_BY_USERNAME;

            config->max_track_clients = DEFAULT_IPC_CLIENT_TRACK_IPC;
            config->pp_sagan_track_clients = TRACK_TIME;

            config->sagan_proto = 17;           /* Default to UDP */
            config->max_processor_threads = MAX_PROCESSOR_THREADS;

            config->eve_fd              = -1;
            config->sagan_alert_fd      = -1;
            config->sagan_fast_fd       = -1;
            config->sagan_log_fd        = -1;
            config->perfmonitor_file_fd = -1;

            /* Copy default FIFO */

            if ( config->sagan_is_file == false )
                {
                    config->sagan_fifo[0] = '\0';

                    strlcpy(config->sagan_fifo, FIFO, sizeof(config->sagan_fifo));
                }

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)

            config->sagan_fifo_size = MAX_FIFO_SIZE;

#endif

#ifdef WITH_BLUEDOT

            /* Bluedot defaults */

            strlcpy(config->bluedot_device_id, "NO_DEVICE_ID", sizeof(config->bluedot_device_id));
            config->bluedot_timeout = 120;

            config->bluedot_cat[0] = '\0';
            config->bluedot_url[0] = '\0';

#endif

#ifdef WITH_SYSLOG

            config->sagan_syslog_facility = DEFAULT_SYSLOG_FACILITY;
            config->sagan_syslog_priority = DEFAULT_SYSLOG_PRIORITY;
            config->sagan_syslog_options = LOG_PID;

#endif

#ifdef HAVE_LIBESMTP

            strlcpy(config->sagan_email_subject, DEFAULT_SMTP_SUBJECT, sizeof(config->sagan_email_subject));
            config->sagan_esmtp_from[0] = '\0';
            config->sagan_esmtp_server[0] = '\0';

#endif

#ifdef HAVE_LIBPCAP

            strlcpy(config->plog_interface, PLOG_INTERFACE, sizeof(config->plog_interface));
            strlcpy(config->plog_filter, PLOG_FILTER, sizeof(config->plog_filter));
            strlcpy(config->plog_logdev, PLOG_LOGDEV, sizeof(config->plog_logdev));

#endif

#ifdef HAVE_LIBHIREDIS

#define DEFAULT_REDIS_MAX_WRITER_THREADS 10

            config->redis_password[0] = '\0';
            config->redis_max_writer_threads = DEFAULT_REDIS_MAX_WRITER_THREADS;

#endif


        }

    if (stat(config->sagan_config, &filecheck) != false )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] The configuration file '%s' cannot be found! Abort!", __FILE__, __LINE__, config->sagan_config);
        }

    FILE *fh = fopen(yaml_file, "r");

    if (!yaml_parser_initialize(&parser))
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to initialize the libyaml parser. Abort!", __FILE__, __LINE__);
        }

    if (fh == NULL)
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Failed to open the configuration file '%s' Abort!", __FILE__, __LINE__, yaml_file);
        }

    /* Set input file */

    yaml_parser_set_input_file(&parser, fh);

    while(!done)
        {

            if (!yaml_parser_parse(&parser, &event))
                {

                    /* Useful YAML vars: parser.context_mark.line+1, parser.context_mark.column+1, parser.problem, parser.problem_mark.line+1,
                       parser.problem_mark.column+1 */

                    Sagan_Log(S_ERROR, "[%s, line %d] libyam parse error at line %d in '%s'", __FILE__, __LINE__, parser.problem_mark.line+1, config->sagan_config);

                }

            if ( event.type == YAML_DOCUMENT_START_EVENT )
                {

                    if ( debug->debugload )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] YAML_DOCUMENT_START_EVENT", __FILE__, __LINE__);
                        }

                    yaml_version_directive_t *ver = event.data.document_start.version_directive;

                    if ( ver == NULL )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Invalid configuration file. Configuration must start with \"%%YAML 1.1\"", __FILE__, __LINE__);
                        }

                    int major = ver->major;
                    int minor = ver->minor;

                    if (! (major == YAML_VERSION_MAJOR && minor == YAML_VERSION_MINOR) )
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Configuration has a invalid YAML version.  Must be 1.1 or above", __FILE__, __LINE__);
                        }

                }

            else if ( event.type == YAML_STREAM_END_EVENT )
                {

                    done = true;

                    if ( debug->debugload )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] YAML_STREAM_END_EVENT", __FILE__, __LINE__);
                        }
                }

            else if ( event.type == YAML_MAPPING_START_EVENT )
                {

                    toggle = 1;

                    if ( debug->debugload )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] YAML_MAPPING_START_EVENT", __FILE__, __LINE__);
                        }
                }

            else if ( event.type == YAML_MAPPING_END_EVENT )
                {

                    toggle = 0;
                    sub_type = 0;

                    if ( debug->debugload )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] YAML_MAPPING_END_EVENT", __FILE__, __LINE__);
                        }
                }

            else if ( event.type == YAML_SCALAR_EVENT )
                {

                    char *value = (char *)event.data.scalar.value;

                    if ( debug->debugload )
                        {
                            Sagan_Log(S_DEBUG, "[%s, line %d] YAML_SCALAR_EVENT - Value: \"%s\"", __FILE__, __LINE__, value);
                        }

                    /****** Primary Types *******************************************/

                    /************************/
                    /**** Load variables ****/
                    /************************/

                    if ( type == YAML_TYPE_VAR )
                        {

                            if ( toggle == 1 )
                                {

                                    var = (_SaganVar *) realloc(var, (counters->var_count+1) * sizeof(_SaganVar));

                                    if ( var == NULL )
                                        {
                                            Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for var. Abort!", __FILE__, __LINE__);
                                        }

                                    snprintf(var[counters->var_count].var_name, sizeof(var[counters->var_count].var_name)-1, "$%s", value);
                                    var[counters->var_count].var_name[sizeof(var[counters->var_count].var_name)-1] = 0;
                                    toggle = 0;

                                }
                            else
                                {

                                    if (strcmp(var[counters->var_count].var_name, ""))
                                        {

                                            /* If "file:/" is found, we load values from a file */

                                            if (Sagan_strstr(value, "file:/"))
                                                {

                                                    strtok_r(value, ":", &tok);

                                                    char *filename;
                                                    char tmpbuf[CONFBUF];

                                                    FILE *varfile;

                                                    sbool check = 0;

                                                    filename = strtok_r(NULL, ":", &tok);

                                                    if ((varfile = fopen(filename, "r")) == NULL)
                                                        {
                                                            fprintf(stderr, "[E] [%s, line %d] Cannot open var file:%s\n", __FILE__,  __LINE__, filename);
                                                            exit(-1);
                                                        }


                                                    while(fgets(tmpbuf, sizeof(tmpbuf), varfile) != NULL)
                                                        {


                                                            /* Stuff to skip */

                                                            if (tmpbuf[0] == '#') continue;
                                                            if (tmpbuf[0] == ';') continue;
                                                            if (tmpbuf[0] == 10 ) continue;
                                                            if (tmpbuf[0] == 32 ) continue;

                                                            /* Simple check to see if this is the first entry or not.  This is to keep our
                                                               "," on mark */

                                                            Remove_Return(tmpbuf);

                                                            if ( debug->debugload )
                                                                {

                                                                    Sagan_Log(S_DEBUG, "[%s, line %d] Variable from file \"%s\" var \"%s\" loaded: \"%s\"", __FILE__, __LINE__, filename, var[counters->var_count].var_name, tmpbuf);
                                                                }

                                                            if ( check == 0 )
                                                                {

                                                                    check = 1;

                                                                }

                                                            /* Append to the var */

                                                            strlcat(var[counters->var_count].var_value, tmpbuf, sizeof(var[counters->var_count].var_value));

                                                        }

                                                    fclose(varfile);

                                                    if ( debug->debugload )
                                                        {

                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Final load from file for \"%s\" value \"%s\"", __FILE__, __LINE__, var[counters->var_count].var_name, var[counters->var_count].var_value);

                                                        }

                                                    toggle = 1;

                                                }
                                            else
                                                {

                                                    /* If "file:/" is not found, we load like a normal variable */

                                                    strlcpy(var[counters->var_count].var_value, value, sizeof(var[counters->var_count].var_value));

                                                    if ( debug->debugload )
                                                        {

                                                            Sagan_Log(S_DEBUG, "[%s, line %d] Variable: \"%s == %s\"", __FILE__, __LINE__, var[counters->var_count].var_name, var[counters->var_count].var_value);
                                                        }

                                                    pthread_mutex_lock(&CounterLoadConfigGenericMutex);
                                                    counters->var_count++;
                                                    pthread_mutex_unlock(&CounterLoadConfigGenericMutex);

                                                    toggle = 1;

                                                }
                                        }
                                }

                        } /* if type == YAML_TYPE_VAR */


                    else if ( type == YAML_TYPE_INCLUDES )
                        {

                            if ( toggle == 1 )
                                {

                                    toggle = 0;

                                }
                            else
                                {


                                    Var_To_Value(value, tmp, sizeof(tmp));
                                    Sagan_Log(S_NORMAL, "Loading included file '%s'.", tmp);
                                    Load_YAML_Config(tmp);

                                    toggle = 1;

                                }
                        }


                    else if ( type == YAML_TYPE_SAGAN_CORE )
                        {

                            if (!strcmp(value, "core"))
                                {
                                    sub_type = YAML_SAGAN_CORE_CORE;
                                }

                            else if (!strcmp(value, "selector" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_SELECTOR;
                                }

                            else if (!strcmp(value, "redis-server" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_REDIS;
                                }

                            else if (!strcmp(value, "mmap-ipc" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_MMAP_IPC;
                                }

                            else if (!strcmp(value, "ignore_list" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_IGNORE_LIST;
                                }

                            else if (!strcmp(value, "geoip" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_GEOIP;
                                }

                            else if (!strcmp(value, "liblognorm" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_LIBLOGNORM;
                                }

                            else if (!strcmp(value, "plog" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_PLOG;
                                }

                            /* Enter sub-types */

                            if ( sub_type == YAML_SAGAN_CORE_CORE )
                                {

                                    if (!strcmp(last_pass, "sensor-name"))
                                        {
                                            strlcpy(config->sagan_sensor_name, value, sizeof(config->sagan_sensor_name));
                                        }

                                    else if (!strcmp(last_pass, "default-host"))
                                        {
                                            strlcpy(config->sagan_host, value, sizeof(config->sagan_host));
                                        }

                                    else if (!strcmp(last_pass, "default-port"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->sagan_port = atoi(tmp);

                                            if ( config->sagan_port == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan:core 'default-port' is set to zero. Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "default-proto"))
                                        {

                                            if ( !strcasecmp(value, "udp") )
                                                {
                                                    config->sagan_proto = 17;
                                                }

                                            else if ( !strcasecmp(value, "tcp") )
                                                {
                                                    config->sagan_proto = 6;
                                                }

                                            else if ( !strcasecmp(value, "icmp") )
                                                {
                                                    config->sagan_proto = 1;
                                                }

                                            else if ( strcasecmp(value, "tcp") && strcasecmp(value, "udp") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'default_proto' can only be TCP, UDP or ICMP.", __FILE__, __LINE__);

                                                }

                                        }

                                    else if (!strcmp(last_pass, "dns-warnings"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->disable_dns_warnings = true;
                                                }

                                        }

                                    else if (!strcmp(last_pass, "source-lookup"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->syslog_src_lookup = true;
                                                }
                                        }

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)

                                    else if (!strcmp(last_pass, "fifo-size"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->sagan_fifo_size = atoi(tmp);

                                            if ( config->sagan_fifo_size == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan:core 'fifo-size' is set to zero. Abort!", __FILE__, __LINE__);
                                                }

                                            if ( config->sagan_fifo_size != 65536 &&
                                                    config->sagan_fifo_size != 131072 &&
                                                    config->sagan_fifo_size != 262144 &&
                                                    config->sagan_fifo_size != 524288 &&
                                                    config->sagan_fifo_size != 1048576 )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan:core 'fifo-size' is invalid.  Valid value are 65536, 131072, 262144, 524288, and 1048576. Abort!", __FILE__, __LINE__);
                                                }

                                        }
#endif
                                    else if (!strcmp(last_pass, "max-threads"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_processor_threads = atoi(tmp);

                                            if ( config->max_processor_threads  == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan:core 'max_threads' is zero/invalid. Abort!", __FILE__, __LINE__);
                                                }

                                        }

                                    else if (!strcmp(last_pass, "classification"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            Load_Classifications(tmp);

                                        }

                                    else if (!strcmp(last_pass, "reference"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            Load_Reference(tmp);

                                        }

                                    else if (!strcmp(last_pass, "gen-msg-map"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            Load_Gen_Map(tmp);

                                        }

                                    else if (!strcmp(last_pass, "protocol-map"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            Load_Protocol_Map(tmp);

                                        }

                                    else if (!strcmp(last_pass, "xbit-storage"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));

                                            if (strcmp(tmp, "mmap") && strcmp(tmp, "redis"))
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|xbit-storage is set to an invalid type '%s'. It must be 'mmap' or 'redis'. Abort!", __FILE__, __LINE__, tmp);

                                                }

                                            if (!strcmp(tmp, "redis"))
                                                {

                                                    config->xbit_storage = XBIT_STORAGE_REDIS;

                                                }
                                            else
                                                {

                                                    config->xbit_storage = XBIT_STORAGE_MMAP;

                                                }
                                        }

                                } /* if sub_type == YAML_SAGAN_CORE_CORE */

                            if ( sub_type == YAML_SAGAN_CORE_MMAP_IPC )
                                {

                                    if (!strcmp(last_pass, "ipc-directory"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->ipc_directory, tmp, sizeof(config->ipc_directory));

                                        }

                                    else if (!strcmp(last_pass, "xbit"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_xbits = atoi(tmp);

                                            if ( config->max_xbits == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'xbits' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "threshold-by-src"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_threshold_by_src = atoi(tmp);

                                            if ( config->max_threshold_by_src == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'threshold-by-src' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "threshold-by-dst"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_threshold_by_dst = atoi(tmp);

                                            if ( config->max_threshold_by_dst == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'threshold-by-dst' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "threshold-by-username"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_threshold_by_username = atoi(tmp);

                                            if ( config->max_threshold_by_username == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'threshold-by-username' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "after-by-src"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_after_by_src = atoi(tmp);

                                            if ( config->max_after_by_src == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'after-by-src' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "after-by-dst"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_after_by_dst = atoi(tmp);

                                            if ( config->max_after_by_dst == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'after-by-dst' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "after-by-username"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_after_by_username = atoi(tmp);

                                            if ( config->max_after_by_username == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'after-by-username' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "track-clients"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_track_clients = atoi(tmp);

                                            if ( config->max_track_clients == 0 )
                                                {
                                                    Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'track-clients' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                } /* if sub_type == YAML_SAGAN_CORE_MMAP_IPC */

                            if ( sub_type == YAML_SAGAN_CORE_IGNORE_LIST )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->sagan_droplist_flag = true;
                                                }
                                        }

                                    if (!strcmp(last_pass, "ignore_file"))
                                        {

                                            if (config->sagan_droplist_flag == true)
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    strlcpy(config->sagan_droplistfile, tmp, sizeof(config->sagan_droplistfile));

                                                }
                                        }

                                } /* if sub_type == YAML_SAGAN_CORE_IGNORE_LIST */

#ifndef HAVE_LIBHIREDIS

                            if ( sub_type == YAML_SAGAN_CORE_REDIS )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] Sagan was not compiled with hiredis (Redis) support!", __FILE__, __LINE__);

                                                }
                                        }
                                } /* if sub_type == YAML_SAGAN_CORE_REDIS */
#endif

#ifdef HAVE_LIBHIREDIS

                            if ( sub_type == YAML_SAGAN_CORE_REDIS )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    config->redis_flag = true;

                                                }
                                        }


                                    if ( config->redis_flag == true )
                                        {

                                            if (!strcmp(last_pass, "server"))
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    strlcpy(config->redis_server, tmp, sizeof(config->redis_server));

                                                }

                                            if (!strcmp(last_pass, "port"))
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    config->redis_port = atoi(tmp);

                                                    if ( config->redis_port == 0 )
                                                        {
                                                            Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|redis-server - Redis 'port' is set to zero.  Abort!", __FILE__, __LINE__);
                                                        }
                                                }

                                            if (!strcmp(last_pass, "password"))
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    strlcpy(config->redis_password, tmp, sizeof(config->redis_password));
                                                }

                                            if (!strcmp(last_pass, "writer_threads"))
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    config->redis_max_writer_threads = atoi(tmp);

                                                    if ( config->redis_max_writer_threads == 0 )
                                                        {
                                                            Sagan_Log(S_ERROR, "[%s, line %d] sagan-core|redis-server - Redis 'writer_threads' is set to zero.  Abort!", __FILE__, __LINE__);
                                                        }

                                                }

                                        }

                                } /* if sub_type == YAML_SAGAN_CORE_REDIS */

#endif

#ifndef HAVE_LIBMAXMINDDB

                            if ( sub_type == YAML_SAGAN_CORE_GEOIP )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] Sagan was not compiled with Maxmind's \"GeoIP2\" support!", __FILE__, __LINE__);

                                                }
                                        }
                                } /* if sub_type == YAML_SAGAN_CORE_GEOIP */
#endif

#ifdef HAVE_LIBMAXMINDDB

                            if ( sub_type == YAML_SAGAN_CORE_GEOIP )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    config->have_geoip2 = true;

                                                }
                                        }

                                    if (!strcmp(last_pass, "country_database"))
                                        {

                                            if ( config->have_geoip2 == true )
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    strlcpy(config->geoip2_country_file, tmp, sizeof(config->geoip2_country_file));

                                                    config->have_geoip2 = true;

                                                }
                                        }

                                } /* if sub_type == YAML_SAGAN_CORE_GEOIP */
#endif

#ifndef HAVE_LIBLOGNORM

                            if ( sub_type == YAML_SAGAN_CORE_LIBLOGNORM )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] Sagan was not compiled with liblognorm support!", __FILE__, __LINE__);

                                                }
                                        }

                                } /* if sub_type == YAML_SAGAN_CORE_GEOIP */
#endif

#ifdef HAVE_LIBLOGNORM

                            if ( sub_type == YAML_SAGAN_CORE_LIBLOGNORM )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->liblognorm_load = true;

                                                }
                                        }

                                    if (!strcmp(last_pass, "normalize_rulebase"))
                                        {

                                            if ( config->liblognorm_load == true )
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    Liblognorm_Load(tmp);
                                                }

                                        }
                                }
#endif


#ifndef HAVE_LIBPCAP

                            if ( sub_type == YAML_SAGAN_CORE_PLOG )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] Sagan was not compiled with libpcap support!", __FILE__, __LINE__);

                                                }

                                        }

                                } /* sub_type == YAML_SAGAN_CORE_PLOG */
#endif

#ifdef HAVE_LIBPCAP

                            if ( sub_type == YAML_SAGAN_CORE_PLOG )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->plog_flag = true;
                                                }
                                        }

                                    if ( config->plog_flag == true )
                                        {

                                            if (!strcmp(last_pass, "interface"))
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    strlcpy(config->plog_interface, tmp, sizeof(config->plog_interface));

                                                }

                                            else if (!strcmp(last_pass, "bpf-filter"))
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    strlcpy(config->plog_filter, tmp, sizeof(config->plog_filter));

                                                }

                                            else if (!strcmp(last_pass, "log-device"))
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    strlcpy(config->plog_logdev, tmp, sizeof(config->plog_logdev));

                                                }

                                            else if (!strcmp(last_pass, "promiscuous"))
                                                {

                                                    if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                        {
                                                            config->plog_promiscuous = 1;
                                                        }
                                                }
                                        }
                                }
#endif
                            if ( sub_type == YAML_SAGAN_CORE_SELECTOR )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    config->selector_flag = true;

                                                }
                                        }

                                    if ( config->selector_flag == true )
                                        {

                                            if (!strcmp(last_pass, "name"))
                                                {

                                                    Var_To_Value(value, tmp, sizeof(tmp));
                                                    strlcpy(config->selector_name, tmp, sizeof(config->selector_name));

                                                }
                                        }

                                } /* if sub_type == YAML_SAGAN_CORE_SELECTOR */


                        } /*  else if ( type == YAML_TYPE_SAGAN_CORE ) */

                    else if ( type == YAML_TYPE_PROCESSORS )
                        {

                            if (!strcmp(value, "track-clients"))
                                {
                                    sub_type = YAML_PROCESSORS_TRACK_CLIENTS;
                                }

                            else if (!strcmp(value, "perfmonitor"))
                                {
                                    sub_type = YAML_PROCESSORS_PERFMON;
                                }

                            else if (!strcmp(value, "blacklist"))
                                {
                                    sub_type = YAML_PROCESSORS_BLACKLIST;
                                }

                            else if (!strcmp(value, "bluedot"))
                                {
                                    sub_type = YAML_PROCESSORS_BLUEDOT;
                                }

                            else if (!strcmp(value, "bro-intel"))
                                {
                                    sub_type = YAML_PROCESSORS_BROINTEL;
                                }

                            else if (!strcmp(value, "dynamic_load"))
                                {
                                    sub_type = YAML_PROCESSORS_DYNAMIC_LOAD;
                                }

                            if ( sub_type == YAML_PROCESSORS_TRACK_CLIENTS )
                                {

                                    if (!strcasecmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    config->sagan_track_clients_flag = true;
                                                }

                                        }

                                    else if ( !strcmp(last_pass, "timeout") && config->sagan_track_clients_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->pp_sagan_track_clients = atoi(tmp);

                                            if ( config->pp_sagan_track_clients == 0 )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'processor' : 'track_clients' - 'timeout' has to be a non-zero number. Abort!!", __FILE__, __LINE__);

                                                }

                                        }
                                }

                            else if ( sub_type == YAML_PROCESSORS_PERFMON )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->perfmonitor_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "time") && config->perfmonitor_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->perfmonitor_time = atoi(tmp);

                                            if ( config->perfmonitor_time == 0 )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'processor' : 'perfmonitor' - 'time' has to be a non-zero number. Abort!!", __FILE__, __LINE__);
                                                }

                                        }

                                    else if (!strcmp(last_pass, "filename") && config->perfmonitor_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->perfmonitor_file_name, tmp, sizeof(config->perfmonitor_file_name));

                                        }

                                } /* if sub_type == YAML_PROCESSORS_PERFMON */

                            else if ( sub_type == YAML_PROCESSORS_BLACKLIST )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->blacklist_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "filename") && config->blacklist_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->blacklist_files, tmp, sizeof(config->blacklist_files));
                                        }

                                } /* if sub_type == YAML_PROCESSORS_BLACKLIST */

#ifndef WITH_BLUEDOT

                            else if ( sub_type == YAML_PROCESSORS_BLUEDOT )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] The Sagan's configuration file has Bluedot enabled, but Sagan wasn't compiled with Bluedot support! Abort!", __FILE__, __LINE__);

                                                }
                                        }
                                }

#endif

#ifdef WITH_BLUEDOT

                            else if ( sub_type == YAML_PROCESSORS_BLUEDOT )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->bluedot_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "device-id") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->bluedot_device_id, tmp, sizeof(config->bluedot_device_id));
                                        }

                                    else if (!strcmp(last_pass, "max-cache") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_max_cache = strtoull(tmp, NULL, 10);

                                            if ( config->bluedot_max_cache == 0 )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'max-cache' has to be a non-zero number. Abort!!", __FILE__, __LINE__);
                                                }

                                        }

                                    else if (!strcmp(last_pass, "cache-timeout") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_timeout = atoi(tmp) * 60;

                                            if ( config->bluedot_timeout == 0 )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'cache-timeout' has to be a non-zero number. Abort!!", __FILE__, __LINE__);

                                                }
                                        }

                                    else if (!strcmp(last_pass, "categories") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->bluedot_cat, tmp, sizeof(config->bluedot_cat));
                                        }

                                    else if (!strcmp(last_pass, "url") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->bluedot_url, tmp, sizeof(config->bluedot_url));
                                        }

                                } /* if sub_type == YAML_PROCESSORS_BLUEDOT */

#endif


                            else if ( sub_type == YAML_PROCESSORS_BROINTEL )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->brointel_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "filename") && config->brointel_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->brointel_files, tmp, sizeof(config->brointel_files));

                                        }

                                } /* if sub_type == YAML_PROCESSORS_BROINTEL */

                            else if ( sub_type == YAML_PROCESSORS_DYNAMIC_LOAD )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->dynamic_load_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "sample-rate") && config->dynamic_load_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->dynamic_load_sample_rate = atoi(tmp);

                                            if ( config->dynamic_load_sample_rate == 0 )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'processor' : 'dynamic_load' - 'sample_rate' has to be a non-zero number. Abort!!", __FILE__, __LINE__);

                                                }

                                        }

                                    else if (!strcmp(last_pass, "type") && config->dynamic_load_flag == true )
                                        {

                                            if (!strcmp(value, "dynamic_load"))
                                                {
                                                    config->dynamic_load_type = 0;
                                                }

                                            else if (!strcmp(value, "log_only"))
                                                {
                                                    config->dynamic_load_type = 1;
                                                }

                                            else if (!strcmp(value, "alert"))
                                                {
                                                    config->dynamic_load_type = 2;
                                                }

                                        }

                                } /* if sub_type == YAML_PROCESSORS_DYNAMIC_LOAD */

                        } /* else if ( type == YAML_TYPE_PROCESSORS */

                    else if ( type == YAML_TYPE_OUTPUT )
                        {

                            if (!strcmp(value, "eve-log"))
                                {
                                    sub_type = YAML_OUTPUT_EVE;
                                }

                            else if (!strcmp(value, "alert"))
                                {
                                    sub_type = YAML_OUTPUT_ALERT;
                                }

                            else if (!strcmp(value, "fast"))
                                {
                                    sub_type = YAML_OUTPUT_FAST;
                                }

                            else if (!strcmp(value, "unified2"))
                                {
                                    sub_type = YAML_OUTPUT_UNIFIED2;
                                }

                            else if (!strcmp(value, "external"))
                                {
                                    sub_type = YAML_OUTPUT_EXTERNAL;
                                }

                            else if (!strcmp(value, "smtp"))
                                {
                                    sub_type = YAML_OUTPUT_SMTP;
                                }

                            else if (!strcmp(value, "snortsam"))
                                {
                                    sub_type = YAML_OUTPUT_SNORTSAM;
                                }

                            else if (!strcmp(value, "syslog"))
                                {
                                    sub_type = YAML_OUTPUT_SYSLOG;
                                }

                            if ( sub_type == YAML_OUTPUT_EVE )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->eve_flag = true;
                                                    strlcpy(config->eve_interface, "logs", sizeof(config->eve_interface)); 	/* Set a "default" value */
                                                }
                                        }

                                    else if ( !strcmp(last_pass, "filetype") && config->eve_flag == true )
                                        {

                                            if (!strcmp(value, "regular"))
                                                {
                                                    config->eve_type = 0;
                                                }

                                            // if (!strcmp(value, "something")) {
                                            // }
                                        }


                                    else if ( !strcmp(last_pass, "interface") && config->eve_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->eve_interface, tmp, sizeof(config->eve_interface));
                                        }

                                    else if ( !strcmp(last_pass, "filename") && config->eve_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->eve_filename, tmp, sizeof(config->eve_filename));
                                        }

                                    else if ( !strcmp(last_pass, "alerts") && config->eve_flag == true )
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->eve_alerts = true;
                                                }

                                        }


                                    else if ( !strcmp(last_pass, "logs") && config->eve_flag == true )
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->eve_logs = true;
                                                }

                                        }
                                }

                            else if ( sub_type == YAML_OUTPUT_ALERT )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->alert_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "filename") && config->alert_flag == true)
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->sagan_alert_filepath, tmp, sizeof(config->sagan_alert_filepath));

                                        }

                                } /* sub_type == YAML_OUTPUT_ALERT */

                            else if ( sub_type == YAML_OUTPUT_FAST )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->fast_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "filename") && config->fast_flag == true)
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->fast_filename, tmp, sizeof(config->fast_filename));

                                        }

                                } /* sub_type == YAML_OUTPUT_FAST */

#if !defined(HAVE_DNET_H) && !defined(HAVE_DUMBNET_H)

                            else if ( sub_type == YAML_OUTPUT_UNIFIED2 )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'unified2' output is enabled, but Sagan is not compiled with libdnet support. Abort!", __FILE__, __LINE__);
                                                }

                                        }
                                }
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

                            else if ( sub_type == YAML_OUTPUT_UNIFIED2 )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->sagan_unified2_flag = true;
                                                }

                                        }

                                    else if ( !strcmp(last_pass, "filename") && config->sagan_unified2_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->unified2_filepath, tmp, sizeof(config->unified2_filepath));
                                        }

                                    else if ( !strcmp(last_pass, "limit") && config->sagan_unified2_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->unified2_limit = atoi(tmp) * 1024 * 1024;

                                            if ( config->unified2_limit == 0 )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'outputs' : 'unified2' - 'limit' has to be a non-zero number. Abort!!", __FILE__, __LINE__);
                                                }
                                        }

                                } /* if sub_type == YAML_OUTPUT_UNIFIED2  */

#endif

                            else if ( sub_type == YAML_OUTPUT_EXTERNAL )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->sagan_external_output_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "command") && config->sagan_external_output_flag == true)
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->sagan_external_command, tmp, sizeof(config->sagan_external_command));

                                        }

                                } /* else if sub_type == YAML_OUTPUT_EXTERNAL ) */


#ifndef HAVE_LIBESMTP

                            else if ( sub_type == YAML_OUTPUT_SMTP )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'smtp' output is enabled, but Sagan is not compiled with libesmtp support. Abort!", __FILE__, __LINE__);
                                                }

                                        }
                                }
#endif

#ifdef HAVE_LIBESMTP

                            else if ( sub_type == YAML_OUTPUT_SMTP )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->sagan_esmtp_flag = true;
                                                }
                                        }

                                    else if ( !strcmp(last_pass, "from") && config->sagan_esmtp_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->sagan_esmtp_from, tmp, sizeof(config->sagan_esmtp_from));

                                        }

                                    else if ( !strcmp(last_pass, "server") && config->sagan_esmtp_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->sagan_esmtp_server, tmp, sizeof(config->sagan_esmtp_server));

                                        }

                                    else if ( !strcmp(last_pass, "subject") && config->sagan_esmtp_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->sagan_email_subject, tmp, sizeof(config->sagan_email_subject));

                                        }

                                } /* else if sub_type == YAML_OUTPUT_SMTP ) */

#endif

#ifndef WITH_SNORTSAM

                            else if ( sub_type == YAML_OUTPUT_SNORTSAM )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'snortsam' output is enabled, but Sagan is not compiled with Snortsam support. Abort!", __FILE__, __LINE__);
                                                }

                                        }
                                }

#endif

#ifdef WITH_SNORTSAM

                            else if ( sub_type == YAML_OUTPUT_SNORTSAM )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->sagan_fwsam_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "server") && config->sagan_fwsam_flag == true)
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->sagan_fwsam_info, tmp, sizeof(config->sagan_fwsam_info));

                                        }
                                }
#endif

#ifndef WITH_SYSLOG

                            else if ( sub_type == YAML_OUTPUT_SYSLOG )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(S_ERROR, "[%s, line %d] 'syslog' output is enabled, but Sagan is not compiled with syslog support. Abort!", __FILE__, __LINE__);
                                                }

                                        }
                                }

#endif

#ifdef WITH_SYSLOG

                            else if ( sub_type == YAML_OUTPUT_SYSLOG )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    config->sagan_syslog_flag = true;

                                                }
                                        }

                                    else if (!strcmp(last_pass, "facility") && config->sagan_syslog_flag == true )
                                        {

#ifdef LOG_AUTH
                                            if (!strcmp(value, "LOG_AUTH"))
                                                {
                                                    config->sagan_syslog_facility = LOG_AUTH;
                                                }
#endif

#ifdef LOG_AUTHPRIV
                                            if (!strcmp(value, "LOG_AUTHPRIV"))
                                                {
                                                    config->sagan_syslog_facility = LOG_AUTHPRIV;
                                                }
#endif

#ifdef LOG_CRON
                                            if (!strcmp(value, "LOG_CRON"))
                                                {
                                                    config->sagan_syslog_facility = LOG_CRON;
                                                }
#endif

#ifdef LOG_DAEMON
                                            if (!strcmp(value, "LOG_DAEMON"))
                                                {
                                                    config->sagan_syslog_facility = LOG_DAEMON;
                                                }
#endif

#ifdef LOG_FTP
                                            if (!strcmp(value, "LOG_FTP"))
                                                {
                                                    config->sagan_syslog_facility = LOG_FTP;
                                                }
#endif

#ifdef LOG_INSTALL
                                            if (!strcmp(value, "LOG_INSTALL"))
                                                {
                                                    config->sagan_syslog_facility = LOG_INSTALL;
                                                }
#endif

#ifdef LOG_KERN
                                            if (!strcmp(value, "LOG_KERN"))
                                                {
                                                    config->sagan_syslog_facility = LOG_KERN;
                                                }
#endif

#ifdef LOG_LPR
                                            if (!strcmp(value, "LOG_LPR"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LPR;
                                                }
#endif

#ifdef LOG_MAIL
                                            if (!strcmp(value, "LOG_MAIL"))
                                                {
                                                    config->sagan_syslog_facility = LOG_MAIL;
                                                }
#endif

#ifdef LOG_NETINFO
                                            if (!strcmp(value, "LOG_NETINFO"))
                                                {
                                                    config->sagan_syslog_facility = LOG_NETINFO;
                                                }
#endif

#ifdef LOG_RAS
                                            if (!strcmp(value, "LOG_RAS"))
                                                {
                                                    config->sagan_syslog_facility = LOG_RAS;
                                                }
#endif

#ifdef LOG_REMOTEAUTH
                                            if (!strcmp(value, "LOG_REMOTEAUTH"))
                                                {
                                                    config->sagan_syslog_facility = LOG_REMOTEAUTH;
                                                }
#endif

#ifdef LOG_NEWS
                                            if (!strcmp(value, "LOG_NEWS"))
                                                {
                                                    config->sagan_syslog_facility = LOG_NEWS;
                                                }
#endif

#ifdef LOG_SYSLOG
                                            if (!strcmp(value, "LOG_SYSLOG"))
                                                {
                                                    config->sagan_syslog_facility = LOG_SYSLOG;
                                                }
#endif

#ifdef LOG_USER
                                            if (!strcmp(value, "LOG_USER"))
                                                {
                                                    config->sagan_syslog_facility = LOG_USER;
                                                }
#endif

#ifdef LOG_UUCP
                                            if (!strcmp(value, "LOG_UUCP"))
                                                {
                                                    config->sagan_syslog_facility = LOG_UUCP;
                                                }
#endif

#ifdef LOG_LOCAL0
                                            if (!strcmp(value, "LOG_LOCAL0"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LOCAL0;
                                                }
#endif

#ifdef LOG_LOCAL1
                                            if (!strcmp(value, "LOG_LOCAL1"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LOCAL1;
                                                }
#endif

#ifdef LOG_LOCAL2
                                            if (!strcmp(value, "LOG_LOCAL2"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LOCAL2;
                                                }
#endif

#ifdef LOG_LOCAL3
                                            if (!strcmp(value, "LOG_LOCAL3"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LOCAL3;
                                                }
#endif

#ifdef LOG_LOCAL4
                                            if (!strcmp(value, "LOG_LOCAL4"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LOCAL4;
                                                }
#endif

#ifdef LOG_LOCAL5
                                            if (!strcmp(value, "LOG_LOCAL5"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LOCAL5;
                                                }
#endif

#ifdef LOG_LOCAL6
                                            if (!strcmp(value, "LOG_LOCAL6"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LOCAL6;
                                                }
#endif

#ifdef LOG_LOCAL7
                                            if (!strcmp(value, "LOG_LOCAL7"))
                                                {
                                                    config->sagan_syslog_facility = LOG_LOCAL7;
                                                }
#endif


                                        } /* !strcmp(last_pass, "facility") */

                                    else if (!strcmp(last_pass, "priority") && config->sagan_syslog_flag == true )
                                        {

#ifdef LOG_EMERG
                                            if (!strcmp(value, "LOG_EMERG"))
                                                {
                                                    config->sagan_syslog_priority = LOG_EMERG;
                                                }
#endif

#ifdef LOG_ALERT
                                            if (!strcmp(value, "LOG_ALERT"))
                                                {
                                                    config->sagan_syslog_priority = LOG_ALERT;
                                                }
#endif

#ifdef LOG_CRIT
                                            if (!strcmp(value, "LOG_CRIT"))
                                                {
                                                    config->sagan_syslog_priority = LOG_CRIT;
                                                }
#endif

#ifdef LOG_ERR
                                            if (!strcmp(value, "LOG_ERR"))
                                                {
                                                    config->sagan_syslog_priority = LOG_ERR;
                                                }
#endif

#ifdef LOG_WARNING
                                            if (!strcmp(value, "LOG_WARNING"))
                                                {
                                                    config->sagan_syslog_priority = LOG_WARNING;
                                                }
#endif

#ifdef LOG_NOTICE
                                            if (!strcmp(value, "LOG_NOTICE"))
                                                {
                                                    config->sagan_syslog_priority = LOG_NOTICE;
                                                }
#endif

#ifdef LOG_INFO
                                            if (!strcmp(value, "LOG_INFO"))
                                                {
                                                    config->sagan_syslog_priority = LOG_INFO;
                                                }
#endif

#ifdef LOG_DEBUG
                                            if (!strcmp(value, "LOG_DEBUG"))
                                                {
                                                    config->sagan_syslog_priority = LOG_DEBUG;
                                                }
#endif

                                        } /* !strcmp(last_pass, "priority") */

                                    else if (!strcmp(last_pass, "extra") && config->sagan_syslog_flag == true )
                                        {

#ifdef LOG_CONS
                                            if (!strcmp(value, "LOG_CONS"))
                                                {
                                                    config->sagan_syslog_options |= LOG_CONS;
                                                }
#endif

#ifdef LOG_NDELAY
                                            if (!strcmp(value, "LOG_NDELAY"))
                                                {
                                                    config->sagan_syslog_options |= LOG_NDELAY;
                                                }
#endif

#ifdef LOG_PERROR
                                            if (!strcmp(value, "LOG_PERROR"))
                                                {
                                                    config->sagan_syslog_options |= LOG_PERROR;
                                                }
#endif

#ifdef LOG_PID
                                            if (!strcmp(value, "LOG_PID"))
                                                {
                                                    config->sagan_syslog_options |= LOG_PID;
                                                }
#endif

#ifdef LOG_NOWAIT
                                            if (!strcmp(value, "LOG_NOWAIT"))
                                                {
                                                    config->sagan_syslog_options |= LOG_NOWAIT;
                                                }
#endif

                                        } /* !strcmp(last_pass, "extra") */

                                } /* if sub_type == YAML_OUTPUT_SYSLOG */
#endif
                        } /* else if ype == YAML_TYPE_OUTPUT */

                    else if ( type == YAML_TYPE_RULES )
                        {

#ifdef WITH_BLUEDOT

                            if ( config->bluedot_flag == true && bluedot_load == false )
                                {

                                    Sagan_Bluedot_Init();
                                    Sagan_Bluedot_Load_Cat();

                                    bluedot_load = true;

                                }

#endif

                            Var_To_Value(value, tmp, sizeof(tmp));
                            Load_Rules( (char*)tmp );

                            rules_loaded = (_Rules_Loaded *) realloc(rules_loaded, (counters->rules_loaded_count+1) * sizeof(_Rules_Loaded));

                            if ( rules_loaded == NULL )
                                {
                                    Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for rules_loaded. Abort!", __FILE__, __LINE__);
                                }

                            Var_To_Value(value, tmp, sizeof(tmp));
                            strlcpy(rules_loaded[counters->rules_loaded_count].ruleset, tmp, sizeof(rules_loaded[counters->rules_loaded_count].ruleset));

                            pthread_mutex_lock(&CounterLoadConfigGenericMutex);
                            counters->rules_loaded_count++;
                            pthread_mutex_unlock(&CounterLoadConfigGenericMutex);

                        }

                    strlcpy(last_pass, value, sizeof(last_pass));

                    /**** Tag types *************************************************/

                    /**************/
                    /**** vars ****/
                    /**************/

                    if (!strcmp(value, "vars") || !strcmp(value, "address-groups") ||
                            !strcmp(value, "port-groups") || !strcmp(value, "sagan-groups") ||
                            !strcmp(value, "misc-groups") || !strcmp(value, "aetas-groups"))
                        {

                            if ( debug->debugload )
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] **** Found variables ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_VAR;
                            toggle = 0;

                        } /* tag: var */

                    /*****************/
                    /**** include ****/
                    /*****************/

                    else if (!strcmp(value, "include"))
                        {

                            if ( debug->debugload )
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] **** Found include ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_INCLUDES;
                            toggle = 0;

                        }  /* tag: include */

                    /********************/
                    /**** Sagan core ****/
                    /********************/

                    else if (!strcmp(value, "sagan-core"))
                        {

                            if ( debug->debugload )
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] **** Found Sagan Core ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_SAGAN_CORE;
                            toggle = 0;

                        } /* tag: sagan-core */


                    /********************/
                    /**** Processors ****/
                    /********************/

                    else if (!strcmp(value, "processors"))
                        {

                            if ( debug->debugload )
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] **** Found Processors ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_PROCESSORS;
                            toggle = 0;

                        } /* tag: processors: */

                    /*****************/
                    /**** Outputs ****/
                    /*****************/

                    else if (!strcmp(value, "outputs"))
                        {

                            if ( debug->debugload )
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] **** Found Output ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_OUTPUT;
                            toggle = 0;

                        } /* tag: outputs: */

                    /****************/
                    /**** Rules *****/
                    /****************/

                    else if (!strcmp(value, "rules-files"))
                        {

                            if ( debug->debugload )
                                {
                                    Sagan_Log(S_DEBUG, "[%s, line %d] **** Found Rule-Files ****", __FILE__, __LINE__);
                                }

                            type = YAML_TYPE_RULES;
                            toggle = 0;

                        } /* tag: rule-files */

                } /* else if ( event.type == YAML_SCALAR_EVENT */

        } /* End of while(!done) */

    /* libyaml clean up */

    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fh);

    /* Load required var's info config array */

    for (a = 0; a<counters->var_count; a++)
        {

            if ( !strcmp(var[a].var_name, "$FIFO") && config->sagan_is_file == 0 )
                {
                    strlcpy(config->sagan_fifo, var[a].var_value, sizeof(config->sagan_fifo));
                }

            else if ( !strcmp(var[a].var_name, "$LOCKFILE" ) )
                {
                    strlcpy(config->sagan_lockfile, var[a].var_value, sizeof(config->sagan_lockfile));
                }

            else if ( !strcmp(var[a].var_name, "$SAGANLOGPATH" ) )
                {
                    strlcpy(config->sagan_log_path, var[a].var_value, sizeof(config->sagan_log_path));
                }

        }

    /**********************/
    /* Sanity checks here */
    /**********************/

    /* Check rules for duplicate sid.  We can't have that! */

    for (a = 0; a < counters->rulecount; a++)
        {

            for ( check = a+1; check < counters->rulecount; check++)
                {

                    if (!strcmp (rulestruct[check].s_sid, rulestruct[a].s_sid ))
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] Detected duplicate signature id [sid] number %s.  Please correct this.", __FILE__, __LINE__, rulestruct[check].s_sid, rulestruct[a].s_sid);
                        }
                }
        }


    if ( config->sagan_is_file == false && config->sagan_fifo[0] == '\0' )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] No FIFO option found which is required! Aborting!", __FILE__, __LINE__);
        }

    if ( config->sagan_host[0] == '\0' )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] The 'sagan_host' option was not found and is required.", __FILE__, __LINE__);
        }


#ifdef HAVE_LIBESMTP

    if ( config->sagan_esmtp_flag == true )
        {

            if ( config->sagan_esmtp_from[0] == '\0' )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] SMTP output is enabled but no 'from' address is specified. Abort!");
                }

            else if ( config->sagan_esmtp_server[0] == '\0' )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] SMTP output is enabled but not 'server' address is specified. Abort!");
                }

        }

#endif

#ifdef HAVE_LIBMAXMINDDB

    if ( config->have_geoip2 == true )
        {

            if ( Check_Var("$HOME_COUNTRY") == false )
                {

                    Sagan_Log(S_ERROR, "[%s, line %d] GeoIP2 is enabled, but the $HOME_COUNTRY variable is not set. . Abort!", __FILE__, __LINE__);
                }

            Sagan_Log(S_NORMAL, "Loading GeoIP2 database. [%s]", config->geoip2_country_file);
            Open_GeoIP2_Database();

        }

#endif

#ifdef HAVE_LIBLOGNORM

    if ( config->liblognorm_load == false )
        {

            Sagan_Log(S_ERROR, "[%s, line %d] liblognorm is in use but is not set up.  Abort.", __FILE__, __LINE__);

        }

#endif

#ifdef WITH_BLUEDOT

    if ( config->bluedot_flag == true )
        {

            if ( config->bluedot_cat[0] == '\0' )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Bluedot \"catagories\" option is missing.", __FILE__, __LINE__);
                }

            if ( config->bluedot_url[0] == '\0' )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] Bluedot \"url\" option is missing.", __FILE__, __LINE__);
                }
        }

#endif

    reload_rules = false;

}

#endif
