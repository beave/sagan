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
#include <libgen.h>
#include <string.h>

#include "version.h"
#include "sagan.h"
#include "sagan-defs.h"
#include "config-yaml.h"
#include "rules.h"
#include "sagan-config.h"
#include "classifications.h"
#include "input-json-map.h"
#include "gen-msg.h"
#include "protocol-map.h"
#include "references.h"
#include "parsers/parsers.h"

/* Processors */

#include "processors/blacklist.h"
#include "processors/perfmon.h"
#include "processors/zeek-intel.h"

#ifdef HAVE_LIBYAML
#include <yaml.h>
#endif

#ifdef HAVE_LIBFASTJSON
#include "message-json-map.h"
#endif

#ifdef WITH_BLUEDOT
#include "processors/bluedot.h"

bool bluedot_load;
struct _Sagan_Bluedot_Skip *Bluedot_Skip;

#endif

#ifdef HAVE_LIBLOGNORM

#include <liblognorm.h>
#include "liblognormalize.h"
struct liblognorm_struct *liblognormstruct;
int liblognorm_count;

#endif

#ifdef HAVE_LIBMAXMINDDB
#include "geoip.h"

struct _Sagan_GeoIP_Skip *GeoIP_Skip;

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

bool reload_rules;

#ifdef HAVE_LIBYAML

void Load_YAML_Config( char *yaml_file )
{

    struct stat filecheck;

    yaml_parser_t parser;
    yaml_event_t  event;

    bool done = 0;

    int check = 0;

    unsigned char type = 0;
    int sub_type = 0;
    unsigned char toggle = 0;

    char *tok = NULL;

    char tmp[CONFBUF] = { 0 };

    char last_pass[128] = { 0 };

#ifdef HAVE_LIBMAXMINDDB

    char *geo_tok = NULL;
    char *maxmind_ptr = NULL;

    unsigned char geoip_ipbits[MAXIPBIT] = { 0 };
    unsigned char geoip_maskbits[MAXIPBIT]= { 0 };

    char *geoip_iprange = NULL;
    char *geoip_tmpmask = NULL;
    int  geoip_mask = 0;

#endif


#if WITH_BLUEDOT

    char *bluedot_tok = NULL;
    char *bluedot_ptr = NULL;

    unsigned char bluedot_ipbits[MAXIPBIT] = { 0 };
    unsigned char bluedot_maskbits[MAXIPBIT]= { 0 };

    char *bluedot_iprange = NULL;
    char *bluedot_tmpmask = NULL;
    int  bluedot_mask = 0;

#endif

    char *lf1 = NULL;
    char *lf2 = NULL;
    char *dir = NULL;
    char *filename = NULL;

    int a;

    reload_rules = true;

    /* Set some system defaults */

    if (!strcmp(config->sagan_config, yaml_file))
        {

            strlcpy(config->sagan_sensor_name, SENSOR_NAME, sizeof(config->sagan_sensor_name));
            strlcpy(config->sagan_cluster_name, CLUSTER_NAME, sizeof(config->sagan_cluster_name));
            strlcpy(config->sagan_log_path, SAGANLOGPATH, sizeof(config->sagan_log_path));
            strlcpy(config->sagan_rule_path, RULE_PATH, sizeof(config->sagan_rule_path));
            strlcpy(config->ipc_directory, IPC_DIRECTORY, sizeof(config->ipc_directory));
            strlcpy(config->external_net, EXTERNAL_NET, sizeof(config->external_net));
            strlcpy(config->home_net, HOME_NET, sizeof(config->home_net));


            /* Setup and get lockfile paths, filenames, etc */

            strlcpy(config->sagan_lockfile_full, LOCKFILE, sizeof(config->sagan_lockfile_full));
            lf1 = strdup(config->sagan_lockfile_full);
            lf2 = strdup(config->sagan_lockfile_full);

            dir = dirname(lf1);

            if ( dir == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Directory for lockfile appears '%s' to be incorrect. Abort",  __FILE__, __LINE__, config->sagan_lockfile_full);
                }

            filename = basename(lf2);

            if ( filename == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] The filename for lockfile appears '%s' to be incorrect. Abort",  __FILE__, __LINE__, config->sagan_lockfile_full);
                }

            strlcpy(config->sagan_lockpath, dir, sizeof(config->sagan_lockpath));
            strlcpy(config->sagan_lockfile, filename, sizeof(config->sagan_lockfile));

#ifdef HAVE_LIBFASTJSON

            strlcpy(config->json_input_map_file, DEFAULT_JSON_INPUT_MAP, sizeof(config->json_input_map_file));
            strlcpy(config->json_input_software, "NONE SET", sizeof(config->json_input_software));

            config->parse_json_message = false;
            config->parse_json_program = false;

#endif


#ifdef WITH_SYSLOG

            config->rule_tracking_flag = true;
            config->rule_tracking_console = false;
            config->rule_tracking_syslog = true;
            config->rule_tracking_time = 1440;

#endif


            config->sagan_host[0] = '\0';
            config->sagan_port = 514;
            config->input_type = INPUT_PIPE;
            config->chown_fifo = true;

            /* Defaults for Parse_IP(); */

            config->parse_ip_ipv6 = true;
            config->parse_ip_ipv4_mapped_ipv6 = false;

            config->eve_alerts_base64 = true;

            config->max_after2 = DEFAULT_IPC_AFTER2_IPC;
            config->max_threshold2 = DEFAULT_IPC_THRESHOLD2_IPC;
            config->max_track_clients = DEFAULT_IPC_CLIENT_TRACK_IPC;
            config->max_flexbits = DEFAULT_IPC_FLEXBITS;
            config->max_xbits = DEFAULT_IPC_XBITS;

            config->max_batch = DEFAULT_SYSLOG_BATCH;

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
            config->bluedot_uri[0] = '\0';
            strlcpy(config->bluedot_host, "bluedot.qis.io", sizeof(config->bluedot_host));

            config->bluedot_ip_max_cache = 0;
            config->bluedot_hash_max_cache = 0;
            config->bluedot_url_max_cache = 0;
            config->bluedot_filename_max_cache = 0;
            config->bluedot_ja3_max_cache = 0;

            config->bluedot_ip_queue = 0;
            config->bluedot_hash_queue = 0;
            config->bluedot_url_queue = 0;
            config->bluedot_filename_queue = 0;
            config->bluedot_ja3_queue = 0;

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
            Sagan_Log(ERROR, "[%s, line %d] The configuration file '%s' cannot be found! Abort!", __FILE__, __LINE__, config->sagan_config);
        }

    FILE *fh = fopen(yaml_file, "r");

    if (!yaml_parser_initialize(&parser))
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to initialize the libyaml parser. Abort!", __FILE__, __LINE__);
        }

    if (fh == NULL)
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to open the configuration file '%s' Abort!", __FILE__, __LINE__, yaml_file);
        }

    /* Set input file */

    yaml_parser_set_input_file(&parser, fh);

    while(!done)
        {

            if (!yaml_parser_parse(&parser, &event))
                {

                    /* Useful YAML vars: parser.context_mark.line+1, parser.context_mark.column+1, parser.problem, parser.problem_mark.line+1,
                       parser.problem_mark.column+1 */

                    Sagan_Log(ERROR, "[%s, line %d] libyaml parse error at line %d in '%s'", __FILE__, __LINE__, parser.problem_mark.line+1, config->sagan_config);

                }

            if ( event.type == YAML_DOCUMENT_START_EVENT )
                {

                    if ( debug->debugload )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] YAML_DOCUMENT_START_EVENT", __FILE__, __LINE__);
                        }

                    yaml_version_directive_t *ver = event.data.document_start.version_directive;

                    if ( ver == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Invalid configuration file. Configuration must start with \"%%YAML 1.1\"", __FILE__, __LINE__);
                        }

                    int major = ver->major;
                    int minor = ver->minor;

                    if (! (major == YAML_VERSION_MAJOR && minor == YAML_VERSION_MINOR) )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Configuration has a invalid YAML version.  Must be 1.1 or above", __FILE__, __LINE__);
                        }

                }

            else if ( event.type == YAML_STREAM_END_EVENT )
                {

                    done = true;

                    if ( debug->debugload )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] YAML_STREAM_END_EVENT", __FILE__, __LINE__);
                        }
                }

            else if ( event.type == YAML_MAPPING_START_EVENT )
                {

                    toggle = 1;

                    if ( debug->debugload )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] YAML_MAPPING_START_EVENT", __FILE__, __LINE__);
                        }
                }

            else if ( event.type == YAML_MAPPING_END_EVENT )
                {

                    toggle = 0;
                    sub_type = 0;

                    if ( debug->debugload )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] YAML_MAPPING_END_EVENT", __FILE__, __LINE__);
                        }
                }

            else if ( event.type == YAML_SCALAR_EVENT )
                {

                    char *value = (char *)event.data.scalar.value;

                    if ( debug->debugload )
                        {
                            Sagan_Log(DEBUG, "[%s, line %d] YAML_SCALAR_EVENT - Value: \"%s\"", __FILE__, __LINE__, value);
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
                                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for var. Abort!", __FILE__, __LINE__);
                                        }

                                    memset(&var[counters->var_count], 0, sizeof(struct _SaganVar));

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

                                                    bool check = 0;

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

                                                                    Sagan_Log(DEBUG, "[%s, line %d] Variable from file \"%s\" var \"%s\" loaded: \"%s\"", __FILE__, __LINE__, filename, var[counters->var_count].var_name, tmpbuf);
                                                                }

                                                            if ( check == 0 )
                                                                {

                                                                    check = 1;

                                                                }

                                                            /* Append to the var */

                                                            strlcat(var[counters->var_count].var_value, tmpbuf, sizeof(var[counters->var_count].var_value));


                                                            var[counters->var_count].var_value[strlen(var[counters->var_count].var_value)] = ',';
                                                            var[counters->var_count].var_value[strlen(var[counters->var_count].var_value) + 1] = '\0';

                                                        }

                                                    var[counters->var_count].var_value[strlen(var[counters->var_count].var_value) - 1] = '\0';


                                                    fclose(varfile);

                                                    if ( debug->debugload )
                                                        {

                                                            Sagan_Log(DEBUG, "[%s, line %d] Final load from file for \"%s\" value \"%s\"", __FILE__, __LINE__, var[counters->var_count].var_name, var[counters->var_count].var_value);

                                                        }

                                                    toggle = 1;

                                                }
                                            else
                                                {

                                                    /* If "file:/" is not found, we load like a normal variable */

                                                    strlcpy(var[counters->var_count].var_value, value, sizeof(var[counters->var_count].var_value));

                                                    if ( debug->debugload )
                                                        {

                                                            Sagan_Log(DEBUG, "[%s, line %d] Variable: \"%s == %s\"", __FILE__, __LINE__, var[counters->var_count].var_name, var[counters->var_count].var_value);
                                                        }

                                                    __atomic_add_fetch(&counters->var_count, 1, __ATOMIC_SEQ_CST);

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
                                    Sagan_Log(NORMAL, "Loading included file '%s'.", tmp);
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

                            else if (!strcmp(value, "parse-ip" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_PARSE_IP;
                                }

                            else if (!strcmp(value, "redis-server" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_REDIS;
                                }

                            else if (!strcmp(value, "mmap-ipc" ))
                                {
                                    sub_type = YAML_SAGAN_CORE_MMAP_IPC;
                                }

                            else if (!strcmp(value, "ignore_list" ) || !strcmp(value, "ignore-list" ) )
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

                                    if (!strcmp(last_pass, "cluster-name"))
                                        {
                                            strlcpy(config->sagan_cluster_name, value, sizeof(config->sagan_cluster_name));
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
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan:core 'default-port' is set to zero. Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "chown-fifo"))
                                        {

                                            if (!strcasecmp(value, "disable") || !strcasecmp(value, "false" ) || !strcasecmp(value, "no") )
                                                {
                                                    config->chown_fifo = false;
                                                }
                                        }

#ifndef HAVE_LIBFASTJSON

                                    else if (!strcmp(last_pass, "keys-in-message"))
                                        {
                                            if (!strcasecmp(value, "enabled" && !strcasecmp(value, "true" ) )
                                            {

                                                Sagan_Log(ERROR, "[%s, line %d] sagan:core 'keys-in--message' isn't supported.  No JSON support. Abort!", __FILE__, __LINE__);
                                                }


                                        }

#endif


#ifndef HAVE_LIBFASTJSON

                                    else if (!strcmp(last_pass, "parse-json-message"))
                                        {
                                            if (!strcasecmp(value, "enabled" && !strcasecmp(value, "true" ) )
                                            {

                                                Sagan_Log(ERROR, "[%s, line %d] sagan:core 'parse-json-message' isn't supported.  No JSON support. Abort!", __FILE__, __LINE__);
                                                }


                                        }

#endif

                                    else if (!strcmp(last_pass, "parse-json-message"))
                                        {

                                            if (!strcasecmp(value, "enabled") || !strcasecmp(value, "true" ) || !strcasecmp(value, "yes") )
                                                {
                                                    config->parse_json_message = true;
                                                }
                                        }


#ifndef HAVE_LIBFASTJSON

                                    else if (!strcmp(last_pass, "parse-json-program"))
                                        {
                                            if (!strcasecmp(value, "enabled" && !strcasecmp(value, "true" ) )
                                            {

                                                Sagan_Log(ERROR, "[%s, line %d] sagan:core 'parse-json-program' isn't supported.  No JSON support. Abort!", __FILE__, __LINE__);
                                                }

                                        }

#endif

                                    else if (!strcmp(last_pass, "parse-json-program"))
                                        {

                                            if (!strcasecmp(value, "enabled") || !strcasecmp(value, "true" ) || !strcasecmp(value, "yes") )
                                                {
                                                    config->parse_json_program = true;
                                                }
                                        }

#ifdef HAVE_LIBFASTJSON

                                    else if (!strcmp(last_pass, "json-message-map" ) && ( config->parse_json_message == true || config->parse_json_program == true  ) )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->json_message_map_file, tmp, sizeof(config->json_message_map_file));
                                        }

#endif

#ifndef HAVE_LIBFASTJSON

                                    else if (!strcmp(last_pass, "input-type"))
                                        {
                                            if (!strcasecmp(value, "json" ) )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] Sagan was not compiled with hiredis (Redis) support!", __FILE__, __LINE__);
                                                }
                                        }

#endif

                                    else if (!strcmp(last_pass, "input-type"))
                                        {
                                            if (!strcasecmp(value, "pipe" ) )
                                                {
                                                    config->input_type = INPUT_PIPE;
                                                }

                                            else if (!strcasecmp(value, "json" ) )
                                                {
                                                    config->input_type = INPUT_JSON;
                                                }

                                            else if (strcasecmp(value, "json" ) && strcasecmp(value, "pipe" ) )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan:core 'input-type' is invalid. Abort!", __FILE__, __LINE__);
                                                }
                                        }


#ifdef HAVE_LIBFASTJSON


                                    else if (!strcmp(last_pass, "json-map" ) && config->input_type == INPUT_JSON )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->json_input_map_file, tmp, sizeof(config->json_input_map_file));
                                        }

                                    else if (!strcmp(last_pass, "json-software" ) && config->input_type == INPUT_JSON )
                                        {
                                            strlcpy(config->json_input_software, value, sizeof(config->json_input_software));
                                        }


#endif

                                    else if (!strcmp(last_pass, "default-proto"))
                                        {

                                            if ( !strcasecmp(value, "udp") )
                                                {
                                                    config->sagan_proto = 17;
                                                    config->sagan_proto_string = "UDP";
                                                }

                                            else if ( !strcasecmp(value, "tcp") )
                                                {
                                                    config->sagan_proto = 6;
                                                    config->sagan_proto_string = "TCP";
                                                }

                                            else if ( !strcasecmp(value, "icmp") )
                                                {
                                                    config->sagan_proto = 1;
                                                    config->sagan_proto_string = "ICMP";
                                                }

                                            else if ( strcasecmp(value, "tcp") && strcasecmp(value, "udp") )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] 'default_proto' can only be TCP, UDP or ICMP.", __FILE__, __LINE__);

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

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled") )
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
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan:core 'fifo-size' is set to zero. Abort!", __FILE__, __LINE__);
                                                }

                                            if ( config->sagan_fifo_size != 65536 &&
                                                    config->sagan_fifo_size != 131072 &&
                                                    config->sagan_fifo_size != 262144 &&
                                                    config->sagan_fifo_size != 524288 &&
                                                    config->sagan_fifo_size != 1048576 )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] sagan:core 'fifo-size' is invalid.  Valid value are 65536, 131072, 262144, 524288, and 1048576. Abort!", __FILE__, __LINE__);
                                                }

                                        }
#endif
                                    else if (!strcmp(last_pass, "max-threads"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_processor_threads = atoi(tmp);

                                            if ( config->max_processor_threads  == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan:core 'max_threads' is zero/invalid. Abort!", __FILE__, __LINE__);
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

                                    else if (!strcmp(last_pass, "batch-size"))
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));

                                            config->max_batch = atoi(tmp);

                                            if ( config->max_batch  == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan:core 'max_batch' is zero/invalid. Abort!", __FILE__, __LINE__);
                                                }

                                            if ( config->max_batch > MAX_SYSLOG_BATCH )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan:core 'max_batch' is greater than %d (the max default). Abort!", __FILE__, __LINE__, MAX_SYSLOG_BATCH);
                                                }


                                        }

                                    else if (!strcmp(last_pass, "xbit-storage"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));

                                            if (strcmp(tmp, "mmap") && strcmp(tmp, "redis"))
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] sagan-core|xbit-storage is set to an invalid type '%s'. It must be 'mmap' or 'redis'. Abort!", __FILE__, __LINE__, tmp);

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
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'xbits' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "flexbit"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_flexbits = atoi(tmp);

                                            if ( config->max_flexbits == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'flexbits' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "threshold"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_threshold2 = atoi(tmp);

                                            if ( config->max_threshold2 == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'threshold' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }

                                    else if (!strcmp(last_pass, "after"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_after2 = atoi(tmp);

                                            if ( config->max_after2 == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'after' is set to zero.  Abort!", __FILE__, __LINE__);
                                                }
                                        }


                                    else if (!strcmp(last_pass, "track-clients"))
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->max_track_clients = atoi(tmp);

                                            if ( config->max_track_clients == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] sagan-core|mmap-ipc - 'track-clients' is set to zero.  Abort!", __FILE__, __LINE__);
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

                                    if (!strcmp(last_pass, "ignore_file") || !strcmp(last_pass, "ignore-file") )
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

                                                    Sagan_Log(ERROR, "[%s, line %d] Sagan was not compiled with hiredis (Redis) support!", __FILE__, __LINE__);

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
                                                            Sagan_Log(ERROR, "[%s, line %d] sagan-core|redis-server - Redis 'port' is set to zero.  Abort!", __FILE__, __LINE__);
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
                                                            Sagan_Log(ERROR, "[%s, line %d] sagan-core|redis-server - Redis 'writer_threads' is set to zero.  Abort!", __FILE__, __LINE__);
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

                                                    Sagan_Log(ERROR, "[%s, line %d] Sagan was not compiled with Maxmind's \"GeoIP\" support!", __FILE__, __LINE__);

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

                                    if (!strcmp(last_pass, "country_database") && config->have_geoip2 == true)
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->geoip2_country_file, tmp, sizeof(config->geoip2_country_file));

                                        }

                                    if (!strcmp(last_pass, "skip_networks") && config->have_geoip2 == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            Remove_Spaces(tmp);

                                            maxmind_ptr = strtok_r(tmp, ",", &tok);

                                            while( maxmind_ptr != NULL )
                                                {

                                                    geoip_iprange = strtok_r(maxmind_ptr, "/", &geo_tok);

                                                    if ( geoip_iprange == NULL )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] IP range for GeoIP 'skip_networks' is invalid. Abort.", __FILE__, __LINE__);
                                                        }

                                                    if (!IP2Bit(geoip_iprange, geoip_ipbits))
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] Invalid address for GeoIP 'skip_address'. Abort", __FILE__, __LINE__ );
                                                        }

                                                    geoip_tmpmask = strtok_r(NULL, "/", &geo_tok);

                                                    if ( geoip_tmpmask == NULL )
                                                        {
                                                            geoip_mask = 32;
                                                        }

                                                    GeoIP_Skip = (_Sagan_GeoIP_Skip *) realloc(GeoIP_Skip, (counters->geoip_skip_count+1) * sizeof(_Sagan_GeoIP_Skip));

                                                    if ( GeoIP_Skip == NULL )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for GeoIP_Skip Abort!", __FILE__, __LINE__);
                                                        }

                                                    memset(&GeoIP_Skip[counters->geoip_skip_count], 0, sizeof(_Sagan_GeoIP_Skip));

                                                    geoip_mask = atoi(geoip_tmpmask);

                                                    if ( geoip_mask == 0 || !Mask2Bit(geoip_mask, geoip_maskbits))
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] Invalid mask for GeoIP 'skip_networks'. Abort", __FILE__, __LINE__);
                                                        }


                                                    memcpy(GeoIP_Skip[counters->geoip_skip_count].range.ipbits, geoip_ipbits, sizeof(geoip_ipbits));
                                                    memcpy(GeoIP_Skip[counters->geoip_skip_count].range.maskbits, geoip_maskbits, sizeof(geoip_maskbits));

                                                    __atomic_add_fetch(&counters->geoip_skip_count, 1, __ATOMIC_SEQ_CST);

                                                    maxmind_ptr = strtok_r(NULL, ",", &tok);

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

                                                    Sagan_Log(ERROR, "[%s, line %d] Sagan was not compiled with liblognorm support!", __FILE__, __LINE__);

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

                                                    Sagan_Log(ERROR, "[%s, line %d] Sagan was not compiled with libpcap support!", __FILE__, __LINE__);

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

                                            else if (!strcmp(last_pass, "bpf") || !strcmp(last_pass, "bpf-filter") )
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


                            if ( sub_type == YAML_SAGAN_CORE_PARSE_IP )
                                {

                                    if (!strcmp(last_pass, "ipv6" ))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled" ))
                                                {
                                                    config->parse_ip_ipv6 = true;
                                                }

                                        }

                                    else if (!strcmp(last_pass, "ipv4-mapped-ipv6" ))
                                        {

                                            if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled" ))
                                                {
                                                    config->parse_ip_ipv4_mapped_ipv6 = true;
                                                }

                                        }

                                }

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

                            else if (!strcmp(value, "client-stats"))
                                {
                                    sub_type = YAML_PROCESSORS_CLIENT_STATS;
                                }

                            else if (!strcmp(value, "blacklist"))
                                {
                                    sub_type = YAML_PROCESSORS_BLACKLIST;
                                }

                            else if (!strcmp(value, "bluedot"))
                                {
                                    sub_type = YAML_PROCESSORS_BLUEDOT;
                                }

                            else if (!strcmp(value, "bro-intel") || !strcmp(value, "zeek-intel") )
                                {
                                    sub_type = YAML_PROCESSORS_BROINTEL;
                                }

                            else if (!strcmp(value, "dynamic_load") || !strcmp(value, "dynamic-load"))
                                {
                                    sub_type = YAML_PROCESSORS_DYNAMIC_LOAD;
                                }

                            else if (!strcmp(value, "stats-json"))
                                {
                                    sub_type = YAML_PROCESSORS_STATS_JSON;
                                }


#ifdef WITH_SYSLOG
                            else if (!strcmp(value, "rule-tracking"))
                                {
                                    sub_type = YAML_SAGAN_CORE_RULESET_TRACKING;
                                }
#endif

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

                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'track_clients' - 'timeout' has to be a non-zero value. Abort!!", __FILE__, __LINE__);

                                                }

                                        }
                                }

                            else if ( sub_type == YAML_PROCESSORS_CLIENT_STATS )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->client_stats_flag = true;
                                                }

                                        }

                                    else if (!strcmp(last_pass, "filename") && config->client_stats_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->client_stats_file_name, tmp, sizeof(config->client_stats_file_name));
                                        }

                                    else if (!strcmp(last_pass, "time" ) && config->client_stats_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->client_stats_time = atoi(tmp);

                                            if ( config->client_stats_time == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'client_stats' - 'time' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                }

                                        }

                                    else if (!strcmp(last_pass, "data-interval" ) && config->client_stats_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->client_stats_interval = atoi(tmp);

                                            if ( config->client_stats_interval == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'client_stats' - 'data-interval' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                }

                                        }

// client_stats_max
                                    else if (!strcmp(last_pass, "max-clients" ) && config->client_stats_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->client_stats_max = atoi(tmp);

                                            if ( config->client_stats_max == 0 )
                                                {
                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'client_stats' - 'max-clients' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                }

                                        }



                                }

                            else if ( sub_type == YAML_PROCESSORS_STATS_JSON )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled") )
                                                {
                                                    config->stats_json_flag = true;
                                                }
                                        }

                                    else if (!strcmp(last_pass, "subtract_old_values") && config->stats_json_flag == true )
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled") )
                                                {
                                                    config->stats_json_sub_old_values = true;
                                                }

                                        }

                                    else if (!strcmp(last_pass, "time") && config->stats_json_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->stats_json_time = atoi(tmp);

                                            if ( config->stats_json_time == 0 )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'stats-json' - 'time' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                }

                                        }

                                    else if (!strcmp(last_pass, "filename") && config->stats_json_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->stats_json_filename, tmp, sizeof(config->stats_json_filename));

                                        }

                                } /* if sub_type == YAML_PROCESSORS_STATS_JSON */


                            else if ( sub_type == YAML_PROCESSORS_PERFMON )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled") )
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

                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'perfmonitor' - 'time' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
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

                                                    Sagan_Log(ERROR, "[%s, line %d] The Sagan's configuration file has Bluedot enabled, but Sagan wasn't compiled with Bluedot support! Abort!", __FILE__, __LINE__);

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


                                    else if (!strcmp(last_pass, "host") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->bluedot_host, tmp, sizeof(config->bluedot_host));
                                        }

                                    else if (!strcmp(last_pass, "max-ip-cache") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_ip_max_cache = strtoull(tmp, NULL, 10);

                                            if ( config->bluedot_ip_max_cache == 0 )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'max-ip-cache' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                }

                                        }

                                    else if (!strcmp(last_pass, "max-hash-cache") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_hash_max_cache = strtoull(tmp, NULL, 10);

                                            /*                                            if ( config->bluedot_hash_max_cache == 0 )
                                                                                            {
                                                                                                Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'max-hash-cache' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                                            }
                                            						*/

                                        }

                                    else if (!strcmp(last_pass, "max-url-cache") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_url_max_cache = strtoull(tmp, NULL, 10);

                                            /*
                                                                if ( config->bluedot_url_max_cache == 0 )
                                                                    {
                                                                        Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'max-url-cache' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                    }
                                            */

                                        }

                                    else if (!strcmp(last_pass, "max-filename-cache") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_filename_max_cache = strtoull(tmp, NULL, 10);

                                            /*
                                                                if ( config->bluedot_filename_max_cache == 0 )
                                                                    {
                                                                        Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'max-file-cache' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                    }
                                            */
                                        }

                                    else if (!strcmp(last_pass, "max-ja3-cache") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_ja3_max_cache = strtoull(tmp, NULL, 10);
                                            /*
                                                                                        if ( config->bluedot_ja3_max_cache == 0 )
                                                                                            {
                                                                                                Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'max-ja3-cache' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                                            }
                                            							*/
                                        }

                                    else if (!strcmp(last_pass, "ip-queue") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_ip_queue = strtoull(tmp, NULL, 10);
                                            /*
                                                                                        if ( config->bluedot_ip_queue == 0 )
                                                                                            {
                                                                                                Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'ip-queue' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                                            } */
                                        }


                                    else if (!strcmp(last_pass, "hash-queue") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_hash_queue = strtoull(tmp, NULL, 10);

                                            /*                                            if ( config->bluedot_hash_queue == 0 )
                                                                                            {
                                                                                                Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'hash-queue' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                                            } */
                                        }

                                    else if (!strcmp(last_pass, "url-queue") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_url_queue = strtoull(tmp, NULL, 10);

                                            /*
                                                                if ( config->bluedot_url_queue == 0 )
                                                                    {
                                                                        Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'url-queue' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                    }
                                            */
                                        }

                                    else if (!strcmp(last_pass, "filename-queue") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_filename_queue = strtoull(tmp, NULL, 10);

                                            /*
                                                                if ( config->bluedot_filename_queue == 0 )
                                                                    {
                                                                        Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'filename-queue' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                    }
                                            */
                                        }

                                    else if (!strcmp(last_pass, "ja3-queue") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_ja3_queue = strtoull(tmp, NULL, 10);

                                            /*
                                                                if ( config->bluedot_ja3_queue == 0 )
                                                                    {
                                                                        Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'ja3-queue' has to be a non-zero value. Abort!!", __FILE__, __LINE__);
                                                                    }
                                            */
                                        }

                                    else if (!strcmp(last_pass, "cache-timeout") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_timeout = atoi(tmp) * 60;

                                            if ( config->bluedot_timeout == 0 )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'bluedot' - 'cache-timeout' has to be a non-zero value. Abort!!", __FILE__, __LINE__);

                                                }
                                        }

                                    else if (!strcmp(last_pass, "categories") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->bluedot_cat, tmp, sizeof(config->bluedot_cat));
                                        }

                                    else if (!strcmp(last_pass, "uri") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            strlcpy(config->bluedot_uri, tmp, sizeof(config->bluedot_uri));
                                        }


                                    else if (!strcmp(last_pass, "ttl") && config->bluedot_flag == true )
                                        {
                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            config->bluedot_dns_ttl = atoi(tmp);
                                        }

                                    if (!strcmp(last_pass, "skip_networks") && config->bluedot_flag == true )
                                        {

                                            Var_To_Value(value, tmp, sizeof(tmp));
                                            Remove_Spaces(tmp);

                                            bluedot_ptr = strtok_r(tmp, ",", &tok);

                                            while ( bluedot_ptr != NULL )
                                                {

                                                    bluedot_iprange = strtok_r(bluedot_ptr, "/", &bluedot_tok);

                                                    if ( bluedot_iprange == NULL )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] processor: 'bluedot' - 'skip_networks' is invalid. Abort.", __FILE__, __LINE__);
                                                        }

                                                    if (!IP2Bit(bluedot_iprange, bluedot_ipbits))
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] processor: 'bluedot' - 'skip_address' is invalid. Abort", __FILE__, __LINE__);
                                                        }

                                                    bluedot_tmpmask = strtok_r(NULL, "/", &bluedot_tok);

                                                    if ( bluedot_tmpmask == NULL )
                                                        {
                                                            bluedot_mask = 32;
                                                        }

                                                    Bluedot_Skip = (_Sagan_Bluedot_Skip *) realloc(Bluedot_Skip, (counters->bluedot_skip_count+1) * sizeof(_Sagan_Bluedot_Skip));

                                                    if ( Bluedot_Skip == NULL )
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] processor: 'bluedot' - Failed to reallocate memory for Bluedot_Skip Abort!", __FILE__, __LINE__);
                                                        }

                                                    memset(&Bluedot_Skip[counters->bluedot_skip_count], 0, sizeof(_Sagan_Bluedot_Skip));

                                                    bluedot_mask = atoi(bluedot_tmpmask);

                                                    if ( bluedot_mask == 0 || !Mask2Bit(bluedot_mask, bluedot_maskbits))
                                                        {
                                                            Sagan_Log(ERROR, "[%s, line %d] processor: 'bluedot' - Invalid mask for 'skip_networks'. Abort", __FILE__, __LINE__);
                                                        }

                                                    memcpy(Bluedot_Skip[counters->bluedot_skip_count].range.ipbits, bluedot_ipbits, sizeof(bluedot_ipbits));
                                                    memcpy(Bluedot_Skip[counters->bluedot_skip_count].range.maskbits, bluedot_maskbits, sizeof(bluedot_maskbits));

                                                    __atomic_add_fetch(&counters->bluedot_skip_count, 1, __ATOMIC_SEQ_CST);

                                                    bluedot_ptr = strtok_r(NULL, ",", &tok);

                                                }

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

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled") )
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

                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : 'dynamic_load' - 'sample_rate' has to be a non-zero value. Abort!!", __FILE__, __LINE__);

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

#ifndef WITH_SYSLOG

                            else if ( sub_type == YAML_SAGAN_CORE_RULESET_TRACKING )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] 'syslog' output is enabled, but Sagan is not compiled with syslog support. Abort!", __FILE__, __LINE__);
                                                }

                                        }
                                }

#endif


#ifdef WITH_SYSLOG

                            else if ( sub_type == YAML_SAGAN_CORE_RULESET_TRACKING )
                                {


                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {
                                                    config->rule_tracking_flag = true;
                                                }
                                        }

                                    if (!strcmp(last_pass, "console"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled") )
                                                {
                                                    config->rule_tracking_console = true;
                                                }
                                        }

                                    if (!strcmp(last_pass, "syslog"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "enabled") )
                                                {
                                                    config->rule_tracking_syslog = true;
                                                }
                                        }

                                    if (!strcmp(last_pass, "time"))
                                        {

                                            config->rule_tracking_time = atoi(value);

                                            if ( config->rule_tracking_time == 0 )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] 'processor' : rule_tracking''' - 'time' has to be a non-zero value. Abort!!", __FILE__, __LINE__);

                                                }

                                            config->rule_tracking_time = config->rule_tracking_time * 60;
                                        }

                                } /* if sub_type == YAML_SAGAN_CORE_RULESET_TRACKING */

                        } /* else if ( type == YAML_TYPE_PROCESSORS */
#endif


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

                                                    config->eve_type = 0;  /* Only one type at this time! */

                                                }
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

                                    else if ( !strcmp(last_pass, "alerts-base64")  && config->eve_flag == true )
                                        {
                                            if ( !strcasecmp(value, "no") || !strcasecmp(value, "false") )
                                                {
                                                    config->eve_alerts_base64 = false;
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

#ifndef HAVE_LIBESMTP

                            else if ( sub_type == YAML_OUTPUT_SMTP )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] 'smtp' output is enabled, but Sagan is not compiled with libesmtp support. Abort!", __FILE__, __LINE__);
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

#ifndef WITH_SYSLOG

                            else if ( sub_type == YAML_OUTPUT_SYSLOG )
                                {

                                    if (!strcmp(last_pass, "enabled"))
                                        {

                                            if ( !strcasecmp(value, "yes") || !strcasecmp(value, "true") )
                                                {

                                                    Sagan_Log(ERROR, "[%s, line %d] 'syslog' output is enabled, but Sagan is not compiled with syslog support. Abort!", __FILE__, __LINE__);
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
                            (void)Load_Rules( (char*)tmp );

                            rules_loaded = (_Rules_Loaded *) realloc(rules_loaded, (counters->rules_loaded_count+1) * sizeof(_Rules_Loaded));

                            if ( rules_loaded == NULL )
                                {
                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for rules_loaded. Abort!", __FILE__, __LINE__);
                                }

                            Var_To_Value(value, tmp, sizeof(tmp));
                            strlcpy(rules_loaded[counters->rules_loaded_count].ruleset, tmp, sizeof(rules_loaded[counters->rules_loaded_count].ruleset));

                            __atomic_add_fetch(&counters->rules_loaded_count, 1, __ATOMIC_SEQ_CST);

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
                                    Sagan_Log(DEBUG, "[%s, line %d] **** Found variables ****", __FILE__, __LINE__);
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
                                    Sagan_Log(DEBUG, "[%s, line %d] **** Found include ****", __FILE__, __LINE__);
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
                                    Sagan_Log(DEBUG, "[%s, line %d] **** Found Sagan Core ****", __FILE__, __LINE__);
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
                                    Sagan_Log(DEBUG, "[%s, line %d] **** Found Processors ****", __FILE__, __LINE__);
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
                                    Sagan_Log(DEBUG, "[%s, line %d] **** Found Output ****", __FILE__, __LINE__);
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
                                    Sagan_Log(DEBUG, "[%s, line %d] **** Found Rule-Files ****", __FILE__, __LINE__);
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
                    strlcpy(config->sagan_lockfile_full, var[a].var_value, sizeof(config->sagan_lockfile_full));

                    lf1 = strdup(config->sagan_lockfile_full);
                    lf2 = strdup(config->sagan_lockfile_full);

                    dir = dirname(lf1);

                    if ( dir == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Directory for lockfile appears '%s' to be incorrect. Abort",  __FILE__, __LINE__, config->sagan_lockfile_full);
                        }

                    filename = basename(lf2);

                    if ( filename == NULL )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] The filename for lockfile appears '%s' to be incorrect. Abort",  __FILE__, __LINE__, config->sagan_lockfile_full);
                        }

                    strlcpy(config->sagan_lockpath, dir, sizeof(config->sagan_lockpath));
                    strlcpy(config->sagan_lockfile, filename, sizeof(config->sagan_lockfile));

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

                    if ( rulestruct[check].s_sid == rulestruct[a].s_sid )
                        {
                            Sagan_Log(ERROR, "[%s, line %d] Detected duplicate signature id number %" PRIu64 ".", __FILE__, __LINE__, rulestruct[check].s_sid, rulestruct[a].s_sid);
                        }
                }
        }


    if ( config->sagan_is_file == false && config->sagan_fifo[0] == '\0' )
        {
            Sagan_Log(ERROR, "[%s, line %d] No FIFO option found which is required! Aborting!", __FILE__, __LINE__);
        }

    if ( config->sagan_host[0] == '\0' )
        {
            Sagan_Log(ERROR, "[%s, line %d] The 'sagan_host' option was not found and is required.", __FILE__, __LINE__);
        }

#ifdef HAVE_LIBHIREDIS

    if ( config->redis_flag == false && config->xbit_storage == XBIT_STORAGE_REDIS )
        {
            Sagan_Log(ERROR, "[%s, line %d] xbit storage engine is Redis, but the redis configuration is disabled", __FILE__, __LINE__);
        }


#endif

#ifdef HAVE_LIBESMTP

    if ( config->sagan_esmtp_flag == true )
        {

            if ( config->sagan_esmtp_from[0] == '\0' )
                {
                    Sagan_Log(ERROR, "[%s, line %d] SMTP output is enabled but no 'from' address is specified. Abort!");
                }

            else if ( config->sagan_esmtp_server[0] == '\0' )
                {
                    Sagan_Log(ERROR, "[%s, line %d] SMTP output is enabled but not 'server' address is specified. Abort!");
                }

        }

#endif

#ifdef HAVE_LIBMAXMINDDB

    if ( config->have_geoip2 == true )
        {

            if ( Check_Var("$HOME_COUNTRY") == false )
                {

                    Sagan_Log(ERROR, "[%s, line %d] GeoIP is enabled, but the $HOME_COUNTRY variable is not set. . Abort!", __FILE__, __LINE__);
                }

            Sagan_Log(NORMAL, "Loading GeoIP database. [%s]", config->geoip2_country_file);
            Open_GeoIP2_Database();

        }

#endif

#ifdef HAVE_LIBLOGNORM

    if ( config->liblognorm_load == false )
        {

            Sagan_Log(ERROR, "[%s, line %d] liblognorm is in use but is not set up.  Abort.", __FILE__, __LINE__);

        }

#endif

#ifdef WITH_BLUEDOT

    if ( config->bluedot_flag == true )
        {

            if ( config->bluedot_cat[0] == '\0' )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Bluedot \"catagories\" option is missing.", __FILE__, __LINE__);
                }

            if ( config->bluedot_uri[0] == '\0' )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Bluedot \"uri\" option is missing.", __FILE__, __LINE__);
                }
        }

#endif

#ifdef HAVE_LIBFASTJSON

    if ( config->input_type == INPUT_JSON )
        {

            Load_Input_JSON_Map( config->json_input_map_file );

        }

    if ( config->parse_json_message == true || config->parse_json_program == true )
        {

            Load_Message_JSON_Map( config->json_message_map_file );

        }


#endif

    reload_rules = false;

}

#endif
