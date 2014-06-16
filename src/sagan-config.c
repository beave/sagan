/*
** Copyright (C) 2009-2014 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2014 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-config.c
 *
 * Loads the sagan.conf file into memory
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#ifdef HAVE_LIBLOGNORM
#include <liblognorm.h>
#include <ptree.h>
#include <lognorm.h>
#endif

#include "version.h"
#include "sagan.h"

/* Processors */

#include "processors/sagan-blacklist.h"
#include "processors/sagan-search.h"

#ifdef WITH_WEBSENSE
#include "processors/sagan-websense.h"
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/sagan-unified2.h"
#endif

#ifdef HAVE_LIBLOGNORM
struct liblognorm_struct *liblognormstruct;
int liblognorm_count;
#endif

struct _Rule_Struct *rulestruct;
struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;
struct _SaganVar *var;

//pthread_mutex_t SaganLoadRules=PTHREAD_MUTEX_INITIALIZER;

void Load_Config( void )
{

    FILE *sagancfg;

    char *filename;
    char ruleset[MAXPATH];
    char normfile[MAXPATH];

    char tmpbuf[CONFBUF];
    char tmpbuf2[CONFBUF];
    char tmpstring[CONFBUF];

    char *sagan_option=NULL;
    char *sagan_var1=NULL;
    char *sagan_var2=NULL;
    char *sagan_var3=NULL;
    char *ptmp=NULL;

    char *tok=NULL;
    char *tok2=NULL;

    int i,check;

    /* Set some system defaults */

    strlcpy(config->sagan_alert_filepath, ALERTLOG, sizeof(config->sagan_alert_filepath));
    strlcpy(config->sagan_lockfile, LOCKFILE, sizeof(config->sagan_lockfile));
    strlcpy(config->sagan_log_path, SAGANLOGPATH, sizeof(config->sagan_log_path));
    if ( config->sagan_fifo_flag != 1 ) strlcpy(config->sagan_fifo, FIFO, sizeof(config->sagan_fifo));
    strlcpy(config->sagan_rule_path, RULE_PATH, sizeof(config->sagan_rule_path));

#ifdef HAVE_LIBESMTP
    strlcpy(config->sagan_email_subject, DEFAULT_SMTP_SUBJECT, sizeof(config->sagan_email_subject));
#endif

    config->sagan_proto = 17;		/* Default to UDP */
    config->max_processor_threads = MAX_PROCESSOR_THREADS;

    /* PLOG defaults */

#ifdef HAVE_LIBPCAP
    strlcpy(config->plog_interface, PLOG_INTERFACE, sizeof(config->plog_interface));
    strlcpy(config->plog_filter, PLOG_FILTER, sizeof(config->plog_filter));
    strlcpy(config->plog_logdev, PLOG_LOGDEV, sizeof(config->plog_logdev));
#endif

//config->home_any = 0;
//config->external_any = 0;

    /* Start loading configuration */

    rulestruct = (_Rule_Struct *) realloc(rulestruct, (counters->rulecount+1) * sizeof(_Rule_Struct));

    /* Gather information for the master configuration file */


    if ((sagancfg = fopen(config->sagan_config, "r")) == NULL)
        {
            fprintf(stderr, "[%s, line %d] Cannot open configuration file (%s)\n", __FILE__,  __LINE__, config->sagan_config);
            exit(1);
        }

    while(fgets(tmpbuf, sizeof(tmpbuf), sagancfg) != NULL)
        {
            if (tmpbuf[0] == '#') continue;
            if (tmpbuf[0] == ';') continue;
            if (tmpbuf[0] == 10 ) continue;
            if (tmpbuf[0] == 32 ) continue;

            strlcpy(tmpbuf2, tmpbuf, sizeof(tmpbuf2));	/* Retain a copy of the entire line */

            sagan_option = strtok_r(tmpbuf, " ", &tok);

            if (!strcmp(Remove_Return(sagan_option), "max_processor_threads"))
                {
                    sagan_var1 = strtok_r(NULL, " ", &tok);
                    config->max_processor_threads = strtoull(sagan_var1, NULL, 10);
                }

            if (!strcmp(Remove_Return(sagan_option), "disable_dns_warnings"))
                {
                    Sagan_Log(S_NORMAL, "Supressing DNS warnings");
                    config->disable_dns_warnings = 1;
                }

            if (!strcmp(Remove_Return(sagan_option), "syslog_src_lookup"))
                {
                    Sagan_Log(S_NORMAL, "DNS lookup of source address supplied by syslog daemon");
                    config->syslog_src_lookup = 1;
                }


            if (!strcmp(sagan_option, "sagan_host"))
                strlcpy(config->sagan_host, Remove_Return(strtok_r(NULL, " " , &tok)), sizeof(config->sagan_host));

            if (!strcmp(sagan_option, "sagan_port"))
                {
                    sagan_var1 = strtok_r(NULL, " ", &tok);
                    config->sagan_port = atoi(sagan_var1);
                }

#ifndef HAVE_LIBESMTP
            if (!strcmp(sagan_option, "send-to") || !strcmp(sagan_option, "min_email_priority"))
                Sagan_Log(S_ERROR, "\"libesmtp\" support not found. Re-compile with ESMTP support or disable in the sagan.conf.");
#endif

#ifdef HAVE_LIBESMTP

            if (!strcmp(sagan_option, "send-to"))
                {
                    sagan_var1 = strtok_r(NULL, " ", &tok);
                    strlcpy(config->sagan_esmtp_to, Remove_Return(sagan_var1), sizeof(config->sagan_esmtp_to));
                    config->sagan_esmtp_flag=1;
                    config->sagan_sendto_flag=1;
                }

            if (!strcmp(sagan_option, "min_email_priority"))
                {
                    sagan_var1 = strtok_r(NULL, " ", &tok);
                    config->min_email_priority = atoi(sagan_var1);
                }

            if (!strcmp(sagan_option, "email_subject"))
                {
                    sagan_var1 = strtok_r(NULL, " ", &tok);
                    strlcpy(config->sagan_email_subject, Remove_Return(Between_Quotes(tmpbuf2)), sizeof(config->sagan_email_subject));
                }

#endif

#ifndef HAVE_LIBPCAP
            if (!strcmp(sagan_option, "plog_interface") || !strcmp(sagan_option, "plog_logdev") || !strcmp(sagan_option, "plog_port"))
                Sagan_Log(S_ERROR, "\"libpcap\" support not found. Re-compile with PCAP support or disable in the sagan.conf.");
#endif

#ifdef HAVE_LIBPCAP

            if (!strcmp(sagan_option, "plog_interface"))
                {
                    strlcpy(config->plog_interface, Remove_Return(strtok_r(NULL, " ", &tok)), sizeof(config->plog_interface));
                    config->plog_flag=1;
                }

            if (!strcmp(sagan_option, "plog_logdev"))
                {
                    strlcpy(config->plog_logdev, Remove_Return(strtok_r(NULL, " ", &tok)), sizeof(config->plog_logdev));
                    config->plog_flag=1;
                }

            if (!strcmp(sagan_option, "plog_filter"))
                {
                    strlcpy(config->plog_filter, Remove_Return(Between_Quotes(tmpbuf2)), sizeof(config->plog_filter));
                    config->plog_flag = 1;
                }

            if (!strcmp(sagan_option, "plog_promiscuous"))
                {
                    config->plog_promiscuous = 1;
                    config->plog_flag = 1;
                }

#endif

#ifndef HAVE_LIBLOGNORM
            if (!strcmp(sagan_option, "normalize:"))
                {
                    Sagan_Log(S_WARN, "WARNING: Sagan was not compiled with \"liblognorm\" support!");
                    Sagan_Log(S_WARN, "WARNING: Sagan will continue,  but _without_ liblognorm!");
                }
#endif

#ifdef HAVE_LIBLOGNORM
            /*
             We load the location for liblognorm's 'rule base/samples'.  We don't want to
             load them quiet yet.  We only want to load samples we need,  so we do the
             actual ln_loadSamples() after the configuration file and all rules have
             been analyzed */

            if (!strcmp(sagan_option, "normalize:"))
                {
                    liblognormstruct = (liblognorm_struct *) realloc(liblognormstruct, (liblognorm_count+1) * sizeof(liblognorm_struct));

                    sagan_var1 = strtok_r(NULL, ",", &tok);
                    Remove_Spaces(sagan_var1);
                    strlcpy(liblognormstruct[liblognorm_count].type, sagan_var1, sizeof(liblognormstruct[liblognorm_count].type));

                    strlcpy(tmpstring, strtok_r(NULL, ",", &tok), sizeof(tmpstring));
                    Remove_Spaces(tmpstring);
                    Remove_Return(tmpstring);

                    strlcpy(normfile, Sagan_Var_To_Value(tmpstring), sizeof(normfile));
                    Remove_Spaces(normfile);

                    strlcpy(liblognormstruct[liblognorm_count].filepath, normfile, sizeof(liblognormstruct[liblognorm_count].filepath));
                    liblognorm_count++;
                }

#endif

#ifndef HAVE_LIBGEOIP
            if (!strcmp(sagan_option, "country_database"))
                {
                    Sagan_Log(S_WARN, "WARNING: Sagan was not compiled with Maxmind \"GeoIP\" support!");
                    Sagan_Log(S_WARN, "WARNING: Sagan will continue,  but _without_ GeoIP enabled!");
                }
#endif

#ifdef HAVE_LIBGEOIP
            if (!strcmp(sagan_option, "country_database:"))
                {
                    sagan_var1 = Remove_Return(strtok_r(NULL, " ", &tok));
                    strlcpy(config->geoip_country_file, sagan_var1, sizeof(config->geoip_country_file));
                    Sagan_Log(S_NORMAL, "Loading GeoIP database. [%s]", config->geoip_country_file);
                    Sagan_Open_GeoIP_Database();
                    config->have_geoip = 1;
                }
#endif

            if (!strcmp(sagan_option, "ignore_list:"))
                {
                    sagan_var1 = Remove_Return(strtok_r(NULL, " ", &tok));

                    if ( sagan_var1 == NULL )
                        Sagan_Log(S_ERROR, "[%s, line %d] No \"ignore file\" specified in the sagan.conf file!", __FILE__, __LINE__);

                    config->sagan_droplist_flag = 1;
                    strlcpy(config->sagan_droplistfile, sagan_var1, sizeof(config->sagan_droplistfile));
                }

            /****************************************************************************
             * Processors
             ****************************************************************************/

            if (!strcmp(sagan_option, "processor"))
                {

                    sagan_var1 = strtok_r(NULL," ", &tok);

                    /******* Client tracker *******/

                    if (!strcmp(sagan_var1, "sagan-track-clients:"))
                        {

                            /* Set defaults */

                            config->pp_sagan_track_clients = TRACK_TIME;
                            strlcpy(config->sagan_track_client_host_cache, TRACK_CACHE, sizeof(config->sagan_track_client_host_cache));

                            config->sagan_track_clients_flag = 1;

                            ptmp = sagan_var1;

                            while (ptmp != NULL)
                                {

                                    if (!strcmp(ptmp, "client_timeout"))
                                        {
                                            ptmp = strtok_r(NULL," ", &tok);
                                            config->pp_sagan_track_clients = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "host_cache"))
                                        {
                                            ptmp = strtok_r(NULL," ", &tok);
                                            strlcpy(config->sagan_track_client_host_cache, Remove_Return(ptmp), sizeof(config->sagan_track_client_host_cache));
                                        }

                                    ptmp = strtok_r(NULL, "=", &tok);
                                }
                        }


                    /******* Backlist *******/

                    if (!strcmp(sagan_var1, "blacklist:"))
                        {

                            config->blacklist_flag=1;

                            /* Set defaults */

                            config->blacklist_priority = BLACKLIST_PROCESSOR_PRI; /* Set default */
                            config->blacklist_parse_depth = 2;
                            config->blacklist_parse_src = 1;
                            config->blacklist_parse_dst = 2;

                            ptmp = sagan_var1;

                            while (ptmp != NULL)
                                {

                                    if (!strcmp(ptmp, "parse_depth"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->blacklist_parse_depth = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "blacklist"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->blacklist_file, Remove_Return(ptmp), sizeof(config->blacklist_file));
                                        }

                                    if (!strcmp(ptmp, "parse_src"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->blacklist_parse_src = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "parse_dst"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->blacklist_parse_dst = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "parse_proto"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->blacklist_parse_proto = 1;
                                        }

                                    if (!strcmp(ptmp, "parse_proto_program"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->blacklist_parse_proto_program = 1;
                                        }

                                    if (!strcmp(ptmp, "lognorm"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->blacklist_lognorm = 1;
                                        }

                                    if (!strcmp(ptmp, "priority"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->blacklist_priority=atoi(ptmp);
                                        }

                                    ptmp = strtok_r(NULL, "=", &tok);

                                }
                        }

                    /******* Search "Nocase" *******/

                    if (!strcmp(sagan_var1, "search_nocase:"))
                        {

                            /* Set defaults */

                            config->search_nocase_flag=1;
                            config->search_nocase_parse_depth=2;
                            config->search_nocase_priority=SEARCH_PROCESSOR_PRI;

                            ptmp = sagan_var1;

                            while (ptmp != NULL )
                                {

                                    if (!strcmp(ptmp, "parse_src"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->search_nocase_parse_src = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "parse_dst"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->search_nocase_parse_dst = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "parse_proto"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->search_nocase_parse_proto = 1;
                                        }

                                    if (!strcmp(ptmp, "parse_proto_program"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->search_nocase_parse_proto_program = 1;
                                        }

                                    if (!strcmp(ptmp, "searchlist"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->search_nocase_file, Remove_Return(ptmp), sizeof(config->search_nocase_file));
                                        }

                                    if (!strcmp(ptmp, "lognorm"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->search_nocase_lognorm = 1;
                                        }

                                    if (!strcmp(ptmp, "priority"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->search_nocase_priority=atoi(ptmp);
                                        }

                                    ptmp = strtok_r(NULL, "=", &tok);

                                }
                        }

                    /******* Search "case" *******/

                    if (!strcmp(sagan_var1, "search_case:"))
                        {

                            config->search_case_flag=1;
                            config->search_case_parse_depth=2;
                            config->search_case_parse_src = 1;
                            config->search_case_parse_src = 2;

                            ptmp = sagan_var1;

                            while (ptmp != NULL )
                                {

                                    if (!strcmp(ptmp, "parse_src"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->search_case_parse_src = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "parse_dst"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->search_case_parse_dst = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "parse_proto"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->search_case_parse_proto = 1;
                                        }

                                    if (!strcmp(ptmp, "parse_proto_program"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->search_case_parse_proto_program = 1;
                                        }

                                    if (!strcmp(ptmp, "searchlist"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->search_case_file, Remove_Return(ptmp), sizeof(config->search_case_file));
                                        }

                                    if (!strcmp(ptmp, "lognorm"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->search_case_lognorm = 1;
                                        }

                                    if (!strcmp(ptmp, "priority"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->search_case_priority=atoi(ptmp);
                                        }

                                    ptmp = strtok_r(NULL, "=", &tok);
                                }
                        }

#ifdef WITH_WEBSENSE

                    /******* Websense *******/

                    if (!strcmp(sagan_var1, "websense:"))
                        {

                            config->websense_flag=1;

                            /* Set defaults */

                            config->websense_parse_depth=2;		/* default */
                            strlcpy(config->websense_device_id, "NO_DEVICE_ID", sizeof(config->websense_device_id));
                            config->websense_parse_src = 1;
                            config->websense_parse_dst = 2;
                            config->websense_priority = WEBSENSE_PROCESSOR_PRI;

                            ptmp = sagan_var1;

                            while (ptmp != NULL )
                                {

                                    if (!strcmp(ptmp, "parse_depth"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->websense_parse_depth = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "auth"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->websense_auth, Remove_Return(ptmp), sizeof(config->websense_auth));
                                        }

                                    if (!strcmp(ptmp, "url"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->websense_url, Remove_Return(ptmp), sizeof(config->websense_url));
                                        }

                                    if (!strcmp(ptmp, "max_cache"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->websense_max_cache = strtoull(ptmp, NULL, 10);
                                        }

                                    if (!strcmp(ptmp, "cache_timeout"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->websense_timeout = atoi(ptmp) * 60;
                                        }

                                    if (!strcmp(ptmp, "ignore_list"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->websense_ignore_list, Remove_Return(ptmp), sizeof(config->websense_ignore_list));
                                        }

                                    if (!strcmp(ptmp, "device_id"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->websense_device_id, Remove_Return(ptmp), sizeof(config->websense_device_id));
                                        }

                                    if (!strcmp(ptmp, "parse_src"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->websense_parse_src = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "parse_dst"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->websense_parse_dst = atoi(ptmp);
                                        }

                                    if (!strcmp(ptmp, "parse_proto"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->websense_parse_proto = 1;
                                        }

                                    if (!strcmp(ptmp, "parse_proto_program"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->websense_parse_proto_program = 1;
                                        }

                                    if (!strcmp(ptmp, "lognorm"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            if (!strcmp(ptmp, "true") || !strcmp(ptmp, "1")) config->websense_lognorm = 1;
                                        }

                                    if (!strcmp(ptmp, "priority"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->websense_priority=atoi(ptmp);
                                        }

                                    ptmp = strtok_r(NULL, "=", &tok);
                                }

                        }

                    /* ERROR CHECKING HERE? */

#endif
                }

            /****************************************************************************
             * Output formats
             ****************************************************************************/

            if (!strcmp(sagan_option, "output"))
                {

                    config->output_thread_flag = 1;

                    sagan_var1 = strtok_r(NULL," ", &tok);

                    if (!strcmp(sagan_var1, "external:"))
                        {
                            config->sagan_ext_flag=1;
                            config->sagan_external_output_flag=1;
                            strlcpy(config->sagan_extern, Remove_Return(strtok_r(NULL, " ", &tok)), sizeof(config->sagan_extern));
                            if (strstr(strtok_r(NULL, " ", &tok), "parsable")) config->sagan_exttype=1;
                        }


#ifdef WITH_SNORTSAM
                    if (!strcmp(sagan_var1, "alert_fwsam:"))
                        {
                            strlcpy(config->sagan_fwsam_info, Remove_Return(strtok_r(NULL, " ", &tok)), sizeof(config->sagan_fwsam_info));
                            config->sagan_fwsam_flag=1;
                        }
#endif

#if !defined(HAVE_DNET_H) && !defined(HAVE_DUMBNET_H)
                    if (!strcmp(sagan_var1, "unified2:"))
                        {
                            Sagan_Log(S_WARN,"\"libdnet\" support not found.  This is needed for unified2.");
                            Sagan_Log(S_WARN, "Re-compile with libdnet support or disable in the sagan.conf.");
                        }
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

                    if (!strcmp(sagan_var1, "unified2:"))
                        {

                            config->sagan_unified2_flag = 1;

                            ptmp = sagan_var1;
                            Remove_Return(ptmp);

                            while (ptmp != NULL )
                                {

                                    if (!strcmp(ptmp, "filename"))
                                        {
                                            ptmp = strtok_r(NULL, ",", &tok);
                                            snprintf(config->unified2_filepath, sizeof(config->unified2_filepath)-1, "%s/%s", config->sagan_log_path, ptmp);
                                        }

                                    if (!strcmp(ptmp, "limit"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            config->unified2_limit = atoi(ptmp) * 1024 * 1024;
                                        }

                                    if (!strcmp(ptmp, "nostamp")) config->unified2_nostamp = 1;

                                    ptmp = strtok_r(NULL, " ", &tok);

                                }
                        }

#endif

#ifdef HAVE_LIBESMTP

                    if (!strcmp(sagan_var1, "email:"))
                        {

                            ptmp = sagan_var1;

                            while (ptmp != NULL )
                                {

                                    if (!strcmp(ptmp, "from"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->sagan_esmtp_from, Remove_Return(ptmp), sizeof(config->sagan_esmtp_from));
                                        }

                                    if (!strcmp(ptmp, "smtpserver"))
                                        {
                                            ptmp = strtok_r(NULL, " ", &tok);
                                            strlcpy(config->sagan_esmtp_server, Remove_Return(ptmp), sizeof(config->sagan_esmtp_server));
                                        }

                                    ptmp = strtok_r(NULL, "=", &tok);
                                }

                        }
#endif
                }

            /* var */

            if (!strcmp(sagan_option, "var"))
                {
                    sagan_var1 = strtok_r(NULL, " ", &tok);
                    var = (_SaganVar *) realloc(var, (counters->var_count+1) * sizeof(_SaganVar));   /* Allocate memory */
                    snprintf(var[counters->var_count].var_name, sizeof(var[counters->var_count].var_name)-1, "$%s", sagan_var1);


                    /* Test for multiple values via [ ] or signle value */

                    if (strstr(tmpbuf2, "[") && !strstr(tmpbuf2, "]") || !strstr(tmpbuf2, "[") && strstr(tmpbuf2, "]"))
                        {
                            Sagan_Log(S_ERROR, "[%s, line %d] A 'var' in the sagan.conf file contains mismatched [ ]!", __FILE__, __LINE__);
                        }

                    /* Multiple values */

                    if (strstr(tmpbuf2, "[") && strstr(tmpbuf2, "]"))
                        {

                            sagan_var2 = strtok_r(NULL, "[", &tok);
                            sagan_var3 = strtok_r(sagan_var2, "]", &tok2);

                            Remove_Spaces(sagan_var3);
                            Remove_Return(sagan_var3);

                            strlcpy(var[counters->var_count].var_value, sagan_var3, sizeof(var[counters->var_count].var_value));


                        }
                    else
                        {

                            /* Single value */

                            sagan_var2 = strtok_r(NULL, " ", &tok); /* Move to position of value of var */
                            strlcpy(var[counters->var_count].var_value, Remove_Return(sagan_var2), sizeof(var[counters->var_count].var_value));

                        }


                    counters->var_count++;

                    /* Required var's - all others are optional */

                    if (!strcmp(sagan_var1, "FIFO") && config->sagan_fifo_flag != 1) strlcpy(config->sagan_fifo, sagan_var2, sizeof(config->sagan_fifo));
                    if (!strcmp(sagan_var1, "LOCKFILE" )) strlcpy(config->sagan_lockfile, sagan_var2, sizeof(config->sagan_lockfile));
                    if (!strcmp(sagan_var1, "ALERTLOG" )) strlcpy(config->sagan_alert_filepath, sagan_var2, sizeof(config->sagan_alert_filepath));
                    if (!strcmp(sagan_var1, "SAGANLOGPATH" )) strlcpy(config->sagan_log_path, sagan_var2, sizeof(config->sagan_log_path));


                    /*
                    	if (!strcmp(sagan_var1, "HOME_NET" )) {
                    	   if (strcasestr(sagan_var2, "any" )) config->home_any = 1;
                    	   }

                    	if (!strcmp(sagan_var1, "EXTERNAL_NET" )) {
                    	   if (strcasestr(sagan_var2, "any" )) config->external_any = 1;
                    	   }
                    */
                }

            /* "include */

            if (!strcmp(sagan_option, "include" ))
                {

                    strlcpy(tmpstring, Remove_Return(strtok_r(NULL, " ", &tok)), sizeof(tmpstring));

                    strlcpy(ruleset, Sagan_Var_To_Value(tmpstring), sizeof(ruleset));
                    Remove_Spaces(ruleset);

                    filename=Get_Filename(ruleset);   /* Get the file name to figure out "what" we're loading */

                    if (!strcmp(filename, "classification.config")) Load_Classifications(ruleset);
                    if (!strcmp(filename, "reference.config")) Load_Reference(ruleset);
                    if (!strcmp(filename, "gen-msg.map")) Load_Gen_Map(ruleset);
                    if (!strcmp(filename, "protocol.map")) Load_Protocol_Map(ruleset);

                    /* It's not reference.config, classification.config, gen-msg.map or protocol.map, it must be a ruleset */

                    if (strcmp(filename, "reference.config") && strcmp(filename, "classification.config") && strcmp(filename, "gen-msg.map") && strcmp(filename, "protocol.map"))
                        {
//			    pthread_mutex_lock(&SaganLoadRules);
                            Load_Rules(ruleset);
//			    pthread_mutex_unlock(&SaganLoadRules);

                        }
                }
        }

    fclose(sagancfg);

    /* Check rules for duplicate sid.  We can't have that! */

    for (i = 0; i < counters->rulecount; i++)
        {
            for ( check = i+1; check < counters->rulecount; check ++)
                {
                    if (!strcmp (rulestruct[check].s_sid, rulestruct[i].s_sid ))
                        Sagan_Log(S_ERROR, "[%s, line %d] Detected duplicate signature id [sid] number %s.  Please correct this.", __FILE__, __LINE__, rulestruct[check].s_sid, rulestruct[i].s_sid);
                }
        }

    /* If we have the "send-to" option,  verify the configuration has the proper smtpserver, etc.  */

#ifdef HAVE_LIBESMTP

    if (config->sagan_esmtp_flag && !strcmp(config->sagan_esmtp_server, "")) Sagan_Log(S_ERROR, "[%s, line %d] Configuration SMTP 'smtpserver' field is missing! |%s|", __FILE__, __LINE__, config->sagan_esmtp_server);
    if (config->sagan_esmtp_flag && !strcmp(config->sagan_esmtp_from, "" )) Sagan_Log(S_ERROR, "[%s, line %d] Configuration SMTP 'from' field is missing!", __FILE__,  __LINE__);

#endif

    if (!strcmp(config->sagan_fifo, "")) Sagan_Log(S_ERROR, "No FIFO option found which is required! Aborting!");
    if (!strcmp(config->sagan_host, "" )) Sagan_Log(S_ERROR, "The 'sagan_host' option was not found and is required.");
    if ( config->sagan_port == 0 ) Sagan_Log(S_ERROR, "The 'sagan_port' option was not set and is required.");

#ifdef HAVE_LIBGEOIP
    if ( config->have_geoip )
        {
            if ( Sagan_Check_Var("$HOME_COUNTRY") == 0 )
                {
                    Sagan_Log(S_ERROR, "[%s, line %d] GeoIP is in use,  but $HOME_COUNTRY was never set in your configuration. Abort.", __FILE__, __LINE__);
                }
        }
#endif

}
