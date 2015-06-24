/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
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

/* Sagan configuration struct (global) */

typedef struct _SaganConfig _SaganConfig;
struct _SaganConfig
{

    /* Non-dependent var's */

    sbool 	 sagan_reload;
    const char	 *sagan_runas;
    char         sagan_config[MAXPATH];                 /* Master Sagan configuration file */
    char         sagan_alert_filepath[MAXPATH];
    char         sagan_interface[50];
    FILE         *sagan_alert_stream;
    char         sagan_log_filepath[MAXPATH];
    FILE         *sagan_log_stream;
    char         sagan_lockfile[MAXPATH];
    char         sagan_fifo[MAXPATH];
    sbool        sagan_fifo_flag;                       /* FIFO or FILE */
    char         sagan_log_path[MAXPATH];
    char         sagan_rule_path[MAXPATH];
    char         sagan_host[MAXHOST];
    char         sagan_extern[MAXPATH];
    char         sagan_startutime[20];                  /* Records utime at startup */

    char         sagan_droplistfile[MAXPATH];           /* Log lines to "ignore" */
    sbool        sagan_droplist_flag;

    sbool        output_thread_flag;

    int          max_processor_threads;

    sbool        sagan_external_output_flag;            /* For things like external, email, fwsam */

    int          sagan_port;
    sbool        sagan_ext_flag;
    sbool        disable_dns_warnings;
    sbool        syslog_src_lookup;
    int          sagan_proto;

    /*    sbool        home_any;  */                     /* 0 == no, 1 == yes */
    /*    sbool        external_any;  */

    sbool 	 lognorm_all; 				/* Flag to load all normalization files or not */
    sbool        endian;

    /* Processors */

    int         pp_sagan_track_clients;
    sbool       sagan_track_clients_flag;
    char        sagan_track_client_host_cache[MAXPATH];
    FILE        *sagan_track_client_file;

    sbool       blacklist_flag;
    char        blacklist_files[2048];

    sbool	perfmonitor_flag;
    int		perfmonitor_time;
    char	perfmonitor_file_name[MAXPATH];
    FILE	*perfmonitor_file_stream;

    sbool        sagan_fwsam_flag;
    char         sagan_fwsam_info[1024];

    /* Syslog output */

    sbool	sagan_syslog_flag;
    int		sagan_syslog_facility;
    int		sagan_syslog_priority;
    int		sagan_syslog_options;


#ifdef HAVE_LIBPCAP
    char        plog_interface[50];
    char        plog_logdev[50];
    char        plog_filter[256];
    sbool       plog_flag;
    int         plog_promiscuous;
#endif

    /* libesmtp/SMTP support */

#ifdef HAVE_LIBESMTP
    int         min_email_priority;
    char        sagan_esmtp_to[255];
    sbool       sagan_sendto_flag;
    char        sagan_esmtp_from[255];
    char        sagan_esmtp_server[255];
    sbool       sagan_esmtp_flag;
    char        sagan_email_subject[64];
#endif

    /* Prelude framework support */

#ifdef HAVE_LIBPRELUDE
    char        sagan_prelude_profile[MAXPATH];
    sbool       sagan_prelude_flag;
#endif

    /* libdnet - Used for unified2 support */

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
    char         unified2_filepath[MAXPATH];
    uint32_t     unified2_timestamp;
    FILE         *unified2_stream;
    unsigned int unified2_limit;
    unsigned int unified2_current;
    int          unified2_nostamp;
    sbool        sagan_unified2_flag;
#endif

    /* Bluedot */

#ifdef WITH_BLUEDOT
    sbool        bluedot_flag;
    char         bluedot_device_id[64];
    char         bluedot_url[256];
    char         bluedot_auth[64];
    char         bluedot_cat[MAXPATH];
    int          bluedot_timeout;
    uint64_t     bluedot_max_cache;
    uint64_t     bluedot_last_time;                    /* For cache cleaning */
#endif


    /* Bro Intel Framework Support */

    sbool	 brointel_flag;
    char	 brointel_files[2048];

    /* For Maxmind GeoIP2 address lookup */

#ifdef HAVE_LIBMAXMINDDB

    MMDB_s 	geoip2;
    char        geoip2_country_file[MAXPATH];
    sbool 	have_geoip2;

#endif

    /* Used for altering pipe size (if supported) */

#if defined(F_GETPIPE_SZ) && defined(F_SETPIPE_SZ)
    int          sagan_fifo_size;
#endif

};



void Load_Config( void );
