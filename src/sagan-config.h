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
#include <hiredis/hiredis.h>
#endif

/* Sagan configuration struct (global) */

typedef struct _SaganConfig _SaganConfig;
struct _SaganConfig
{

    /* Non-dependent var's */

    sbool 	 sagan_reload;
    sbool	 daemonize;
    sbool	 quiet;

    sbool	 liblognorm_load;

    const char	 *sagan_runas;
    char         sagan_config[MAXPATH];                 /* Master Sagan configuration file */

    sbool    selector_flag;
    char     selector_name[MAXSELECTOR];

    sbool	 alert_flag;

    sbool	 	eve_flag; 			/* 0 = file */
    unsigned char 	eve_type;
    char		eve_interface[32];
    char 		eve_filename[MAXPATH];
    FILE		*eve_stream;
    int		    eve_fd;
    sbool		eve_alerts;
    sbool		eve_logs;


    char         sagan_alert_filepath[MAXPATH];

    char	 sagan_sensor_name[64];
    char         sagan_interface[50];
    FILE         *sagan_alert_stream;
    int          sagan_alert_fd;
    FILE	     *sagan_fast_stream;
    int	         sagan_fast_fd;
    char         sagan_log_filepath[MAXPATH];
    FILE         *sagan_log_stream;
    int          sagan_log_fd;
    char         sagan_lockfile[MAXPATH];
    char         sagan_fifo[MAXPATH];
    sbool        sagan_is_file;                       /* FIFO or FILE */
    char         sagan_log_path[MAXPATH];
    char         sagan_rule_path[MAXPATH];
    char         sagan_host[MAXHOST];
    char         sagan_startutime[20];                  /* Records utime at startup */
    char         home_net[MAXPATH];
    char         external_net[MAXPATH];
    char	 xbit_storage;				/* 0 == mmap, 1 == redis */

    char         sagan_droplistfile[MAXPATH];           /* Log lines to "ignore" */
    sbool        sagan_droplist_flag;

    sbool        output_thread_flag;

    int          max_processor_threads;

    sbool        sagan_external_output_flag;            /* For calling external commands */
    char         sagan_external_command[MAXPATH];

    int          sagan_port;
    sbool        disable_dns_warnings;
    sbool        syslog_src_lookup;
    int          sagan_proto;

    sbool	 pcre_jit; 				/* For PCRE JIT support testing */

    sbool        endian;

    sbool 	 fast_flag;
    char         fast_filename[MAXPATH];

    /* Processors */

    int         pp_sagan_track_clients;
    sbool       sagan_track_clients_flag;

    sbool       blacklist_flag;
    char        blacklist_files[2048];

    sbool	perfmonitor_flag;
    int		perfmonitor_time;
    char	perfmonitor_file_name[MAXPATH];
    FILE	*perfmonitor_file_stream;
    int	    perfmonitor_file_fd;

    sbool        sagan_fwsam_flag;
    char         sagan_fwsam_info[1024];

    /* Dynamic rule loading and reporting */

    sbool		dynamic_load_flag;
    int			dynamic_load_sample_rate;
    unsigned char	dynamic_load_type;

    /* Syslog output */

    sbool	sagan_syslog_flag;
    int		sagan_syslog_facility;
    int		sagan_syslog_priority;
    int		sagan_syslog_options;

    int		shm_counters;
    int		shm_xbit;
    int 	shm_thresh_by_src;
    int		shm_thresh_by_dst;
    int		shm_thresh_by_dstport;
    int		shm_thresh_by_srcport;
    int		shm_thresh_by_username;

    int		shm_after_by_src;
    int		shm_after_by_dst;
    int 	shm_after_by_srcport;
    int		shm_after_by_dstport;
    int		shm_after_by_username;

    int		shm_track_clients;

    /* IPC sizes for threshold, after, etc */

    char	ipc_directory[MAXPATH];

    int		max_xbits;

    int		max_threshold_by_src;
    int		max_threshold_by_dst;
    int         max_threshold_by_srcport;
    int		max_threshold_by_dstport;
    int		max_threshold_by_username;

    int		max_after_by_src;
    int		max_after_by_dst;
    int         max_after_by_srcport;
    int		max_after_by_dstport;
    int		max_after_by_username;

    int		max_track_clients;

#ifdef HAVE_LIBPCAP
    char        plog_interface[50];
    char        plog_logdev[50];
    char        plog_filter[256];
    sbool       plog_flag;
    int         plog_promiscuous;
#endif

    /* Redis/hiredis support */

#ifdef HAVE_LIBHIREDIS

    redisContext *c_reader_redis;
//    redisContext *c_writer_redis[MAX_THREADS];

    sbool 	redis_flag;
    char	redis_server[255];
    int		redis_port;
    char	redis_password[255];

    int		redis_max_writer_threads;

#endif

    /* libesmtp/SMTP support */

#ifdef HAVE_LIBESMTP
    sbool       sagan_sendto_flag;
    char        sagan_esmtp_from[255];
    char        sagan_esmtp_server[255];
    sbool       sagan_esmtp_flag;
    char        sagan_email_subject[64];
#endif

    /* libdnet - Used for unified2 support */

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
    char         unified2_filepath[MAXPATH];
    uint32_t     unified2_timestamp;
    FILE         *unified2_stream;
    int          unified2_fd;
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
    uintmax_t     bluedot_max_cache;
    uintmax_t     bluedot_last_time;                    /* For cache cleaning */
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

#if defined(HAVE_GETPIPE_SZ) && defined(HAVE_SETPIPE_SZ)
    int          sagan_fifo_size;
#endif

};


