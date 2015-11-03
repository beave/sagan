/* $Id$ */
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

/* sagan.h
 *
 * Sagan prototypes and definitions.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdint.h>
#include <pcre.h>
#include <time.h>

#ifdef HAVE_LIBMAXMINDDB
#include <maxminddb.h>
#endif

#include "sagan-defs.h"

typedef char sbool;	/* From rsyslog. 'bool' causes compatiablity problems on OSX. "(small bool) I intentionally use char, to keep it slim so that many fit into the CPU cache!".  */

#ifndef HAVE_STRLCPY
int strlcpy(char *, const char *,  size_t );
#endif

#ifndef HAVE_STRLCAT
int strlcat(char *, const char *, size_t );
#endif

int    Is_Numeric (char *);
char   *To_UpperC(char* const );
char   *To_LowerC(char* const );

int	Check_Endian( void );
void    Usage( void );
void    Sagan_Chroot( const char * );
char   *Remove_Return(char *);
char   *Remove_Spaces(char *);
char   *Between_Quotes( char * );
double CalcPct(uint64_t, uint64_t);
char   *Replace_String(char *, char *, char *);
char   *Get_Filename(char *);

typedef struct _SaganDNSCache _SaganDNSCache;
struct _SaganDNSCache
{

    char hostname[64];
    char src_ip[20];
};

typedef struct _SaganCounters _SaganCounters;
struct _SaganCounters
{

    uint64_t threshold_total;
    uint64_t after_total;
    uint64_t sagantotal;
    uint64_t saganfound;
    uint64_t sagan_output_drop;
    uint64_t sagan_processor_drop;
    uint64_t sagan_log_drop;
    uint64_t dns_cache_count;
    uint64_t dns_miss_count;
    uint64_t fwsam_count;
    uint64_t ignore_count;
    uint64_t blacklist_count;

    uint64_t alert_total;

    uint64_t malformed_host;
    uint64_t malformed_facility;
    uint64_t malformed_priority;
    uint64_t malformed_level;
    uint64_t malformed_tag;
    uint64_t malformed_date;
    uint64_t malformed_time;
    uint64_t malformed_program;
    uint64_t malformed_message;

    uint64_t worker_thread_exhaustion;

    uint64_t track_clients_client_count;                /* sagan-track-clients processor */
    uint64_t track_clients_down;

    uint64_t blacklist_hit_count;
    uint64_t blacklist_lookup_count;

    int	     thread_output_counter;
    int	     thread_processor_counter;

    int	     flowbit_total_counter;

    int      var_count;

    int	     classcount;
    int      rulecount;
    int	     refcount;
    int      ruletotal;

    int      genmapcount;
    int	     mapcount;
    int      mapcount_message;
    int      mapcount_program;

    int	     droplist_count;

    int	     flowbit_count;
    int	     flowbit_track_count;

    int      brointel_addr_count;
    int      brointel_domain_count;
    int      brointel_file_hash_count;
    int      brointel_url_count;
    int      brointel_software_count;
    int      brointel_email_count;
    int      brointel_user_name_count;
    int      brointel_file_name_count;
    int      brointel_cert_hash_count;
    int      brointel_dups;

#ifdef HAVE_LIBLOGNORM
    int liblognormtoload_count;
#endif

#ifdef HAVE_LIBMAXMINDDB
    uint64_t geoip2_hit;				/* GeoIP2 hit count */
    uint64_t geoip2_lookup;				/* Total lookups */
    uint64_t geoip2_miss;				/* Misses (country not found) */
#endif

#ifdef WITH_BLUEDOT
    uint64_t bluedot_ip_cache_count;                      /* Bluedot cache processor */
    uint64_t bluedot_ip_cache_hit;                        /* Bluedot hit's from Cache */
    uint64_t bluedot_ip_positive_hit;
    uint64_t bluedot_ip_total;

    uint64_t bluedot_error_count;

    uint64_t bluedot_hash_cache_count;
    uint64_t bluedot_hash_cache_hit;
    uint64_t bluedot_hash_positive_hit;
    uint64_t bluedot_hash_total;

    uint64_t bluedot_url_cache_count;
    uint64_t bluedot_url_cache_hit;
    uint64_t bluedot_url_positive_hit;
    uint64_t bluedot_url_total;

    uint64_t bluedot_filename_cache_count;
    uint64_t bluedot_filename_cache_hit;
    uint64_t bluedot_filename_positive_hit;
    uint64_t bluedot_filename_total;

    int bluedot_cat_count;

#endif


#ifdef HAVE_LIBESMTP
    uint64_t esmtp_count_success;
    uint64_t esmtp_count_failed;
#endif

};

typedef struct _SaganDebug _SaganDebug;
struct _SaganDebug
{

    sbool debugsyslog;
    sbool debugload;
    sbool debugfwsam;
    sbool debugexternal;
    sbool debugthreads;
    sbool debugflowbit;
    sbool debugengine;
    sbool debugbrointel;
    sbool debugmalformed;
    sbool debuglimits;

#ifdef HAVE_LIBMAXMINDDB
    sbool debuggeoip2;
#endif

#ifdef HAVE_LIBLOGNORM
    sbool debugnormalize;
#endif

#ifdef HAVE_LIBESMTP
    sbool debugesmtp;
#endif

#ifdef HAVE_LIBPCAP
    sbool debugplog;
#endif

#ifdef WITH_BLUEDOT
    sbool debugbluedot;
#endif



};

typedef struct _Sagan_Proc_Syslog
{
    char syslog_host[50];
    char syslog_facility[50];
    char syslog_priority[50];
    char syslog_level[50];
    char syslog_tag[50];
    char syslog_date[50];
    char syslog_time[50];
    char syslog_program[50];
    char syslog_message[MAX_SYSLOGMSG];
} _SaganProcSyslog;

typedef struct _Sagan_Event
{

    char *ip_src;
    char *ip_dst;
    int   dst_port;
    int   src_port;

    time_t event_time_sec;

    int  found;

    char *fpri;             /* ?? == *priority */

    sbool endian;
    sbool drop;

    char *f_msg;

    /* message information */

    char *time;
    char *date;

    char *priority;         /* Syslog priority */
    char *host;
    char *facility;
    char *level;
    char *tag;
    char *program;
    char *message;

    char *sid;
    char *rev;
    char *class;
    int pri;
    int ip_proto;

    char *normalize_http_uri;
    char *normalize_http_hostname;

    unsigned long generatorid;
    unsigned long alertid;


} _SaganEvent;

/* Thresholding structure by source */
typedef struct thresh_by_src thresh_by_src;
struct thresh_by_src
{
    uint32_t ipsrc;
    int  count;
    uint64_t utime;
    char sid[32];
};

/* Thresholding structure by destination */
typedef struct thresh_by_dst thresh_by_dst;
struct thresh_by_dst
{
    uint32_t ipdst;
    int  count;
    uint64_t utime;
    char sid[32];
};

/* Thesholding structure by username */
typedef struct thresh_by_username thresh_by_username;
struct thresh_by_username
{
    char username[128];
    int  count;
    uint64_t utime;
    char sid[32];
};


/* After structure by source */
typedef struct after_by_src after_by_src;
struct after_by_src
{
    uint32_t ipsrc;
    int  count;
    uint64_t utime;
    char sid[32];
};

/* After structure by destination */
typedef struct after_by_dst after_by_dst;
struct after_by_dst
{
    uint32_t ipdst;
    int  count;
    uint64_t utime;
    char sid[32];
};

/* After structure by username */
typedef struct after_by_username after_by_username;
struct after_by_username
{
    char username[128];
    int  count;
    uint64_t utime;
    char sid[32];
};


typedef struct _SaganVar _SaganVar;
struct _SaganVar
{
    char var_name[MAX_VAR_NAME_SIZE];
    char var_value[MAX_VAR_VALUE_SIZE];
};

typedef struct _Sagan_Processor_Info _Sagan_Processor_Info;
struct _Sagan_Processor_Info
{

    char *processor_name;
    char *processor_facility;
    char *processor_priority;		/* Syslog priority */
    int   processor_pri;		/* Sagan priority */
    char *processor_class;
    char *processor_tag;
    char *processor_rev;
    int   processor_generator_id;
};


void Sagan_Log( int, const char *, ... );
void Sagan_Droppriv( void );
char *DNS_Lookup( char * );
char *Sagan_Var_To_Value(char *);
uint32_t IP2Bit (char * );
int Sagan_Validate_HEX (const char *);
char *Sagan_Content_Pipe(char *, int, const char *);
sbool is_rfc1918 ( uint32_t );
char *Sagan_Replace_Sagan( char *, char *);
int Sagan_Character_Count ( char *, char *);
sbool Sagan_Wildcard( char *, char *);
void Sagan_Open_Log_File( sbool, int );
int Sagan_Check_Var(const char *);

#if defined(F_GETPIPE_SZ) && defined(F_SETPIPE_SZ)
void Sagan_Set_Pipe_Size( FILE * );
#endif
