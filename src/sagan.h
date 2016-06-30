/* $Id$ */
/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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
#include <arpa/inet.h>

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
double CalcPct(uintmax_t, uintmax_t);
char   *Replace_String(char *, char *, char *);
char   *Get_Filename(char *);

uintmax_t Sagan_Value_To_Seconds (char *, uintmax_t);

typedef struct _SaganDNSCache _SaganDNSCache;
struct _SaganDNSCache
{

    char hostname[64];
    char src_ip[20];
};

typedef struct _Sagan_IPC_Counters _Sagan_IPC_Counters;
struct _Sagan_IPC_Counters
{

    int  flowbit_count;
    int	 thresh_count_by_src;
    int	 thresh_count_by_dst;
    int	 thresh_count_by_dstport;
    int	 thresh_count_by_username;
    int	 after_count_by_src;
    int	 after_count_by_dst;
    int	 after_count_by_dstport;
    int	 after_count_by_username;

    int	 track_client_count;
    int  track_clients_client_count;
    int  track_clients_down;

};


typedef struct _SaganCounters _SaganCounters;
struct _SaganCounters
{

    uintmax_t threshold_total;
    uintmax_t after_total;
    uintmax_t sagantotal;
    uintmax_t saganfound;
    uintmax_t sagan_output_drop;
    uintmax_t sagan_processor_drop;
    uintmax_t sagan_log_drop;
    uintmax_t dns_cache_count;
    uintmax_t dns_miss_count;
    uintmax_t fwsam_count;
    uintmax_t ignore_count;
    uintmax_t blacklist_count;

    uintmax_t alert_total;

    uintmax_t malformed_host;
    uintmax_t malformed_facility;
    uintmax_t malformed_priority;
    uintmax_t malformed_level;
    uintmax_t malformed_tag;
    uintmax_t malformed_date;
    uintmax_t malformed_time;
    uintmax_t malformed_program;
    uintmax_t malformed_message;

    uintmax_t worker_thread_exhaustion;

    uintmax_t blacklist_hit_count;
    uintmax_t blacklist_lookup_count;

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

    uintmax_t follow_flow_total;			/* This will only be needed if follow_flow is an option */
    uintmax_t follow_flow_drop;			/* Amount of flows that did not match and were dropped */

#ifdef HAVE_LIBMAXMINDDB
    uintmax_t geoip2_hit;				/* GeoIP2 hit count */
    uintmax_t geoip2_lookup;				/* Total lookups */
    uintmax_t geoip2_miss;				/* Misses (country not found) */
#endif

#ifdef WITH_BLUEDOT
    uintmax_t bluedot_ip_cache_count;                      /* Bluedot cache processor */
    uintmax_t bluedot_ip_cache_hit;                        /* Bluedot hit's from Cache */
    uintmax_t bluedot_ip_positive_hit;
    uintmax_t bluedot_ip_total;
	
    uintmax_t bluedot_mdate;					   /* Hits , but where over a modification date */
    uintmax_t bluedot_cdate;            	                   /* Hits , but where over a creation date */ 
    uintmax_t bluedot_mdate_cache;                                 /* Hits from cache , but where over a modification date */
    uintmax_t bluedot_cdate_cache;      			   /* Hits from cache , but where over a create date */


    uintmax_t bluedot_error_count;

    uintmax_t bluedot_hash_cache_count;
    uintmax_t bluedot_hash_cache_hit;
    uintmax_t bluedot_hash_positive_hit;
    uintmax_t bluedot_hash_total;

    uintmax_t bluedot_url_cache_count;
    uintmax_t bluedot_url_cache_hit;
    uintmax_t bluedot_url_positive_hit;
    uintmax_t bluedot_url_total;

    uintmax_t bluedot_filename_cache_count;
    uintmax_t bluedot_filename_cache_hit;
    uintmax_t bluedot_filename_positive_hit;
    uintmax_t bluedot_filename_total;

    int bluedot_cat_count;

#endif


#ifdef HAVE_LIBESMTP
    uintmax_t esmtp_count_success;
    uintmax_t esmtp_count_failed;
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
    sbool debugipc;

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
typedef struct thresh_by_src_ipc thresh_by_src_ipc;
struct thresh_by_src_ipc
{
    uint32_t ipsrc;
    int  count;
    uintmax_t utime;
    char sid[20];
    int expire;
};


/* Thresholding structure by destination */
typedef struct thresh_by_dst_ipc thresh_by_dst_ipc;
struct thresh_by_dst_ipc
{
    uint32_t ipdst;
    int  count;
    uintmax_t utime;
    char sid[20];
    int expire;
};


/* Thresholding structure by destination port */
typedef struct thresh_by_dstport_ipc thresh_by_dstport_ipc;
struct thresh_by_dstport_ipc
{
    uint32_t ipdstport;
    int  count;
    uint64_t utime;
    char sid[20];
    int expire;
};


/* Thesholding structure by username */
typedef struct thresh_by_username_ipc thresh_by_username_ipc;
struct thresh_by_username_ipc
{
    char username[128];
    int  count;
    uintmax_t utime;
    char sid[20];
    int expire;
};

/* After structure by source */
typedef struct after_by_src_ipc after_by_src_ipc;
struct after_by_src_ipc
{
    uint32_t ipsrc;
    int  count;
    uintmax_t utime;
    char sid[20];
    int expire;
};

/* After structure by destination */
typedef struct after_by_dst_ipc after_by_dst_ipc;
struct after_by_dst_ipc
{
    uint32_t ipdst;
    int  count;
    uintmax_t utime;
    char sid[20];
    int expire;
};


/* After structure by destination port */
typedef struct after_by_dstport_ipc after_by_dstport_ipc;
struct after_by_dstport_ipc
{
    uint32_t ipdstport;
    int  count;
    uint64_t utime;
    char sid[20];
    int expire;
};


/* After structure by username */
typedef struct after_by_username_ipc after_by_username_ipc;
struct after_by_username_ipc
{
    char username[128];
    int  count;
    uintmax_t utime;
    char sid[20];
    int expire;
};

typedef struct _SaganVar _SaganVar;
struct _SaganVar
{
    char var_name[MAX_VAR_NAME_SIZE];
    char var_value[MAX_VAR_VALUE_SIZE];
};

typedef struct network_addr
{
    in_addr_t addr;
    int pfx;
} network_addr_t;

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
char *Bit2IP(uint32_t);

int Sagan_Validate_HEX (const char *);
char *Sagan_Content_Pipe(char *, int, const char *);
sbool is_rfc1918 ( uint32_t );
char *Sagan_Replace_Sagan( char *, char *);
int Sagan_Character_Count ( char *, char *);
sbool Sagan_Wildcard( char *, char *);
void Sagan_Open_Log_File( sbool, int );
int Sagan_Check_Var(const char *);
char *Sagan_u32_Time_To_Human ( uintmax_t );
char *Netaddr_To_Range( char * );
char *Strip_Chars(const char *string, const char *chars);
sbool Is_IP (char *str);

char *Sagan_Return_Date( uintmax_t );
char *Sagan_Return_Time( uintmax_t );

sbool Sagan_File_Lock ( int );
sbool Sagan_File_Unlock ( int );

#if defined(F_GETPIPE_SZ) && defined(F_SETPIPE_SZ)
void Sagan_Set_Pipe_Size( FILE * );
#endif
