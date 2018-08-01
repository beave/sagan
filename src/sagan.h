/* $Id$ */
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
#include <stddef.h>
#include <pcre.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include "sagan-defs.h"

#ifdef HAVE_LIBMAXMINDDB
#include <maxminddb.h>
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t );
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t );
#endif

/*
 * OS specific macro's for setting the thread name. "top" can display
 * this name. This was largely taken from Suricata.
 */

#if defined __FreeBSD__ /* FreeBSD */
/** \todo Add implementation for FreeBSD */
#define SetThreadName(n) ({ \
    char tname[16] = ""; \
    if (strlen(n) > 16) \
        Sagan_Log(WARN, "Thread name is too long, truncating it..."); \
    strlcpy(tname, n, 16); \
    pthread_set_name_np(pthread_self(), tname); \
    0; \
})
#elif defined __OpenBSD__ /* OpenBSD */
/** \todo Add implementation for OpenBSD */
#define SetThreadName(n) (0)
#elif defined OS_WIN32 /* Windows */
/** \todo Add implementation for Windows */
#define SetThreadName(n) (0)
#elif defined OS_DARWIN /* Mac OS X */
/** \todo Add implementation for MacOS */
#define SetThreadName(n) (0)
#elif defined HAVE_SYS_PRCTL_H /* PR_SET_NAME */
/**
 * \brief Set the threads name
 */
#define SetThreadName(n) ({ \
    char tname[THREAD_NAME_LEN + 1] = ""; \
    if (strlen(n) > THREAD_NAME_LEN) \
        Sagan_Log(WARN, "Thread name is too long, truncating it..."); \
    strlcpy(tname, n, THREAD_NAME_LEN); \
    int ret = 0; \
    if ((ret = prctl(PR_SET_NAME, tname, 0, 0, 0)) < 0) \
        Sagan_Log(WARN, "Error setting thread name \"%s\": %s", tname, strerror(errno)); \
    ret; \
})
#else
#define SetThreadName(n) (0)
#endif

bool     Is_Numeric (char *);
void      To_UpperC(char* const );
void      To_LowerC(char* const );
bool	  Check_Endian( void );
void      Usage( void );
void      Chroot( const char * );
void	  Remove_Return(char *);
int       Classtype_Lookup( const char *, char *, size_t size );
void      Remove_Spaces(char *);
void      Between_Quotes( char *, char *str, size_t size );
double    CalcPct(uint64_t, uint64_t);
void      Replace_String(char *, char *, char *, char *str, size_t size);
uint64_t Value_To_Seconds (char *, uint64_t);
void      Sagan_Log( int, const char *, ... );
void      Droppriv( void );
int       DNS_Lookup( char *, char *str, size_t size );
void      Var_To_Value(char *, char *str, size_t size);
bool     IP2Bit (char *, unsigned char * );
bool     Mask2Bit (int, unsigned char * );
const char *Bit2IP(unsigned char *, char *str, size_t size);
bool     Validate_HEX (const char *);
void      Content_Pipe(char *, int, const char *, char *, size_t size);
bool     is_notroutable ( unsigned char * );
bool     is_inrange ( unsigned char *, unsigned char *, int );
void      Replace_Sagan( char *, char *, char *str, size_t size);
int       Character_Count ( char *, char *);
bool     Wildcard( char *, char *);
void      Open_Log_File( bool, int );
int       Check_Var(const char *);
int       Netaddr_To_Range( char *, unsigned char * );
void      Strip_Chars(const char *string, const char *chars, char *str);
bool     Is_IP (char *ipaddr, int ver);
bool     File_Lock ( int );
bool     File_Unlock ( int );
bool     Check_Content_Not( char * );
uint32_t  Djb2_Hash( char * );
bool     Starts_With(const char *str, const char *prefix);
char      *strrpbrk(const char *str, const char *accept);



#if defined(F_GETPIPE_SZ) && defined(F_SETPIPE_SZ)
void      Set_Pipe_Size( FILE * );
#endif


#ifdef __OpenBSD__
/* OpenBSD won't allow for this test:
 * "suricata(...): mprotect W^X violation" */
#ifndef PageSupportsRWX()
#define PageSupportsRWX() 0
#endif
#else
#ifndef HAVE_SYS_MMAN_H
#define PageSupportsRWX() 1
#else
int       PageSupportsRWX(void);
#endif /* HAVE_SYS_MMAN_H */
#endif

typedef struct _SyslogInput _SyslogInput;
struct _SyslogInput
{
    char *syslog_host;
    char *syslog_facility;
    char *syslog_priority;
    char *syslog_level;
    char *syslog_tag;
    char *syslog_date;
    char *syslog_time;
    char *syslog_program;
    char *syslog_msg;
};

typedef struct _SaganDNSCache _SaganDNSCache;
struct _SaganDNSCache
{

    char hostname[64];
    char src_ip[20];
};

typedef struct _Sagan_IPC_Counters _Sagan_IPC_Counters;
struct _Sagan_IPC_Counters
{

    int  xbit_count;
    int	 thresh_count_by_src;
    int	 thresh_count_by_dst;
    int	 thresh_count_by_dstport;
    int  thresh_count_by_srcport;
    int	 thresh_count_by_username;
    int	 after_count_by_src;
    int	 after_count_by_dst;
    int  after_count_by_srcport;
    int	 after_count_by_dstport;
    int	 after_count_by_username;

    int	 track_client_count;
    int  track_clients_client_count;
    int  track_clients_down;

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

    uint64_t blacklist_hit_count;
    uint64_t blacklist_lookup_count;

    int	     thread_output_counter;
    int	     thread_processor_counter;

    int	     xbit_total_counter;

    int      var_count;

    int	     dynamic_rule_count;

    int	     classcount;
    int      rulecount;
    int	     refcount;
    int      ruletotal;

    int      genmapcount;

    int      mapcount_message;
    int      mapcount_program;

    int	     droplist_count;

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

    int	      rules_loaded_count;

    uint64_t follow_flow_total;	 /* This will only be needed if follow_flow is an option */
    uint64_t follow_flow_drop;   /* Amount of flows that did not match and were dropped */

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

    int bluedot_ip_queue_current;
    int bluedot_hash_queue_current;
    int bluedot_url_queue_current;
    int bluedot_filename_queue_current;

    uint64_t bluedot_mdate;					   /* Hits , but where over a modification date */
    uint64_t bluedot_cdate;            	                   /* Hits , but where over a creation date */
    uint64_t bluedot_mdate_cache;                                 /* Hits from cache , but where over a modification date */
    uint64_t bluedot_cdate_cache;      			   /* Hits from cache , but where over a create date */
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

#ifdef HAVE_LIBHIREDIS
    uint64_t redis_writer_threads_drop;
#endif

};

typedef struct _SaganDebug _SaganDebug;
struct _SaganDebug
{

    bool debugsyslog;
    bool debugload;
    bool debugfwsam;
    bool debugexternal;
    bool debugthreads;
    bool debugxbit;
    bool debugengine;
    bool debugbrointel;
    bool debugmalformed;
    bool debuglimits;
    bool debugipc;
    bool debugjson;
    bool debugparse_ip;

#ifdef HAVE_LIBMAXMINDDB
    bool debuggeoip2;
#endif

#ifdef HAVE_LIBLOGNORM
    bool debugnormalize;
#endif

#ifdef HAVE_LIBESMTP
    bool debugesmtp;
#endif

#ifdef HAVE_LIBPCAP
    bool debugplog;
#endif

#ifdef WITH_BLUEDOT
    bool debugbluedot;
#endif

#ifdef HAVE_LIBHIREDIS
    bool debugredis;
#endif

};

#ifdef HAVE_LIBHIREDIS

typedef struct _Sagan_Redis _Sagan_Redis;
struct _Sagan_Redis
{
    char redis_command[2048];
};

#endif

typedef struct _Sagan_Proc_Syslog _Sagan_Proc_Syslog;
struct _Sagan_Proc_Syslog
{
    char syslog_host[MAX_SYSLOG_HOST];
    char syslog_facility[MAX_SYSLOG_FACILITY];
    char syslog_priority[MAX_SYSLOG_PRIORITY];
    char syslog_level[MAX_SYSLOG_LEVEL];
    char syslog_tag[MAX_SYSLOG_TAG];
    char syslog_date[MAX_SYSLOG_DATE];
    char syslog_time[MAX_SYSLOG_TIME];
    char syslog_program[MAX_SYSLOG_PROGRAM];
    char syslog_message[MAX_SYSLOGMSG];

};

typedef struct _Syslog_JSON_Map _Syslog_JSON_Map;
struct _Syslog_JSON_Map
{
    char syslog_map_host[JSON_MAP_HOST];
    char syslog_map_facility[JSON_MAP_FACILITY];
    char syslog_map_priority[JSON_MAP_PRIORITY];
    char syslog_map_level[JSON_MAP_LEVEL];
    char syslog_map_tags[JSON_MAP_TAG];
    char syslog_map_date[JSON_MAP_DATE];
    char syslog_map_time[JSON_MAP_TIME];
    char syslog_map_program[JSON_MAP_PROGRAM];
    char syslog_map_message[JSON_MAP_MESSAGE];

};


typedef struct _Sagan_Event _Sagan_Event;
struct _Sagan_Event
{

    char *ip_src;
    char *ip_dst;
    int   dst_port;
    int   src_port;

    char *selector;

    struct timeval event_time;

    int  found;

    char *fpri;             /* *priority */

    bool endian;
    bool drop;

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

    json_object *json_normalize;
};


/* Thresholding structure by source */

typedef struct thresh_by_src_ipc thresh_by_src_ipc;
struct thresh_by_src_ipc
{
    unsigned char ipsrc[MAXIPBIT];
    int  count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
    char syslog_message[MAX_SYSLOGMSG];
    char signature_msg[MAX_SAGAN_MSG];
};


/* Thresholding structure by destination */

typedef struct thresh_by_dst_ipc thresh_by_dst_ipc;
struct thresh_by_dst_ipc
{
    unsigned char ipdst[MAXIPBIT];
    int  count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
    char syslog_message[MAX_SYSLOGMSG];
    char signature_msg[MAX_SAGAN_MSG];
};


/* Thresholding structure by source port */

typedef struct thresh_by_srcport_ipc thresh_by_srcport_ipc;
struct thresh_by_srcport_ipc
{
    uint32_t ipsrcport;
    int  count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
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
    char selector[MAXSELECTOR];
};


/* Thesholding structure by username */

typedef struct thresh_by_username_ipc thresh_by_username_ipc;
struct thresh_by_username_ipc
{
    char username[128];
    int  count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
    char syslog_message[MAX_SYSLOGMSG];
    char signature_msg[MAX_SAGAN_MSG];
};

/* After structure by source */

typedef struct after_by_src_ipc after_by_src_ipc;
struct after_by_src_ipc
{
    unsigned char ipsrc[MAXIPBIT];
    uint64_t count;
    uint64_t total_count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
    char syslog_message[MAX_SYSLOGMSG];
    char signature_msg[MAX_SAGAN_MSG];
};

/* After structure by destination */

typedef struct after_by_dst_ipc after_by_dst_ipc;
struct after_by_dst_ipc
{
    unsigned char ipdst[MAXIPBIT];
    int  count;
    uint64_t total_count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
    char syslog_message[MAX_SYSLOGMSG];
    char signature_msg[MAX_SAGAN_MSG];

};

/* After structure by source port */

typedef struct after_by_srcport_ipc after_by_srcport_ipc;
struct after_by_srcport_ipc
{
    uint32_t ipsrcport;
    uint64_t count;
    uint64_t total_count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
};

/* After structure by destination port */

typedef struct after_by_dstport_ipc after_by_dstport_ipc;
struct after_by_dstport_ipc
{
    uint32_t ipdstport;
    uint64_t count;
    uint64_t total_count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
};

/* After structure by username */

typedef struct after_by_username_ipc after_by_username_ipc;
struct after_by_username_ipc
{
    char username[128];
    uint64_t count;
    uint64_t total_count;
    uint64_t utime;
    char sid[20];
    int expire;
    char selector[MAXSELECTOR];
    char syslog_message[MAX_SYSLOGMSG];
    char signature_msg[MAX_SAGAN_MSG];
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

/* IP Lookup cache */

typedef struct _Sagan_Lookup_Cache_Entry _Sagan_Lookup_Cache_Entry;
struct _Sagan_Lookup_Cache_Entry
{
    char ip[MAXIP];
    unsigned char ip_bits[MAXIPBIT];
    int  port;
    unsigned char proto;
    bool status;
};

typedef struct _Sagan_Lookup_Cache_Entry _Sagan_Lookup_Cache_Other;
struct _Sagan_Lookup_Cache_Other
{
    int proto;
};

/* Function that require the above arrays */

//int64_t   FlowGetId( _Sagan_Event *);
int64_t	  FlowGetId(struct timeval tp);
void 	  Escape_Chars( char *str_in, char *str, size_t size);

