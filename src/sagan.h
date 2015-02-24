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

#ifdef HAVE_LIBGEOIP
#include <GeoIP.h>
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
void    Chroot( const char *, const char * );
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

    uint64_t track_clients_client_count;                /* sagan-track-clients processor */
    uint64_t track_clients_down;

    uint64_t blacklist_hit_count;

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

#ifdef HAVE_LIBGEOIP
    uint64_t geoip_hit;				/* GeoIP hit count */
    uint64_t geoip_lookup;			/* Total lookups */
    uint64_t geoip_miss;				/* Misses (country not found) */
#endif

#ifdef WITH_WEBSENSE
    uint64_t websense_cache_count;			/* Websense cache processor */
    uint64_t websense_cache_hit;			/* Websense hit's from Cache */
    uint64_t websense_postive_hit;
    uint64_t websense_ignore_hit;			/* Ignores from our ignore list */
    uint64_t websense_total;
    uint64_t websense_error_count;
    int websense_ignore_list_count;
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

#ifdef HAVE_LIBGEOIP
    sbool debuggeoip;
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

#ifdef WITH_WEBSENSE
    sbool debugwebsense;
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
    char *message;          /* msg + sysmsg? */

    char *sid;
    char *rev;
    char *class;
    int pri;
    int ip_proto;


    unsigned long generatorid;
    unsigned long alertid;


} _SaganEvent;

/* Thresholding structure by source */
typedef struct thresh_by_src thresh_by_src;
struct thresh_by_src
{
    unsigned s_size_thresh_by_src;
    char ipsrc[64];
    int  count;
    uint64_t utime;
    char sid[512];
};

/* Thresholding structure by destination */
typedef struct thresh_by_dst thresh_by_dst;
struct thresh_by_dst
{
    unsigned s_size_thresh_by_dst;
    char ipdst[64];
    int  count;
    uint64_t utime;
    char sid[512];
};

/* After structure by source */
typedef struct after_by_src after_by_src;
struct after_by_src
{
    unsigned s_size_afterh_by_src;
    char ipsrc[64];
    int  count;
    uint64_t utime;
    char sid[512];
};

/* After structure by destination */
typedef struct after_by_dst after_by_dst;
struct after_by_dst
{
    unsigned s_size_after_by_dst;
    char ipdst[64];
    int  count;
    uint64_t utime;
    char sid[512];
};

typedef struct _SaganVar _SaganVar;
struct _SaganVar
{
    char var_name[64];
    char var_value[64];
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
void sagan_droppriv( const char *);
char *DNS_Lookup( char * );
char *Sagan_Var_To_Value(char *);
uint32_t IP2Bit (char * );
int Sagan_Validate_HEX (const char *);
char *Sagan_Content_Pipe(char *, int, const char *);
sbool is_rfc1918 ( uint32_t );
char *Sagan_Replace_Sagan( char *, char *);
int Sagan_Character_Count ( char *, char *);

