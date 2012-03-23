/* $Id$ */
/*
** Copyright (C) 2009-2012 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2012 Champ Clark III <cclark@quadrantsec.com>
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
#include "sagan-defs.h"


typedef char sbool;	/* From rsyslog. 'bool' causes compatiablity problems on OSX. "(small bool) I intentionally use char, to keep it slim so that many fit into the CPU cache!".  */

#ifndef HAVE_STRLCPY
int strlcpy(char *, const char *,  size_t );
#endif

#ifndef HAVE_STRLCAT
int strlcat(char *, const char *, size_t );
#endif

int isnumeric (char *);
char *toupperc(char* const );
void sagan_error(const char *, ...);
char *gettimestamp( void );
void sagan_error( const char *, ... );
char *findipinmsg ( char * );
void closesagan( int );
int  checkendian( void );
void sagan_usage( void );
void load_normalize( void );
void sagan_chroot( const char *, const char * );
char *remrt(char *);
char *remspaces(char *);
char *remquotes(char *);
char *betweenquotes( char * );
char *reflookup( int, int );
double CalcPct(uint64_t, uint64_t);
char *sagan_replace_str(char *, char *, char *);
char *sagan_getfilename(char *);

char *referencelookup( int );

typedef struct _SaganDNSCache _SaganDNSCache;
struct _SaganDNSCache { 
	
	char hostname[64]; 
	char src_ip[20];
};

typedef struct _SaganCounters _SaganCounters;
struct _SaganCounters { 

    uint64_t threshold_total;
    uint64_t after_total;
    uint64_t sagantotal;
    uint64_t saganfound;
    uint64_t sagan_output_drop;
    uint64_t sagan_processor_drop;
    uint64_t sagan_log_drop;
    uint64_t dns_cache_count;
    uint64_t dns_miss_count;



    int	     thread_output_counter; 
    int	     thread_processor_counter;

    int	     classcount;
    int      rulecount;
    int	     refcount;
    int      ruletotal;

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
    uint64_t cid;            /* For passing CID with signal */
#endif

#ifdef HAVE_LIBLOGNORM
    int liblognormtoload_count;
#endif

};   

typedef struct _SaganDebug _SaganDebug;
struct _SaganDebug { 

    sbool debugsyslog;
    sbool debugload;
    sbool debugfwsam;

#ifdef HAVE_LIBLOGNORM
    sbool debugnormalize;
#endif

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
    sbool debugsql;
#endif

#ifdef HAVE_LIBESMTP
    sbool debugesmtp;
#endif 

#ifdef HAVE_LIBPCAP
    sbool debugplog;
#endif

};

/* Sagan configuration struct (global) */

typedef struct _SaganConfig _SaganConfig;
struct _SaganConfig {

/* Non-dependent var's */

    char	 sagan_config[MAXPATH];			/* Master Sagan configuration file */
    char         sagan_alert_filepath[MAXPATH];
    char         sagan_interface[50];
    FILE         *sagan_alert_stream;
    char	 sagan_log_filepath[MAXPATH];
    FILE	 *sagan_log_stream;
    char	 sagan_lockfile[MAXPATH];
    char	 sagan_fifo[MAXPATH];
    char	 sagan_log_path[MAXPATH];
    char 	 sagan_rule_path[MAXPATH];
    char         sagan_host[MAXHOST];
    char         sagan_extern[MAXPATH];
    char	 sagan_startutime[20]; 			/* Records utime at startup */
    
    uint64_t     max_output_threads;
    sbool	 output_thread_flag;

    uint64_t	 max_processor_threads;
    sbool	 processor_thread_flag;

    int		 sagan_port;
    int		 sagan_exttype;
    sbool	 sagan_ext_flag;
    sbool        disable_dns_warnings;
    sbool	 syslog_src_lookup;
    int		 daemonize;
    int          sagan_proto;

    sbool	 endian;


/* libesmtp/SMTP support */
    
#ifdef HAVE_LIBESMTP
    int		min_email_priority;
    char	sagan_esmtp_to[255];
    sbool	sagan_sendto_flag;
    char	sagan_esmtp_from[255];
    char	sagan_esmtp_server[255];
    sbool	sagan_esmtp_flag;
#endif

/* Prelude framework support */

#ifdef HAVE_LIBPRELUDE
    char	sagan_prelude_profile[255];
    sbool	sagan_prelude_flag;
#endif

/* "plog" - syslog sniffing vars */

#ifdef HAVE_LIBPCAP
    char	plog_interface[50];
    char	plog_logdev[50];
    int		plog_port;
    sbool	plog_flag;
#endif

/* libdnet - Used for unified2 support */

#ifdef HAVE_LIBDNET
    char         unified2_filepath[MAXPATH];
    uint32_t     unified2_timestamp;
    FILE         *unified2_stream;
    unsigned int unified2_limit;
    unsigned int unified2_current;
    int          unified2_nostamp;
    sbool	 sagan_unified2_flag;
#endif

/* MySQL/PostgreSQL support for Snort DB */

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
    int		 dbtype;
    int          sagan_detail;
    int		 sensor_id;
    char	 sagan_hostname[MAXHOST];
    char	 sagan_filter[50];
    char         dbuser[MAXUSER];
    char         dbpassword[MAXPASS];
    char         dbname[50]; 
    char         dbhost[50];
#endif

    sbool        sagan_fwsam_flag;
    char 	 sagan_fwsam_info[1024];

};


/* Parsers */

char *parse_ip_simple( char * );
int   parse_port_simple(_SaganConfig *, char * );

/* Reference structure */
typedef struct ref_struct ref_struct;
struct ref_struct {
unsigned s_size_ref;
char s_refid[512];
char s_refurl[2048];
};

/* Classification strucure */
typedef struct class_struct class_struct;
struct class_struct {
unsigned s_size_class;
char s_shortname[512];
char s_desc[512];
int  s_priority;
};

/* Rule structure */
typedef struct rule_struct rule_struct;
struct rule_struct {
unsigned s_size_rule;
char s_msg[512];

pcre *re_pcre[MAX_PCRE];
pcre_extra *pcre_extra[MAX_PCRE];

char s_content[MAX_CONTENT][512];
char s_reference[MAX_REFERENCE][512];
char s_classtype[512];
char s_sid[512];
char s_rev[512];
int  s_pri;
char s_program[512];
char s_facility[50];
char s_syspri[25];
char s_level[25];
char s_tag[10];

char email[255];
sbool email_flag;

int s_nocase;
int pcre_count;
int content_count;
int ref_count;
int dst_port;
int ip_proto;
sbool s_find_port;
sbool s_find_ip; 
sbool normalize;
int drop;			// inline DROP for ext.

int threshold_type;		// 1 = limit,  2 = thresh,
int threshold_src_or_dst;	// 1 ==  src,  2 == dst
int threshold_count;		
int threshold_seconds;

int after_src_or_dst;       // 1 ==  src,  2 == dst
int after_count;
int after_seconds;

int fwsam_src_or_dst;		// 1 == src,  2 == dst
unsigned long  fwsam_seconds;		

};

typedef struct Sagan_Event 
{

        _SaganDebug *debug;
        _SaganConfig *config;
	_SaganCounters *counters;

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

} SaganEvent;


/* Thresholding structure by source */
typedef struct thresh_by_src thresh_by_src;
struct thresh_by_src { 
unsigned s_size_thresh_by_src;
char ipsrc[64];
int  count;
uint64_t utime;
char sid[512];
};

/* Thresholding structure by destination */
typedef struct thresh_by_dst thresh_by_dst;
struct thresh_by_dst {
unsigned s_size_thresh_by_dst;
char ipdst[64];
int  count;
uint64_t utime;
char sid[512];
};

/* After structure by source */
typedef struct after_by_src after_by_src;
struct after_by_src {
unsigned s_size_afterh_by_src;
char ipsrc[64];
int  count;
uint64_t utime;
char sid[512];
};

/* After structure by destination */
typedef struct after_by_dst after_by_dst;
struct after_by_dst {
unsigned s_size_after_by_dst;
char ipdst[64];
int  count;
uint64_t utime;
char sid[512];
};

/****************************************************************************/
/* MySQL & PostgreSQL support.  Support for Snort databases                 */
/****************************************************************************/

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

#define MAXDBNAME       32
#define MAXSQL          4096
#define MYSQL_PORT      3306

char *sql_escape(_SaganConfig *, const char *, int );
void sagan_db_thread( SaganEvent * );
int  ip2bit( _SaganConfig *, char * );
char *fasthex(char *, int);
int db_connect( _SaganConfig * );
int  get_sensor_id ( _SaganDebug *, _SaganConfig *);
uint64_t get_cid ( _SaganDebug *,  _SaganConfig * );

#endif

#ifdef HAVE_LIBPRELUDE
void PreludeInit( _SaganConfig *);
void sagan_prelude( SaganEvent * );
#endif



#ifdef HAVE_LIBLOGNORM
/* liblognorm struct */
typedef struct liblognorm_struct liblognorm_struct; 
struct liblognorm_struct { 
char type[50];
char filepath[MAXPATH];
};

typedef struct liblognorm_toload_struct liblognorm_toload_struct;
struct liblognorm_toload_struct {
char type[50];
char filepath[MAXPATH];
};
#endif


/****************************************************************************/
/* libesmtp support                                                         */
/****************************************************************************/

#ifdef HAVE_LIBESMTP

#define ESMTPTO         32		/* 'To' buffer size max */
#define ESMTPFROM       32		/* 'From' buffer size max */
#define ESMTPSERVER     32		/* SMTP server size max */
#define MAX_EMAILSIZE   15360		/* Largest e-mail that can be sent */

const char *esmtp_cb (void **, int *, void *);
void sagan_esmtp_thread( SaganEvent * );

#endif

/****************************************************************************/
/* 'Signal' thread options                                                  */
/****************************************************************************/

typedef struct _SaganSigArgs _SaganSigArgs;
	struct _SaganSigArgs {
        int daemonize;
        uint64_t cid;
        _SaganDebug *debug;
        _SaganConfig *config;
        };



/****************************************************************************/
/* The functions below depend on structs above                              */
/****************************************************************************/

#ifdef HAVE_LIBPCAP
void plog_handler( _SaganSigArgs * );
#endif

void sagan_alert( SaganEvent * );
void sagan_ext_thread( SaganEvent * );

void load_config( _SaganDebug *, _SaganConfig * );
void sig_handler( _SaganSigArgs * );
void load_classifications( _SaganDebug *, _SaganConfig *,  const char * );
void load_reference ( _SaganDebug *, _SaganConfig *, const char * );
void load_rules ( _SaganDebug *, _SaganConfig *,  const char * );
void sagan_log( _SaganConfig *,  int, const char *, ... );
void removelockfile ( _SaganConfig * );
void checklockfile ( _SaganConfig * );
void sagan_statistics( _SaganConfig * );
void key_handler( _SaganConfig * );
void sagan_droppriv( _SaganConfig *, const char *);
char *dns_lookup( _SaganConfig *, char *);

void sagan_output( SaganEvent * );
void sagan_processor( SaganEvent * );

void sagan_fwsam( SaganEvent * );
