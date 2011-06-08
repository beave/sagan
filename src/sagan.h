/* $Id$ */
/*
** Copyright (C) 2009-2011 Softwink, Inc. 
** Copyright (C) 2009-2011 Champ Clark III <champ@softwink.com>
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

#include <stdint.h> 
#include <pcre.h>
#include <time.h>

/* Various buffers used during configurations loading */

#define CLASSBUF	1024
#define RULEBUF		5128
#define CONFBUF		1024

#define MAXPATH 	255		/* Max path for files/directories */
#define MAXHOST         32		/* Max host length */
#define MAXPROGRAM	32		/* Max syslog 'program' length */
#define MAXDATE		25		/* Max syslog 'date' length */
#define MAXTIME		10		/* Max syslog 'time length */
#define MAXFACILITY	25		/* Max syslog 'facility' length */
#define MAXPRIORITY	20		/* Max syslog 'priority' length */
#define MAXTAG		32		/* Max syslog 'tag' length */
#define MAXLEVEL	15		/* Max syslog 'level' length */

/* Used for the syslog "msgslot" array.  This can be increased,  but 
 * anything > || == 30 causes SEGFAULTs under FreeBSD 
 * Champ Clark - 02/28/2010
 */

#define MAX_MSGSLOT	25		/* Slots for syslog message passing */

#define MAX_THREADS     4096            /* Max system threads */
#define MAX_SYSLOGMSG   63556		/* Max length of a syslog message */

#define MAX_PCRE	5		/* Max PCRE within a rule */
#define MAX_CONTENT	5		/* Max 'content' within a rule */
#define MAX_REFERENCE	10		/* Max references within a rule */

#define MAXUSER         32
#define	MAXPASS		64

#define BUFLEN 		8192		/* For libesmtp */
#define MAXIP		16		/* Max IP length.  Change to 64 for future IPv6 support */

#define LOCKFILE 	"/var/run/sagan/sagan.pid"
#define SAGANLOG	"/var/log/sagan/sagan.log"
#define ALERTLOG	"/var/log/sagan/alert"
#define SAGANLOGPATH	"/var/log/sagan"

#define RUNAS		"sagan"


typedef char sbool;	/* From rsyslog. 'bool' causes compatiablity problems on OSX. "(small bool) I intentionally use char, to keep it slim so that many fit into the CPU cache!".  */


/* defaults if the user doesn't define */

#define MAX_EXT_THREADS         50

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
#define MAX_LOGZILLA_THREADS	50
#define MAX_DB_THREADS          50
#endif

#ifdef HAVE_LIBESMTP
#define MAX_EMAIL_THREADS	50
#endif 

#ifdef HAVE_LIBPRELUDE
#define MAX_PRELUDE_THREADS	50
#endif

#ifndef HAVE_STRLCPY
int strlcpy(char *, const char *,  size_t );
#endif

#ifndef HAVE_STRLCAT
int strlcat(char *, const char *, size_t );
#endif

/* Parsers */

char *parse_ip_simple( char * );
int   parse_port_simple( char * );

void sig_handler( int );
void sig_handler_daemon( int );
void key_handler( int );
void plog_handler( void );


char *dns_lookup(char *);
int isnumeric (char *);
char *toupperc(char* const );
void sagan_statistics( void );
void sagan_error(const char *, ...);
void sagan_log( int, const char *, ... );
char *gettimestamp( void );
void sagan_error( const char *, ... );
char *findipinmsg ( char * );
void closesagan( int );
int  checkendian( void );
void sagan_usage( void );
void load_config( void );
void load_normalize( void );
void removelockfile ( void );
void checklockfile ( void );
void sagan_droppriv( const char * , const char *);
void sagan_chroot( const char *, const char * );
char *remrt(char *);
char *remspaces(char *);
char *remquotes(char *);
void load_classifications( void );
void load_reference ( void );
void load_rules ( void );
char *betweenquotes( char * );
char *reflookup( int, int );
double CalcPct(uint64_t, uint64_t);

char *referencelookup( int );

typedef struct _SaganCounters _SaganCounters;
struct _SaganCounters { 

    uint64_t threshold_total;
    uint64_t sagantotal;
    uint64_t saganfound;
    uint64_t sagandrop;

    uint64_t threadmaxextc;
    uint64_t saganexternaldrop;

    int      threadextc;

    int	     classcount;
    int      rulecount;
    int	     refcount;
    int      ruletotal;

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
    uint64_t sigcid;            /* For passing CID with signal */
    uint64_t threadmaxdbc;
    uint64_t threadmaxlogzillac;
    int      threadlogzillac;
    int	     threaddbc;

    uint64_t sagansnortdrop;
    uint64_t saganlogzilladrop;
#endif

#ifdef HAVE_LIBESMTP
    int      threademailc;
    uint64_t saganesmtpdrop;
    uint64_t threadmaxemailc;
#endif

#ifdef HAVE_LIBPRELUDE
    int      threadpreludec;
    uint64_t threadmaxpreludec;
    uint64_t saganpreludedrop;
#endif

#ifdef HAVE_LIBLOGNORM
    int liblognormtoload_count;
#endif

};   

typedef struct _SaganDebug _SaganDebug;
struct _SaganDebug { 

    sbool debugsyslog;
    sbool debugload;

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
    uint64_t	 max_external_threads;
    int		 sagan_port;
    int		 sagan_exttype;
    sbool	 sagan_ext_flag;
    sbool        disable_dns_warnings;
    int		 daemonize;
    int          sagan_proto;


/* libesmtp/SMTP support */
    
#ifdef HAVE_LIBESMTP
    uint64_t	max_email_threads;
    int		min_email_priority;
    char	sagan_esmtp_to[255];
    sbool	sagan_sendto_flag;
    char	sagan_esmtp_from[255];
    char	sagan_esmtp_server[255];
    sbool	sagan_esmtp_flag;
#endif

/* Prelude framework support */

#ifdef HAVE_LIBPRELUDE
    uint64_t 	max_prelude_threads;
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

/* MySQL/PostgreSQL support for Snort/Logzilla */

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
    int		 dbtype;
    int		 logzilla_dbtype;
    int          sagan_detail;
    int		 sensor_id;
    uint64_t	 maxdb_threads;
    uint64_t	 max_logzilla_threads;
    char	 sagan_hostname[MAXHOST];
    char	 sagan_filter[50];
    char	 logzilla_user[MAXUSER];
    char	 logzilla_password[MAXPASS];
    char	 logzilla_dbname[50];
    char	 logzilla_dbhost[50];	
    char         dbuser[MAXUSER];
    char         dbpassword[MAXPASS];
    char         dbname[50]; 
    char         dbhost[50];
#endif

};

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

};

typedef struct Sagan_Event 
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

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
	uint64_t cid;
#endif

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

/****************************************************************************/
/* MySQL & PostgreSQL support.  Including support for Snort database and    */
/* Logzilla.                                                                */
/****************************************************************************/

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

#define MAXDBNAME       32
#define MAXSQL          4096
#define MYSQL_PORT      3306

char *sql_escape(const char *, int );
void *logzilla_insert_thread ( void *);
void sagan_logzilla_thread(SaganEvent *);
void sagan_db_thread( SaganEvent * );
int  ip2bit( char *, int );
char *fasthex(char *, int);

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

struct sig_thread_args {
        int daemonize;
        uint64_t cid;
        } sig_thread_args[1];

struct sig_args {
        int daemonize;
        uint64_t cid;
        } sig_args[1];

void sagan_alert( SaganEvent * );
void sagan_ext_thread( SaganEvent * );

/*
#ifdef HAVE_LIBPRELUDE
void sagan_prelude( SaganEvent * );
#endif
*/

/*
#ifdef HAVE_LIBDNET
typedef struct _Unified2Config
{
    char *base_filename;
    char filepath[1024];
    uint32_t timestamp;
    FILE *stream;
    unsigned int limit;
    unsigned int current;
    int nostamp;
    int base_proto;
} Unified2Config;
#endif
*/
