/* $Id$ */
/*
** Copyright (C) 2009-2010 Softwink, Inc. 
** Copyright (C) 2009-2010 Champ Clark III <champ@softwink.com>
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
#define MAXTAG		10		/* Max syslog 'tag' length */
#define MAXLEVEL	15		/* Max syslog 'level' length */

#define MAX_MSGSLOT	100		/* Slots for syslog message passing */
#define MAX_THREADS     4096            /* Max system threads */
#define MAX_SYSLOGMSG   10240		/* Max length of a syslog message */

#define MAX_PCRE	5		/* Max PCRE within a rule */
#define MAX_CONTENT	5		/* Max 'content' within a rule */
#define MAX_REFERENCE	10		/* Max references within a rule */

#define BUFLEN 		8192		/* For libesmtp */
#define MAXIP		16		/* Max IP length.  Change to 64 for future IPv6 support */

#define LOCKFILE 	"/var/run/sagan/sagan.pid"
#define SAGANLOG	"/var/log/sagan/sagan.log"
#define ALERTLOG	"/var/log/sagan/alert"

#define RUNAS		"sagan"


/* defaults if the user doesn't define */

#define MAX_LOGZILLA_THREADS	50
#define MAX_EMAIL_THREADS	50
#define MAX_DB_THREADS		50
#define MAX_EXT_THREADS		50

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

int isnumeric (char *);
char *toupperc(char* const );
void sagan_statistics( void );
void *sagan_ext_thread( void * );
void sagan_error(const char *, ...);
void sagan_log( int, const char *, ... );
char *gettimestamp( void );
void sagan_error( const char *, ... );
char *findipinmsg ( char * );
void closesagan( int );
int  checkendian( void );
void sagan_usage( void );
void load_config( void );
int  logzilla_db_connect( void );
int  db_connect( void );
int  get_sensor_id ( char *,  char *,  char *,  int , int  );
unsigned long long get_cid ( int , int );
void removelockfile ( void );
void checklockfile ( void );
void droppriv( const char * );
char *remrt(char *);
char *remspaces(char *);
char *remquotes(char *);
void load_classifications( void );
void load_reference ( void );
void load_rules ( void );
char *betweenquotes( char * );
char *reflookup( int, int );

char *referencelookup( int );


void *sagan_alert ( char *,  char *, 
                    char *,  int, 
                    char *,  char *, 
                    char *,  char *, 
                    char *,  char *, 
                    int   ,  int, 
		    char *,  int );  


#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
void record_last_cid ( void );

int  get_sig_sid( char *,  char *, 
                  char *,  char *, 
                  int         ,  int  );


void insert_event (int, unsigned long long, int, int, char *, char * );

void insert_hdr (int , unsigned long long , 
                 char *,  char *, 
		 int, int, int, int, int);

void insert_payload ( int,  unsigned long long, char *,  int );

void query_reference ( char *, char *, int, int );
#endif

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
char s_pcre[MAX_PCRE][1024];
int  s_pcreoptions[MAX_PCRE];
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
int s_nocase;
int pcre_count;
int content_count;
int ref_count;
int dst_port;
int ip_proto;
int s_find_port;
int s_find_ip; 

int threshold_type;		// 1 = limit,  2 = thresh,
int threshold_src_or_dst;	// 1 ==  src,  2 == dst
int threshold_count;		
int threshold_seconds;

};

/* Thresholding structure by source */
typedef struct thresh_by_src thresh_by_src;
struct thresh_by_src { 
unsigned s_size_thresh_by_src;
char ipsrc[64];
int  count;
unsigned long long utime;
char sid[512];
};

/* Thresholding structure by destination */
typedef struct thresh_by_dst thresh_by_dst;
struct thresh_by_dst {
unsigned s_size_thresh_by_dst;
char ipdst[64];
int  count;
unsigned long long utime;
char sid[512];
};

/****************************************************************************/
/* MySQL & PostgreSQL support.  Including support for Snort database and    */
/* Logzilla.                                                                */
/****************************************************************************/

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)

#define MAXUSER         32
#define MAXPASS         32
#define MAXDBNAME       32
#define MAXSQL  	4096
#define MYSQL_PORT      3306

struct db_args { 
        char *ip_src;
	char *ip_dst;
        int  found; 
        int  pri;
        char *message;
        unsigned long long cid;
	int endian;
	int dst_port;
	int src_port;
        char *date;
	char *time;
        }; 

struct db_info {
        int  dbtype;
        char *username;
        char *password;
        char *name;
        char *host;
        };

struct db_thread_args { 
        char *ip_src;
	char *ip_dst;
        int  found;
        int  pri;
	char *message;
	unsigned long long cid;
	int endian;
	int dst_port;
	int src_port;
 	char *date;
	char *time;
        };

struct logzilla_thread_args {
        char *host;
        char *facility;
        char *priority;
        char *level;
        char *tag;
        char *date;
        char *time;
        char *program;
        char *msg;
        };

char *sql_escape(const char *, int );
void *logzilla_insert_thread ( void *);
void *sagan_db_thread(void *);
void *sagan_logzilla_thread(void *);
char *ip2bit( char *, int );
char *fasthex(char *, int);

#endif

/****************************************************************************/
/* External thread structures.   This is used when calling 'external'       */
/* prgrams                                                                  */
/****************************************************************************/

struct ext_thread_args { 
        char *sid;
        char *msg;
        char *classtype;
        int   pri;
        char *date;
        char *time;
        char *ip_src;
        char *ip_dst;
        char *facility;
        char *fpri;
        char *sysmsg;
        int  dst_port;
        int  src_port;
	int  rulemem;
        };

/****************************************************************************/
/* libesmtp support                                                         */
/****************************************************************************/

#ifdef HAVE_LIBESMTP
struct email_thread_args {
        char *sid;
        char *msg;
        char *classtype;
        int   pri;
        char *date;
        char *time;
        char *ip_src;
        char *ip_dst;
        char *facility;
        char *fpri;
        char *sysmsg;
        int  dst_port;
        int  src_port;
	int  rulemem;
        };

#define ESMTPTO         32		/* 'To' buffer size max */
#define ESMTPFROM       32		/* 'From' buffer size max */
#define ESMTPSERVER     32		/* SMTP server size max */
#define MAX_EMAILSIZE   15360		/* Largest e-mail that can be sent */

const char *esmtp_cb (void **, int *, void *);
void *sagan_esmtp_thread( void *);

#endif

/****************************************************************************/
/* 'Signal' thread options                                                  */
/****************************************************************************/

struct sig_thread_args {
        int daemonize;
        unsigned long long cid;
        } sig_thread_args[1];

struct sig_args {
        int daemonize;
        unsigned long long cid;
        } sig_args[1];

