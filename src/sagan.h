/* $Id$ */
/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
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

int    Is_Numeric (char *);
char   *To_UpperC(char* const );
int	Check_Endian( void ); 
void    Usage( void );
void    Chroot( const char *, const char * );
char   *Remove_Return(char *);
char   *Remove_Spaces(char *);
char   *Between_Quotes( char * );
char   *Reference_Lookup( int, int );
double CalcPct(uint64_t, uint64_t);
char   *Replace_String(char *, char *, char *);
char   *Get_Filename(char *);

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
    uint64_t fwsam_count;
    uint64_t ignore_count;
    uint64_t blacklist_count;

    uint64_t track_clients_client_count;                /* sagan-track-clients processor */
    uint64_t track_clients_down; 

    uint64_t blacklist_hit_count;
    uint64_t search_nocase_hit_count;
    uint64_t search_case_hit_count;

    int	     thread_output_counter; 
    int	     thread_processor_counter;

    int      var_count; 

    int	     classcount;
    int      rulecount;
    int	     refcount;
    int      ruletotal;

    int      genmapcount;

    int	     droplist_count;
    int	     search_nocase_count;
    int	     search_case_count;

#ifdef HAVE_LIBLOGNORM
    int liblognormtoload_count;
#endif

#ifdef WITH_WEBSENSE
    uint64_t websense_cache_count;			/* Websense cache processor */
    uint64_t websense_cache_hit;			/* Websense hit's from Cache */
    uint64_t websense_postive_hit;
    uint64_t websense_ignore_hit;			/* Ignores from our ignore list */
    uint64_t websense_total; 
    int websense_ignore_list_count;			
#endif

#ifdef HAVE_LIBESMTP
    uint64_t esmtp_count_success;
    uint64_t esmtp_count_failed;
#endif

};   

typedef struct _SaganDebug _SaganDebug;
struct _SaganDebug { 

    sbool debugsyslog;
    sbool debugload;
    sbool debugfwsam;
    sbool debugexternal;
    sbool debugthreads; 

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
    sbool	 sagan_fifo_flag;			/* FIFO or FILE */
    char	 sagan_log_path[MAXPATH];
    char 	 sagan_rule_path[MAXPATH];
    char         sagan_host[MAXHOST];
    char         sagan_extern[MAXPATH];
    char	 sagan_startutime[20]; 			/* Records utime at startup */

    char	 sagan_droplistfile[MAXPATH];		/* Log lines to "ignore" */
    sbool	 sagan_droplist_flag; 
    
//    uint64_t     max_output_threads;
    sbool	 output_thread_flag;

    int 	 max_processor_threads;

    sbool	 sagan_external_output_flag;		/* For things like external, email, fwsam */

    int		 sagan_port;
    int		 sagan_exttype;
    sbool	 sagan_ext_flag;
    sbool        disable_dns_warnings;
    sbool	 syslog_src_lookup;
    int		 daemonize;
    int          sagan_proto;

    sbool	 home_any;			/* 0 == no, 1 == yes */
    sbool	 external_any;		

    sbool	 endian;

/* Processors */

    int         pp_sagan_track_clients;
    sbool	sagan_track_clients_flag; 

    sbool       blacklist_flag;
    char	blacklist_file[MAXPATH];
    int		blacklist_parse_depth;

    sbool	search_nocase_flag;
    char	search_nocase_file[MAXPATH];
    int		search_nocase_parse_depth;

    sbool       search_case_flag;
    char        search_case_file[MAXPATH];
    int         search_case_parse_depth;

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

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
    char         unified2_filepath[MAXPATH];
    uint32_t     unified2_timestamp;
    FILE         *unified2_stream;
    unsigned int unified2_limit;
    unsigned int unified2_current;
    int          unified2_nostamp;
    sbool	 sagan_unified2_flag;
#endif

/* Websense Threatseeker */

#ifdef WITH_WEBSENSE
    sbool	 websense_flag;
    char	 websense_url[256]; 
    char	 websense_auth[64];
    char	 websense_ignore_list[64];
    int		 websense_parse_depth; 
    int		 websense_timeout;
    uint64_t	 websense_max_cache;
    uint64_t	 websense_last_time;			/* For cache cleaning */
#endif

    sbool        sagan_fwsam_flag;
    char 	 sagan_fwsam_info[1024];

};


/* Reference structure */
typedef struct _Ref_Struct _Ref_Struct;
struct _Ref_Struct {
unsigned s_size_ref;
char s_refid[512];
char s_refurl[2048];
};

/* Classification strucure */
typedef struct _Class_Struct _Class_Struct;
struct _Class_Struct {
unsigned s_size_class;
char s_shortname[512];
char s_desc[512];
int  s_priority;
};

/* Rule structure */
typedef struct _Rule_Struct _Rule_Struct;
struct _Rule_Struct {
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
int src_port;
int ip_proto;
sbool s_find_port;
sbool s_find_proto;

sbool s_find_src_ip; 
int   s_find_src_pos; 

sbool s_find_dst_ip;
int   s_find_dst_pos;


sbool normalize;
sbool content_not[MAX_CONTENT];	/* content: ! "something" */

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

/* Storage for sagan-gen-msg.map */

typedef struct _Sagan_Processor_Generator _Sagan_Processor_Generator;
struct _Sagan_Processor_Generator {
unsigned long generatorid;
unsigned long alertid;
char generator_msg[512];
};

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
void sagan_esmtp_thread( _SaganEvent * );

#endif

/****************************************************************************/
/* 'Signal' thread options                                                  */
/****************************************************************************/

typedef struct _SaganSigArgs _SaganSigArgs;
struct _SaganSigArgs {
        int daemonize;
        uint64_t cid;
        };

/****************************************************************************/
/* The functions below depend on structs above                              */
/****************************************************************************/

#ifdef HAVE_LIBPCAP
void plog_handler( _SaganSigArgs * );
#endif

typedef struct _SaganVar _SaganVar;
struct _SaganVar {
     char var_name[64];
     char var_value[64];
};
typedef struct _SaganHomeNet _SaganHomeNet;
struct _SaganHomeNet {
     char network[130];
};

typedef struct _Sagan_Droplist _Sagan_Droplist;
	struct _Sagan_Droplist {
	char ignore_string[256]; 
};

typedef struct _Sagan_Processor_Info _Sagan_Processor_Info;
struct _Sagan_Processor_Info {

	char *processor_name;
	char *processor_facility; 
	char *processor_priority;	/* Syslog priority */
	int   processor_pri;		/* Sagan priority */
	char *processor_class;
	char *processor_tag; 
	char *processor_rev;
	int   processor_generator_id;
};


void Sagan_Alert( _SaganEvent * );
void sagan_ext_thread( _SaganEvent * );

void Load_Config( void );
void Sig_Handler( _SaganSigArgs * );
void Load_Classifications( const char * );
void Load_Reference ( const char * );
void Load_Rules ( const char * );
void Sagan_Log( int, const char *, ... );
void Remove_Lock_File ( void );
void checklockfile ( void );
void sagan_statistics( void );
void key_handler( void );
void sagan_droppriv( const char *);
char *DNS_Lookup( char * );
void Sagan_Output( _SaganEvent * );
void Sagan_Processor ( void );
void sagan_fwsam( _SaganEvent * );
char *Sagan_Var_To_Value(char *);
int  Sagan_Blacklist_Load ( void );
int  Sagan_Searchlist_Load ( int ); 
void Load_Gen_Map( const char * );
void Sagan_Alert_File( _SaganEvent * );
void Load_Ignore_List ( void );
char *Sagan_Generator_Lookup( int, int );
void Sagan_Send_Alert ( _SaganProcSyslog *, _Sagan_Processor_Info *, char *, char *, int , int );
int IP2Bit (char *ipaddr );

sbool is_rfc1918 ( char * );

/* Parsers */

char *parse_ip( char *, int );
int   parse_port( char * );
int   parse_proto( char * );


