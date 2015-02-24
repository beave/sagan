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


typedef struct _Rule_Struct _Rule_Struct;
struct _Rule_Struct
{
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

    sbool s_nocase[MAX_CONTENT];
    int s_offset[MAX_CONTENT];
    int s_depth[MAX_CONTENT];
    int s_distance[MAX_CONTENT];
    int s_within[MAX_CONTENT];

    int pcre_count;
    int content_count;
    int meta_content_count;
    int flowbit_count;				/* Number of flowbits in memory */

    int flowbit_condition_count;		/* Number of isset/isnot within a rule */
    int flowbit_set_count;			/* Number of set/unset within a rule */

    int ref_count;
    int dst_port;
    int src_port;
    int ip_proto;
    sbool s_find_port;
    sbool s_find_proto;
    sbool s_find_proto_program;

    sbool s_find_src_ip;
    int   s_find_src_pos;

    sbool s_find_dst_ip;
    int   s_find_dst_pos;

    int flowbit_flag;                   	/* Does the rule contain a flowbit? */
    int flowbit_noalert;			/* Do we want to suppress "alerts" from the flowbit? */

    int flowbit_type[MAX_FLOWBITS];		/* 1 == set, 2 == unset,  3 == isset, 4 == isnotset */
    int flowbit_direction[MAX_FLOWBITS];	/* 0 == none, 1 == both, 2 == by_src, 3 == by_dst */
    int flowbit_memory_position[MAX_FLOWBITS];	/* "Where" in the flowbit struct flowbit is */
    int flowbit_timeout[MAX_FLOWBITS];		/* How long a flowbit is to stay alive (seconds) */
    char flowbit_name[MAX_FLOWBITS][64]; 	/* Name of the flowbit */

    sbool normalize;
    sbool content_not[MAX_CONTENT];     /* content: ! "something" */

    int drop;                   /* inline DROP for ext. */

    int threshold_type;         /* 1 = limit,  2 = thresh */
    int threshold_src_or_dst;   /* 1 ==  src,  2 == dst */
    int threshold_count;
    int threshold_seconds;

    int after_src_or_dst;               /* 1 ==  src,  2 == dst */
    int after_count;
    int after_seconds;

    int fwsam_src_or_dst;               /* 1 == src,  2 == dst */
    unsigned long  fwsam_seconds;

    sbool meta_content_flag;
    sbool meta_content_case[MAX_META_CONTENT];
    sbool meta_content_not[MAX_META_CONTENT];
    char meta_content[MAX_META_CONTENT][512];
    char meta_content_help[MAX_META_CONTENT][512];

    sbool alert_time_flag;
    unsigned char alert_days;
    int  alert_start_hour;
    int  alert_start_minute;
    int  alert_end_hour;
    int  alert_end_minute;

    /* Bro Intel */

    sbool brointel_flag;

    sbool brointel_ipaddr_src;
    sbool brointel_ipaddr_dst;
    sbool brointel_ipaddr_both;
    sbool brointel_ipaddr_all;

    sbool brointel_domain;
    sbool brointel_file_hash;
    sbool brointel_url;
    sbool brointel_software;
    sbool brointel_email;
    sbool brointel_user_name;
    sbool brointel_file_name;
    sbool brointel_cert_hash;

    /* Blacklist */

    sbool blacklist_flag;

    sbool blacklist_ipaddr_src;
    sbool blacklist_ipaddr_dst;
    sbool blacklist_ipaddr_both;


#ifdef HAVE_LIBGEOIP

    sbool geoip_flag;
    int   geoip_type;           /* 1 == isnot, 2 == is */
    char  geoip_country_codes[1024];
    int   geoip_src_or_dst;             /* 1 == src, 2 == dst */

#endif

};


void Load_Rules ( const char * );
