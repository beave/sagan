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

#ifdef WITH_BLUEDOT
#define BLUEDOT_MAX_CAT        10
#endif

typedef struct _Rules_Loaded _Rules_Loaded;
struct _Rules_Loaded
{
    char ruleset[MAXPATH];
};

typedef struct arr_flow_1 arr_flow_1;
struct arr_flow_1
{
    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;
};

typedef struct arr_flow_2 arr_flow_2;
struct arr_flow_2
{
    struct
    {
        unsigned char ipbits[MAXIPBIT];
        unsigned char maskbits[MAXIPBIT];
    } range;
};

typedef struct arr_port_1 arr_port_1;
struct arr_port_1
{
    int lo;
    int hi;
};

typedef struct arr_port_2 arr_port_2;
struct arr_port_2
{
    int lo;
    int hi;
};

typedef struct meta_content_conversion meta_content_conversion;
struct meta_content_conversion
{
    char meta_content_converted[MAX_META_CONTENT][256];
    int  meta_counter;
};

typedef struct _Rule_Struct _Rule_Struct;
struct _Rule_Struct
{
    unsigned s_size_rule;
    char s_msg[MAX_SAGAN_MSG];

    pcre *re_pcre[MAX_PCRE];
    pcre_extra *pcre_extra[MAX_PCRE];

    char s_content[MAX_CONTENT][256];
    char s_reference[MAX_REFERENCE][256];
    char s_classtype[32];
    char s_sid[32];
    char s_rev[5];
    int  s_pri;
    char s_program[256];
    char s_facility[50];
    char s_syspri[25];
    char s_level[25];
    char s_tag[10];

    char email[255];
    sbool email_flag;

    sbool type;				/* 0 == normal,  1 == dynamic */
    char  dynamic_ruleset[MAXPATH];

    /* Check Flow */
    struct arr_flow_1 flow_1[MAX_CHECK_FLOWS];
    struct arr_flow_2 flow_2[MAX_CHECK_FLOWS];

    struct arr_port_1 port_1[MAX_CHECK_FLOWS];
    struct arr_port_2 port_2[MAX_CHECK_FLOWS];

    struct meta_content_conversion meta_content_containers[MAX_META_CONTENT];

    int direction;

    sbool flow_1_var;
    sbool flow_2_var;
    sbool port_1_var;
    sbool port_2_var;

    sbool has_flow;

    int flow_1_type[MAX_CHECK_FLOWS];
    int flow_2_type[MAX_CHECK_FLOWS];
    int flow_1_counter;
    int flow_2_counter;

    int port_1_type[MAX_CHECK_FLOWS];
    int port_2_type[MAX_CHECK_FLOWS];
    int port_1_counter;
    int port_2_counter;

    sbool s_nocase[MAX_CONTENT];
    int s_offset[MAX_CONTENT];
    int s_depth[MAX_CONTENT];
    int s_distance[MAX_CONTENT];
    int s_within[MAX_CONTENT];

    sbool meta_nocase[MAX_META_CONTENT];
    int meta_offset[MAX_META_CONTENT];
    int meta_depth[MAX_META_CONTENT];
    int meta_distance[MAX_META_CONTENT];
    int meta_within[MAX_META_CONTENT];

    unsigned char pcre_count;
    unsigned char content_count;
    unsigned char meta_content_count;
    unsigned char meta_content_converted_count;

    int xbit_count;				/* Number of xbits in memory */
    unsigned char xbit_condition_count;		/* Number of isset/isnot within a rule */
    unsigned char xbit_set_count;		/* Number of set/unset within a rule */
    unsigned char xbit_count_count;		/* Number of count within a rule */

    sbool xbit_flag;              	        /* Does the rule contain a xbit? */
    sbool xbit_noalert;                         /* Do we want to suppress "alerts" from xbits in ALL output plugins? */
    sbool xbit_nounified2;                      /* Do we want to suppress "unified2" from xbits in unified2 output */

    unsigned char xbit_type[MAX_XBITS];         /* 1 == set, 2 == unset, 3 == isset, 4 == isnotset, 5 == set_srcport,
						   6 == set_dstport, 7 == set_ports, 8 == count */

    unsigned char xbit_direction[MAX_XBITS];    /* 0 == none, 1 == both, 2 == by_src, 3 == by_dst */
    int xbit_timeout[MAX_XBITS];                /* How long a xbit is to stay alive (seconds) */
    char xbit_name[MAX_XBITS][64];              /* Name of the xbit */

    unsigned char xbit_count_gt_lt[MAX_XBITS];  	/* 0 == Greater, 1 == Less than, 2 == Equals. */
    int xbit_count_counter[MAX_XBITS];        /* The amount the user is looking for */
    sbool xbit_count_flag;

    int ref_count;
    int ip_proto;                               /*protocol to match against events*/

    int default_dst_port;                       /*default dst port to set*/
    int default_src_port;                       /*default src port to set*/
    int default_proto;                          /*default protocol to set*/

    sbool s_find_port;
    sbool s_find_proto;
    sbool s_find_proto_program;

    sbool s_find_src_ip;
    int   s_find_src_pos;

    sbool s_find_dst_ip;
    int   s_find_dst_pos;

    int   s_find_hash_type;

    sbool normalize;
    sbool content_not[MAX_CONTENT];             /* content: ! "something" */

    int drop;                                   /* inline DROP for ext. */

    unsigned char threshold_type;               /* 1 = limit,  2 = thresh */
    unsigned char threshold_method;             /* 1 ==  src,  2 == dst,  3 == username, 4 == srcport, 5 == dstport */
    int threshold_count;
    int threshold_seconds;

    unsigned char after_method;                 /* 1 ==  src,  2 == dst, 3 == username, 4 == dstport */
    int after_count;
    int after_seconds;

    unsigned char fwsam_src_or_dst;             /* 1 == src,  2 == dst */
    unsigned long fwsam_seconds;

    sbool meta_content_flag;
    sbool meta_content_case[MAX_META_CONTENT];
    sbool meta_content_not[MAX_META_CONTENT];

    char meta_content[MAX_META_CONTENT][CONFBUF];
    char meta_content_help[MAX_META_CONTENT][CONFBUF];

    sbool alert_time_flag;
    unsigned char alert_days;
    sbool aetas_next_day;

    int	 aetas_start;
    int  aetas_end;

    int  alert_end_hour;
    int  alert_end_minute;

    sbool external_flag;
    char  external_program[MAXPATH];

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
    sbool blacklist_ipaddr_all;

#ifdef WITH_BLUEDOT

    unsigned char   bluedot_ipaddr_type;                 /* 1 == src,  2 == dst,  3 == both,  4 == all */

    int   bluedot_ip_cats[BLUEDOT_MAX_CAT];
    int   bluedot_ip_cat_count;

    uintmax_t bluedot_mdate_effective_period;
    uintmax_t bluedot_cdate_effective_period;

    int   bluedot_hash_cats[BLUEDOT_MAX_CAT];
    int   bluedot_hash_cat_count;

    int   bluedot_url_cats[BLUEDOT_MAX_CAT];
    int   bluedot_url_cat_count;

    int   bluedot_filename_cats[BLUEDOT_MAX_CAT];
    int   bluedot_filename_cat_count;

    sbool bluedot_file_hash;
    sbool bluedot_url;
    sbool bluedot_filename;

#endif


#ifdef HAVE_LIBMAXMINDDB

    sbool geoip2_flag;
    unsigned char geoip2_type;           /* 1 == isnot, 2 == is */
    char  geoip2_country_codes[256];
    unsigned char geoip2_src_or_dst;             /* 1 == src, 2 == dst */

#endif

};

void Load_Rules ( const char * );
