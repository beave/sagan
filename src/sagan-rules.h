/*
** Copyright (C) 2009-2014 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2014 Champ Clark III <cclark@quadrantsec.com>
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
    int pcre_count;
    int content_count;
    int meta_content_count;
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

    int flowbit_flag;                   /* 0 == none, 1 == set, 2 == unset, 3 == isset, 4 == isnotset */
    int flowbit_type;                   /* 0 == none, 1 == both, 2 == by_src, 3 == by_dst */


    sbool flowbit_noalert;
    int   flowbit_memory_position;
    int   flowbit_timeout;                      /* How long a flowbit is to stay alive (seconds) */

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

#ifdef HAVE_LIBGEOIP

    sbool geoip_flag;
    int   geoip_type;           /* 1 == isnot, 2 == is */
    char  geoip_country_codes[1024];
    int   geoip_src_or_dst;             /* 1 == src, 2 == dst */

#endif

};


void Load_Rules ( const char * );
