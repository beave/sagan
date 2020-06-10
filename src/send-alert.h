/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
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

#include "sagan-defs.h"

void Send_Alert ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, char *json_normalize,  _Sagan_Processor_Info *processor_info, char *ip_src, char *ip_dst, char *normalize_http_uri, char *normalize_http_hostname, int proto, uint64_t sid, int src_port, int dst_port, int pos, struct timeval tp, char *bluedot_json, unsigned char bluedot_results );

