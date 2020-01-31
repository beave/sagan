/* $Id$ */
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

void Xbit_Set_Redis(int rule_position, char *ip_src_char, char *ip_dst_char, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL );
bool Xbit_Condition_Redis(int rule_position, char *ip_src_char, char *ip_dst_char);
void Xbit_Return_Tracking_IP ( int rule_position, int xbit_position, char *ip_src_char, char *ip_dst_char, char *str, size_t size );
