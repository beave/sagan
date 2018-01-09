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

/* sagan-json.h
 *
 * Functions that handle JSON output
 *
 */

#include <inttypes.h>

void Format_JSON_Alert_EVE( _Sagan_Event *, char *, size_t);

/* Suricata EVE Alert output */

#define EVE_ALERT "{\"timestamp\":\"\%s\",\"flow_id\":%" PRIu64 ",\"in_iface\":\"%s\",\"event_type\":\"alert\",\"src_ip\":\"%s\",\"src_port\":%d,\"dest_ip\":\"%s\",\"dest_port\":%d,\"proto\":\"%s\",\"alert\":{\"action\":\"%s\",\"gid\":%lu,\"signature_id\":%s,\"rev\":%s,\"signature\":\"%s\",\"category\":\"%s\",\"severity\":%d},\"payload\":\"%s\",\"stream\":0,\"packet\":\"%s\",\"packet_info\":{\"linktype\":1},\"normalize\":%s}"


