/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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


char *Format_Sagan_JSON_Alert( _Sagan_Event * );

/* Timestamp is wrong :( */
/* category doesn't line up */

#define JSON_ALERT "{ \"timestamp\": \"%s%s\", \"event_type\": \"alert\", \"src_ip\": \"%s\", \"src_port\": %d, \"dest_ip\": \"%s\", \"dest_port\": %d, \"proto\": \"%s\", \"alert\": { \"action\": \"%s\", \"gid\": %lu, \"signature_id\": %s, \"rev\": %s, \"signature\": \"%s\", \"category\": \"%s\", \"severity\": %d } }"

// { "timestamp": "XXXXXXXX", "event_type": "XXXXX", "src_ip": "XXXXXXXXX", "src_port": XXXX, "dest_ip": "XXXXXXXX", "dest_port": XXXXX, "proto": "XXX", "alert": { "action": "XXXXXX", "gid": X, "signature_id" :XXXXXXX, "rev": X, "signature": "XXXXXXXXXXXX", "category": "XXXXXXXX", "severity": X } }

// { "timestamp": "2009-11-24T21:27:09.534255", "event_type": "alert", "src_ip": "192.168.2.7", "src_port": 1041, "dest_ip": "x.x.250.50", "dest_port": 80, "proto": "TCP", "alert": { "action": "allowed", "gid": 1, "signature_id" :2001999, "rev": 9, "signature": "ET MALWARE BTGrab.com Spyware Downloading Ads", "category": "A Network Trojan was detected", "severity": 1 } }



