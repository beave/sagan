/*
** Copyright (C) 2009-2011 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2011 Champ Clark III <cclark@quadrantsec.com>
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
#include "config.h"
#endif

/* sagan-unified2.h  */

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

#include <stdint.h>
#include <stdio.h>



#define UNIFIED2_PACKET              2
#define UNIFIED2_IDS_EVENT           7

#define SAGAN_SNPRINTF_ERROR -1
#define SAGAN_SNPRINTF_TRUNCATION 1
#define SAGAN_SNPRINTF_SUCCESS 0
#define SAFEMEM_SUCCESS 1
#define IP_MAXPACKET    65535        /* maximum packet size */

#define SAFEMEM_ERROR 0
#define SAFEMEM_SUCCESS 1

#define ERRORRET return SAFEMEM_ERROR;

void Sagan_Unified2( _SaganEvent * );
void Sagan_Unified2LogPacketAlert( _SaganEvent * );
void Unified2InitFile( _SaganConfig * );
int SaganSnprintf(char *buf, size_t buf_size, const char *format, ...);
void *SaganAlloc( _SaganConfig *, unsigned long);

void Unified2CleanExit( _SaganConfig * ); 

/* Data structure used for serialization of Unified2 Records */
typedef struct _Serial_Unified2_Header
{
    uint32_t   type;
    uint32_t   length;
} Serial_Unified2_Header;

//UNIFIED2_PACKET = type 2

typedef struct _Serial_Unified2Packet
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t packet_second;
    uint32_t packet_microsecond;
    uint32_t linktype;
    uint32_t packet_length;
    uint8_t packet_data[4];
} Serial_Unified2Packet;

//---------------LEGACY, type '7'
//These structures are not used anymore in the product

typedef struct _Serial_Unified2IDSEvent_legacy
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;//sets packet_action
    uint8_t  impact;
    uint8_t  blocked;
} Serial_Unified2IDSEvent_legacy;

/* Not used 'yet'.  - Champ Clark III - 02/14/2011 */

/*
typedef struct _Serial_Unified2IDSEventIPv6_legacy
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  impact_flag;
    uint8_t  impact;
    uint8_t  blocked;
} Serial_Unified2IDSEventIPv6_legacy;
*/

/* The below is from packet.h from Snort */ 

struct sf_timeval32
{
    uint32_t tv_sec;      /* seconds */
    uint32_t tv_usec;     /* microseconds */
};

typedef struct _Event
{
    uint32_t sig_generator;   /* which part of snort generated the alert? */
    uint32_t sig_id;          /* sig id for this generator */
    uint32_t sig_rev;         /* sig revision for this id */
    uint32_t classification;  /* event classification */
    uint32_t priority;        /* event priority */
    uint32_t event_id;        /* event ID */
    uint32_t event_reference; /* reference to other events that have gone off,
                                * such as in the case of tagged packets...
                                */
    struct sf_timeval32 ref_time;   /* reference time for the event reference */

} Event;


#endif



