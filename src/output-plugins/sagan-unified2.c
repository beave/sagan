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

/* sagan-unified2.c
 *
 * This allows Sagan to output to a Snort's 'unified2' format.  This format
 * can then be read by programs like barnyard2,  etc. 
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_DUMBNET_H
#include <dumbnet.h>
#else
#include <dnet.h>
#endif

#include "sagan.h"
#include "sagan-unified2.h"

sbool endian;

uint64_t unified_event_id;

struct _Rule_Struct *rulestruct;
struct _Class_Struct *classstruct;
struct _SaganCounters *counters;
struct _SaganConfig *config;

static void Unified2Write( _SaganConfig *, uint8_t *, uint32_t);
static int SafeMemcpy(void *, const void *, size_t, const void *, const void *);
static int inBounds(const uint8_t *, const uint8_t *, const uint8_t *);
static void Unified2RotateFile( _SaganConfig * );

/* Future note on IPv6 - This would have been 
 * Serial_Unified2IDSEventIPv6_legacy.  
 * - Champ Clark III - 02/15/2011 
 */

static uint8_t write_pkt_buffer[sizeof(Serial_Unified2_Header) +
                                sizeof(Serial_Unified2IDSEvent_legacy) + IP_MAXPACKET];

#define write_pkt_end (write_pkt_buffer + sizeof(write_pkt_buffer))

char *eth_addr="00:11:22:33:44:55";	/* Bogus ethernet address for ethernet frame */

/*********************************************************/
/* Unified2InitFile - Initializes the file to be openned */
/*********************************************************/

void Unified2InitFile( _SaganConfig *config  )
{

    char filepath[1024];
    char *fname_ptr;

    if (config == NULL) Sagan_Log(1, "[%s, line %d] Could not init Unified2. Config data is null", __FILE__, __LINE__ ); 

    config->unified2_timestamp = (uint32_t)time(NULL);

    if (!config->unified2_nostamp)
    {
        if (SaganSnprintf(filepath, sizeof(filepath), "%s.%u",
                          config->unified2_filepath, config->unified2_timestamp) != SAGAN_SNPRINTF_SUCCESS)
			  Sagan_Log(1, "[%s, line %d] Failed to copy Unified2 file path", __FILE__, __LINE__);
        
	fname_ptr = filepath;
    }
    else
    {
        fname_ptr = config->unified2_filepath;
    }

    if ((config->unified2_stream = fopen(fname_ptr, "wb")) == NULL)
       Sagan_Log(1, "[%s, line %d] Cannot open file %s.", __FILE__, __LINE__, fname_ptr);
}


/****************************************************/
/* Sagan_Unified2 - Write the Unified2 event        */
/****************************************************/

void Sagan_Unified2( _SaganEvent *Event )
{ 


Serial_Unified2_Header hdr;
Serial_Unified2IDSEvent_legacy alertdata;
uint32_t write_len = sizeof(Serial_Unified2_Header) + sizeof(Serial_Unified2IDSEvent_legacy);
int i=0;

memset(&alertdata, 0, sizeof(alertdata));

alertdata.event_id = htonl(unified_event_id);  					// Event ID (increments)
alertdata.event_second = htonl(Event->event_time_sec);				// Time of event;
alertdata.event_microsecond = htonl(0);	                			// Not recording to the microsecond
alertdata.signature_id = htonl(atoi(Event->sid));
alertdata.signature_revision = htonl(atoi(Event->rev));				// Rule Revision

/* Search for the classification type. */

/* There's probably a better way to do this - Champ Clark III - 02/17/2011 */

for(i=0; i < counters->classcount; i++) {
    if (!strcmp(Event->class, classstruct[i].s_shortname)) alertdata.classification_id = htonl(i + 1);
}

alertdata.priority_id = htonl(Event->pri);					//P riority
alertdata.protocol = Event->ip_proto;					// Protocol
alertdata.generator_id = htonl(Event->generatorid); 				// From gen-msg.map

alertdata.ip_source = htonl(IP2Bit(Event->ip_src));
alertdata.ip_destination = htonl(IP2Bit(Event->ip_dst));

alertdata.sport_itype = htons(Event->src_port);
alertdata.dport_icode = htons(Event->dst_port);

/* Rotate if log has gotten to big */

if ((config->unified2_current + write_len) > config->unified2_limit)
     Unified2RotateFile(config);


hdr.length = htonl(sizeof(Serial_Unified2IDSEvent_legacy));
hdr.type = htonl(UNIFIED2_IDS_EVENT);

if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Serial_Unified2_Header),
               write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
   {
      Sagan_Log(0, "Failed to copy Serial_Unified2_Header\n");
      return;
   }

if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header),
               &alertdata, sizeof(Serial_Unified2IDSEvent_legacy),
               write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
  {
      Sagan_Log(0, "Failed to copy Serial_Unified2IDSEvent_legacy\n");
      return;
  }

Unified2Write(config, write_pkt_buffer, write_len);

}

/*****************************************************************************/
/* Sagan_Unified2LogPacketAlert - Create's a raw TCP/UDP/IP/ICMP 'packet'    */
/* This packet is "fake",  as we are taking syslog data and 'building'       */
/* a packet with libdnet.  This fake packet is then fed to the Unified2      */
/* file for reading by Barnyard2, etc.                                       */
/*****************************************************************************/

void Sagan_Unified2LogPacketAlert( _SaganEvent *Event )
{

Serial_Unified2_Header hdr;
Serial_Unified2Packet logheader;
uint32_t pkt_length = 0;
uint32_t i = 0;
uint32_t write_len = sizeof(Serial_Unified2_Header) + sizeof(Serial_Unified2Packet) - 4;

/* Ethernet */

u_char *p_eth, eth_buf[ETH_LEN_MAX];
struct eth_hdr *eth;
int len_eth = 0;
struct addr addr;

/* IP header */

struct ip_hdr *ip;
u_char *p_iphdr, iphdr_buf[IP_LEN_MAX];
int len_iphdr = 0;

/* TCP header */

struct tcp_hdr *tcp;
u_char *p_tcp, tcp_buf[IP_LEN_MAX];

/* UDP header */

struct udp_hdr *udp;
u_char *p_udp, udp_buf[IP_LEN_MAX];  

/* ICMP header */

struct icmp_hdr *icmp;
u_char *p_icmp, icmp_buf[IP_LEN_MAX]; 

/* 'Packet' payload (syslog data) */

u_char packet_buf[IP_LEN_MAX];
uint8_t packet_data[63556];
int p_len = 0;

unsigned int len_payload = strlen(Event->message);		// Our payload 'length' 

/* Build the ethernet frame */

eth = (struct eth_hdr *)eth_buf;
memset(eth, 0, sizeof(*eth));

eth->eth_type = htons(ETH_TYPE_IP);

addr_aton(eth_addr, &addr);
memcpy(&eth->eth_src, &addr.addr_eth, ETH_ADDR_LEN);

addr_aton(eth_addr, &addr);
memcpy(&eth->eth_dst, &addr.addr_eth, ETH_ADDR_LEN);

p_eth = eth_buf + ETH_HDR_LEN;
len_eth = p_eth - eth_buf;

/* Type == UDP */

if ( Event->ip_proto == 17 ) { 
	
	udp = (struct udp_hdr *)udp_buf;
	memset(udp, 0, sizeof(*udp));

	udp->uh_sport = htons(Event->src_port);
	udp->uh_dport = htons(Event->dst_port);

	p_udp = udp_buf + UDP_HDR_LEN;
	p_len = p_udp - udp_buf;
	udp->uh_ulen = htons(p_len + len_payload);
	memcpy(packet_buf, udp_buf, sizeof(packet_buf));
}


/* Type == TCP */

else if ( Event->ip_proto == 6 ) { 

	tcp = (struct tcp_hdr *)tcp_buf;
	memset(tcp, 0, sizeof(*tcp));

	tcp->th_sport = htons(Event->src_port);
	tcp->th_dport = htons(Event->dst_port);

	tcp->th_seq = 0;
	tcp->th_ack = 0;
	tcp->th_off = 5;               
	tcp->th_flags = TH_SYN;   // or TH_FIN, TH_PUSH
	tcp->th_win = TCP_WIN_MAX;
	tcp->th_urp = 0;

	p_tcp = tcp_buf + TCP_HDR_LEN;
	p_len =  p_tcp - tcp_buf;
	memcpy(packet_buf, tcp_buf, sizeof(packet_buf));

}

/* Type == ICMP */

else if ( Event->ip_proto == 1 ) { 

	icmp = (struct icmp_hdr *)icmp_buf;
	memset(icmp, 0, sizeof(*icmp));

	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	p_icmp = icmp_buf + ICMP_HDR_LEN;
	p_len = p_icmp - icmp_buf;
	memcpy(packet_buf, icmp_buf, sizeof(packet_buf));
}


/* We'll always need a IP header,  so build it here */

ip = (struct ip_hdr *)iphdr_buf;
memset(ip, 0, sizeof(*ip));

ip->ip_hl = 5;
ip->ip_v = 4;
ip->ip_tos = 0;
ip->ip_id = 0;
ip->ip_off = 0;
ip->ip_ttl = IP_TTL_MAX;
ip->ip_p = Event->ip_proto;		 		// Protocol
ip->ip_sum = 0;

ip->ip_src = htonl(IP2Bit(Event->ip_src));
ip->ip_dst = htonl(IP2Bit(Event->ip_dst));

p_iphdr = iphdr_buf + IP_HDR_LEN;
len_iphdr = p_iphdr - iphdr_buf;

pkt_length = strlen(Event->message) + p_len + len_iphdr;
ip->ip_len = htons( len_payload + p_len + len_iphdr);  // Don't include eth frame. 
ip_checksum(iphdr_buf, len_iphdr);		       // Valid checksum

pkt_length = len_eth + len_iphdr + p_len + len_payload; 
write_len += pkt_length;

/***************************************************************************/
/* Here we populate the data needed for the Packet portion of the Unified2 */
/* output.                                                                 */
/***************************************************************************/

logheader.sensor_id = 0;
logheader.linktype = htonl(1);				// linktype set to ethernet (don't need tokenring, etc).
logheader.event_id = htonl(unified_event_id);
logheader.event_second = htonl(Event->event_time_sec);	
logheader.packet_second = htonl(Event->event_time_sec);
logheader.packet_microsecond = htonl(0);
logheader.packet_length = htonl(len_eth + len_iphdr + p_len + len_payload);

hdr.length = htonl(sizeof(Serial_Unified2Packet) - 4 + pkt_length);
hdr.type = htonl(UNIFIED2_PACKET);

if (SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Serial_Unified2_Header),
               write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
   {
      Sagan_Log(0, "[%s, line %d] Failed to copy Serial_Unified2_Header.", __FILE__, __LINE__);
      return;
   }

if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header),
               &logheader, sizeof(Serial_Unified2Packet) - 4,
                write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
   {
      Sagan_Log(0, "[%s, line %d] Failed to copy Serial_Unified2Packet.", __FILE__, __LINE__ ); 
      return;
   }

/* packet_data stores our fake 'packet' information.  We now start building
 * the packet for use */

/* Ethernet */
for ( i = 0; i < len_eth; i++ ) packet_data[i] = eth_buf[i];

/* IP header */

for ( i = 0; i < len_iphdr; i++ ) packet_data[i + len_eth] = iphdr_buf[i];

/* UDP/TCP/ICMP header */
for ( i = 0; i < p_len-1; i++ ) packet_data[i + len_eth + len_iphdr] = packet_buf[i]; 

/* Payload ( Syslog message ) */

for ( i = 0; i < len_payload; i++ ) packet_data[i + len_eth + len_iphdr + p_len ] = Event->message[i];

/* Copy it to our Unified2/write_pkt_buffer */

if (SafeMemcpy(write_pkt_buffer + sizeof(Serial_Unified2_Header) +
               sizeof(Serial_Unified2Packet) - 4,
               packet_data, pkt_length,
               write_pkt_buffer, write_pkt_end) != SAFEMEM_SUCCESS)
   {
   Sagan_Log(0, "[%s, line %d] Failed to copy pseudo packet data.", __FILE__, __LINE__);
   return;
   }

      
Unified2Write(config, write_pkt_buffer, write_len);
unified_event_id++;		

}


/*****************************************************************************/
/* The below functions where taken from Sourcefire's "Snort" for direct      */
/* compatibility.                                                            */
/*****************************************************************************/

void Unified2CleanExit( _SaganConfig *config )
{
    if (config != NULL)
    {   
        if (config->unified2_stream != NULL)
            fclose(config->unified2_stream);
        free(config);
    }
}

static void Unified2RotateFile( _SaganConfig *config )
{
    fclose(config->unified2_stream);
    config->unified2_current = 0;
    Unified2InitFile(config);
}


void *SaganAlloc( _SaganConfig *config, unsigned long size)
{
    void *tmp;

    tmp = (void *) calloc(size, sizeof(char));

    if(tmp == NULL)
      Sagan_Log(1, "[%s, line %d] Unable to allocate memory! (%lu requested)", __FILE__, __LINE__, size);

    return tmp;
}

int SaganSnprintf(char *buf, size_t buf_size, const char *format, ...)
{
    va_list ap;
    int ret;

    if (buf == NULL || buf_size <= 0 || format == NULL)
        return SAGAN_SNPRINTF_ERROR;

    /* zero first byte in case an error occurs with
     * vsnprintf, so buffer is null terminated with
     * zero length */

    buf[0] = '\0';
    buf[buf_size - 1] = '\0';

    va_start(ap, format);

    ret = vsnprintf(buf, buf_size, format, ap);

    va_end(ap);

    if (ret < 0)
        return SAGAN_SNPRINTF_ERROR;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size)
    {
        /* result was truncated */
        buf[buf_size - 1] = '\0';
        return SAGAN_SNPRINTF_TRUNCATION;
    }

    return SAGAN_SNPRINTF_SUCCESS;
}


int SafeMemcpy(void *dst, const void *src, size_t n, const void *start, const void *end)
{
    void *tmp;

    if(n < 1)
    {
        ERRORRET;
    }

    if (!dst || !src || !start || !end)
    {
        ERRORRET;
    }

    tmp = ((uint8_t*)dst) + (n-1);
    if (tmp < dst)
    {
        ERRORRET;
    }

    if(!inBounds(start,end, dst) || !inBounds(start,end,tmp))
    {
        ERRORRET;
    }

    memcpy(dst, src, n);

    return SAFEMEM_SUCCESS;
}

int inBounds(const uint8_t *start, const uint8_t *end, const uint8_t *p)
{
    if(p >= start && p < end)
    {
        return 1;
    }

    return 0;
}

static void Unified2Write( _SaganConfig *config, uint8_t *buf, uint32_t buf_len)
{
    size_t fwcount = 0;
    int ffstatus = 0;

    /* Nothing to write or nothing to write to */
    if ((buf == NULL) || (config == NULL) || (config->unified2_stream == NULL))
        return;

    /* Don't use fsync().  It is a total performance killer */
    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, config->unified2_stream)) != 1) ||
        ((ffstatus = fflush(config->unified2_stream)) != 0))
    {
        /* errno is saved just to avoid other intervening calls
         * (e.g. ErrorMessage) potentially reseting it to something else. */
        int error = errno;
        int max_retries = 3;

        /* On iterations other than the first, the only non-zero error will be
         * EINTR or interrupt.  Only iterate a maximum of max_retries times so 
         * there is no chance of infinite looping if for some reason the write
         * is constantly interrupted */
        while ((error != 0) && (max_retries != 0))
        {
            if (config->unified2_nostamp)
            {
	    	Sagan_Log(1, "[%s, line %d] Failed to write Unified2 file (%s): %s", __FILE__, __LINE__, config->unified2_filepath, strerror(error));
            }
            else
            {
	    	Sagan_Log(1, "[%s, line %d] Failed to write to Unified2 file. (%s.%u): %s", __FILE__, __LINE__, config->unified2_filepath, config->unified2_timestamp, strerror(error));
            }

            while ((error == EINTR) && (max_retries != 0))
            {
                max_retries--;

                /* Supposedly an interrupt can only occur before anything
                 * has been written.  Try again */

		 Sagan_Log(0, "[%s, line %d] Got interrupt. Retry write to Unified2.", __FILE__, __LINE__);
                
		if (fwcount != 1)
                {
                    /* fwrite() failed.  Redo fwrite and fflush */
                    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, config->unified2_stream)) == 1) &&
                        ((ffstatus = fflush(config->unified2_stream)) == 0))
                    {
                      Sagan_Log(0, "[%s, line %d] Write to Unified2 file succeeded!", __FILE__, __LINE__);
                      error = 0;
                      break;
                    }
                }
                else if ((ffstatus = fflush(config->unified2_stream)) == 0)
                {
		    Sagan_Log(0, "[%s, line %d] Write to Unified2 file succeeded!", __FILE__, __LINE__);
                    error = 0;
                    break;
                }

                error = errno;
		Sagan_Log(1, "[%s, line %d] Retrying write to Unified2 file failed", __FILE__, __LINE__);
            }

            /* If we've reached the maximum number of interrupt retries,
             * just bail out of the main while loop */
            if (max_retries == 0)
                continue;

            switch (error)
            {
                case 0:
                    break;

                case EIO:
		        Sagan_Log(1, "[%s, line %d] Unified2 file is corrupt", __FILE__, __LINE__);
                    
		    Unified2RotateFile(config);

                    if (config->unified2_nostamp)
                    {
		    Sagan_Log(0, "[%s, line %d] New Unified2 file: %s", __FILE__, __LINE__, config->unified2_filepath);
                    }
                    else
                    {
		    Sagan_Log(0, "[%s, line %d] New Unified2 file: %s.%u", __FILE__, __LINE__, config->unified2_filepath, config->unified2_timestamp);
                    }

                    if (((fwcount = fwrite(buf, (size_t)buf_len, 1, config->unified2_stream)) == 1) &&
                        ((ffstatus = fflush(config->unified2_stream)) == 0))
                    {
		        Sagan_Log(0, "[%s, line %d] Write to Unified2 file succeeded!", __FILE__, __LINE__);
                        error = 0;
                        break;
                    }

                    error = errno;

                    /* Loop again if interrupt */
                    if (error == EINTR)
                        break;

                    /* Write out error message again, then fall through and fatal */
                    if (config->unified2_nostamp)
                    {
		    	Sagan_Log(1, "[%s, line %d] Failed to write to Unified2 file", __FILE__, __LINE__);
                    }
                    else
                    {
		    	Sagan_Log(1, "[%s, line %d] Failed to write to Unified2 file", __FILE__, __LINE__);
                    }                    /* Fall through */

                case EAGAIN:  /* We're not in non-blocking mode */
                case EBADF:
                case EFAULT:
                case EFBIG:
                case EINVAL:
                case ENOSPC:
                case EPIPE:
                default:
		    Sagan_Log(1, "[%s, line %d] Cannot write to device", __FILE__, __LINE__);
            }
        }

        if ((max_retries == 0) && (error != 0)) Sagan_Log(1, "[%s, line %d] Maximum number of interrupts exceeded.", __FILE__, __LINE__);
    }
    config->unified2_current += buf_len;
}

#endif
