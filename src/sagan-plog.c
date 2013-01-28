/* 
 - sagan-plog.c is largely based of Marcus J. Ranum (2004) work known as 
   plog.c.  The original source can be located at: 

   http://www.ranum.com/security/computer_security/code/plog.tar

   This code (sagan-plog.c) is redistributed under the same license 
   Marcus J. Ranum specified in his original work.  

   -- From the plog.c source code and applies to sagan-plog.c as well: 

   Marcus J. Ranum, 2004   - All rights reserved

   This software may be used and redistributed free of charge,
   but may not be incorporated into a commercial product or
   offering without the author's permission.

   Plog - promiscuous syslog injector. Listens to a pcap/bpf
   interface, sucks up UDP syslog messages, finds the message
   within the packet, and injects it into /dev/log.

   --

   Permission to implement the plog functionality was obtain by Champ Clark III from Marcus J. Ranum on Jan. 6th, 2011. 

*/

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBPCAP 

#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "sagan.h"

struct _SaganDebug *debug;
struct _SaganConfig *config;

struct my_udphdr {
         u_int16_t uh_sport;           /* source port */
         u_int16_t uh_dport;           /* destination port */
         u_int16_t uh_ulen;            /* udp length */
         u_int16_t uh_sum;             /* udp checksum */
};

static  void  logpkt(u_char *,const struct pcap_pkthdr *,const u_char *);
static  int   wiredevlog( _SaganConfig *);
static  int   outf;


void plog_handler(_SaganSigArgs *args )
{

        pcap_t                  *bp;
        struct  bpf_program     filtr;
	char 			*iface=NULL;
        char                    eb[PCAP_ERRBUF_SIZE];
	char 			filterstr[128];

	iface = config->plog_interface;

	Sagan_Log(0, "");
	Sagan_Log(0, "Initalizing Sagan syslog sniffer thread (PLOG)"); 
	Sagan_Log(0, "Interface: %s", iface); 
	Sagan_Log(0, "UDP port to monitor: %d", config->plog_port);
	Sagan_Log(0, "Log device: %s", config->plog_logdev);
	Sagan_Log(0, "");
	
        if(iface == (char *)0) {
                if((iface = pcap_lookupdev(eb)) == (char *)0)
			Sagan_Log(1, "[%s, line %d] Cannot get device: %s", __FILE__, __LINE__, eb);
        }

        bp = pcap_open_live(iface,4096,0,0,eb);
        if(bp == (pcap_t *)0) 
	  Sagan_Log(1, "[%s, line %d] Cannot open interface %s: %s", __FILE__, __LINE__, iface, eb);

        /* compile and install our filter */

	/* Port is configurable via int config->plog_port */ 

	snprintf(filterstr, sizeof(filterstr), "udp port %d", config->plog_port);

        if(pcap_compile(bp,&filtr,filterstr,1,0))
	  Sagan_Log(1, "[%s, line %d] Cannot compile filter: %s", __FILE__, __LINE__, eb);
        
	if(pcap_setfilter(bp,&filtr))
	  Sagan_Log(1, "[%s, line %d] Cannot install filter in %s: %s", __FILE__, __LINE__, iface, eb);

        /* wireup /dev/log; we can't use openlog() because these are going to be raw inputs */
        if(wiredevlog(config)) {
	  Remove_Lock_File();
	  Sagan_Log(1, "[%s, line %d] Cannot open %s (Syslog not using SOCK_DGRAM?)", __FILE__, __LINE__, config->plog_logdev);
	}
	
        /* endless loop */
	(void)pcap_loop(bp,-1,logpkt, (u_char*)args);
	
        pcap_close(bp);
        exit(0);
}


/* take a raw packet and write it to /dev/log... we are evil! */
static  void
logpkt(u_char *pass_args,const struct pcap_pkthdr *p,const u_char *pkt)
{
        struct  ether_header    *eh;
        struct  ip              *ih;
        struct  my_udphdr       *u;
        int                     off;
        int                     len;
        char                    *l;

        /* crack the ethernet header */
        eh = (struct ether_header *)pkt;
        if(ntohs(eh->ether_type) != ETHERTYPE_IP)
                goto bad;

        /* crack the IP header */
        ih = (struct ip *)(pkt + sizeof(struct ether_header));
        off = ntohs(ih->ip_off);
        len = ntohs(ih->ip_len);

        /* short packet */
        if(len > p->len)
                goto bad;

        /* frags we don't deal with */
        if((off & 0x1fff) != 0)
                goto bad;
       /* weird - we ASKED for UDP */
        if(ih->ip_p != IPPROTO_UDP)
                goto bad;

        /* line the UDP header up */
        u = (struct my_udphdr *)(pkt + sizeof(struct ether_header) + (ih->ip_hl * 4));

        /* WTF? */
        if(ntohs(u->uh_dport) != 514)
                goto bad;

        if(ntohs(u->uh_ulen < 8))
                goto bad;

        /* our log message ought to be just past the UDP header now... */
        l = (char *)u + sizeof(struct udphdr);
        len = ntohs(u->uh_ulen) - sizeof(struct udphdr);

        if(debug->debugplog) {

		int     x;

		/* I can't use Sagan_Log() here,  so we dump to strerr.
		 * have the check the tty (isatty()) before dumping or
		 * strange things happen if detached and threaded 
		 * - Champ Clark III Jan 7th 2011 
		 */


                for(x = 0; x < len; x++) {
			if(isprint(l[x]) && (isatty(1)) )
                                fprintf(stderr,"%c",(int)(l[x]));
                        else
                                fprintf(stderr,"[0x%x]",(int)(l[x]));
                }
                if (isatty(1)) fprintf(stderr,"\n");
       }


        /* send it! */
        if(send(outf,l,len,0) < 0) 
	  Sagan_Log(1, "[%s, line %d] Send error", __FILE__, __LINE__);
        
	return;
bad:
	  Sagan_Log(0, "[%s, line %d] Malformed packet received.", __FILE__, __LINE__);

}

static  int
wiredevlog( _SaganConfig *config )
{
        struct  sockaddr        s;

        s.sa_family = AF_UNIX;
        (void)strncpy(s.sa_data,config->plog_logdev,sizeof(s.sa_data));

	/* Might want to investigate SOCK_STREAM (see syslog-ng) in the future. 
	 * Right now,  the syslog server must use SOCK_DGRAM */ 

        if((outf = socket(AF_UNIX,SOCK_DGRAM,0)) < 0)
                return(TRUE);
        if(connect(outf,&s,sizeof(s)))
                return(TRUE);
        return(FALSE);
}

#endif

