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

/* sagan-snortsam.c
 *
 * This allows Sagan to send block information to firewall via Snortsam.  For
 * more information,  see http://www.snortsam.net
 *
 * This is useful it you want to block an event network wide.  Cool stuff! 
 *
 * The majority of the code was taken from the samtool.c which is distributed
 * with Snortsam.
 *
 */

/*
 * Original Snortsam copyright information:
 *
 * Copyright (c) 2001-2009 Frank Knobbe <frank@knobbe.us>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * This is the remote module that listens for snort alerts generated with the 
 * Alert_FWsam plug-in. This module provides secure gateway functionality between 
 * the snort alerts and various firewalls. It listens to the snort alerts, and can
 * invoke a block on following firewalls:
 *  - Checkpoint Firewall-1 (by sending an OPSEC packet to port 18183, 
 *    either via the OPSEC API, or using a self-assembled packet, or by execution
 *    of the fw.exe through command line.
 *  - Cisco PIX (by telnetting into the PIX and issuing the SHUN command)
 *  - Cisco Routers (by telnetting ino the router and modifying the ACL)
 *  - Cisco Routers (by telnetting ino the router and adding a null-route)
 *  - Netscreen firewalls (by telnetting in the Netscreen and adding IP's to a group
 *    which is denied access in the policy)
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef WITH_SNORTSAM

#include <pthread.h>

#include "sagan.h"
#include "sagan-snortsam.h"

#define NUM_HOSTS 255
#define FWSAM_NETWAIT	1000
#define FWSAM_NETHOLD 	6000

struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _SaganConfig *config;

unsigned long blockip[NUM_HOSTS +1],blockpeer[NUM_HOSTS +1],blockduration=0,blocksid=0;
unsigned short blockport=0,blockproto=0,blocklog=FWSAM_LOG_NONE,blockhow=FWSAM_HOW_INOUT,blockmode=FWSAM_STATUS_BLOCK,checkout=TRUE;

pthread_mutex_t fwsam_mutex = PTHREAD_MUTEX_INITIALIZER;

void sagan_fwsam( _SaganEvent *Event ) {

pthread_mutex_lock(&fwsam_mutex);

int retval=0;

blockduration=rulestruct[Event->found].fwsam_seconds; 
blocksid=atol(Event->sid);

if ( rulestruct[Event->found].fwsam_src_or_dst == 1 ){ 
	blockip[0]=inet_addr(Event->ip_src);
	blockip[1]=0; 
	} else { 
	blockip[0]=inet_addr(Event->ip_dst);
	blockip[1]=0;
	}

retval|=FWsamBlock(config->sagan_fwsam_info);

pthread_mutex_unlock(&fwsam_mutex);

}

int FWsamBlock(char *arg)
{

char str[512],*p,*encbuf,*decbuf,*samport,*sampass,*samhost;
int i,error=TRUE,len,ipidx=0,peeridx=0;
FWsamPacket sampacket;
struct hostent *hoste;
unsigned long samip;
FWsamStation station;

strlcpy(str,arg, sizeof(str)); 

/* Pull apart the server info  -- MOVE THIS TO sagan-config.c ? */

        samhost=str;
        samport=NULL;
        sampass=NULL;
        p=str;
        while(*p && *p!=':' && *p!='/')
                p++;
        if(*p==':')
        {       *p++=0;
                if(*p)
                        samport=p;
                while(*p && *p!='/')
                        p++;
        }
        if(*p=='/')
        {       *p++=0;
                if(*p)
                        sampass=p;
        }
        samip=0;

        if(inet_addr(samhost)==INADDR_NONE)
        {       hoste=gethostbyname(samhost);
                if(!hoste)
                {       
			Sagan_Log(0, "[%s, line %d] Unable to resolve host '%s', ignoring entry!" , __FILE__, __LINE__, samhost);
			return(1);
                }
                else
                        samip=*(unsigned long *)hoste->h_addr;
        }
        else
        {       samip=inet_addr(samhost);
                if(!samip)
                {       Sagan_Log(0, "[%s, line %d] Invalid host address '%s', ignoring entry!", __FILE__, __LINE__, samhost);
                        return(1);
                }
        }
	

        station.stationip.s_addr=samip;
        if(samport!=NULL && atoi(samport)>0)
                station.stationport=atoi(samport);
        else
                station.stationport=FWSAM_DEFAULTPORT;
        if(sampass!=NULL)
        {       strncpy(station.stationkey,sampass,TwoFish_KEY_LENGTH);
                station.stationkey[TwoFish_KEY_LENGTH]=0;
        }
        else
                station.stationkey[0]=0;
	
	strlcpy(station.initialkey,station.stationkey,sizeof(station.initialkey));
	station.stationfish=TwoFishInit(station.stationkey);

        station.localsocketaddr.sin_port=htons(0);
        station.localsocketaddr.sin_addr.s_addr=0;
        station.localsocketaddr.sin_family=AF_INET;
        station.stationsocketaddr.sin_port=htons(station.stationport);
        station.stationsocketaddr.sin_addr=station.stationip;
        station.stationsocketaddr.sin_family=AF_INET;

       do
                station.myseqno=rand();
        while(station.myseqno<20 || station.myseqno>65500);
        station.mykeymod[0]=rand();
        station.mykeymod[1]=rand();
        station.mykeymod[2]=rand();
        station.mykeymod[3]=rand();
        station.stationseqno=0;
        station.persistentsocket=TRUE;
        station.packetversion=FWSAM_PACKETVERSION_PERSISTENT_CONN;

        if(FWsamCheckIn(&station))
        {       error=FALSE;

                do
                {       ipidx=0;
                        do
                        {       if(!station.persistentsocket)
                                {       /* create a socket for the station */
                                        station.stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
                                        if(station.stationsocket==INVALID_SOCKET) {
						Sagan_Log(0, "[%s, line %d]  Invalid Socket error!", __FILE__, __LINE__ );
                                                error=TRUE;
                                        }
                                        if(bind(station.stationsocket,(struct sockaddr *)&(station.localsocketaddr),sizeof(struct sockaddr)))
                                        {       
						Sagan_Log(0, "[%s, line %d] Can not bind socket!", __FILE__, __LINE__);
                                                error=TRUE;
                                        }
                                }
                                else
                                        error=FALSE;
                                if(!error)
                                {       if(!station.persistentsocket)
                                        {       /* let's connect to the agent */
                                                if(connect(station.stationsocket,(struct sockaddr *)&station.stationsocketaddr,sizeof(struct sockaddr)))
                                                {       
							Sagan_Log(0, "[%s, line %d] Could not send block to host %s.", __FILE__, __LINE__, inet_ntoa(station.stationip));	
                                                        closesocket(station.stationsocket);
                                                        error=TRUE;
                                                }
                                        }

                                        if(!error)
                                        {       if( debug->debugfwsam )
							Sagan_Log(0, "[FWsamBlock] Connected to host %s. %s IP %s", inet_ntoa(station.stationip),blockmode==FWSAM_STATUS_BLOCK?"Blocking":"Unblocking",inettoa(blockip[ipidx]));

                                                /* now build the packet */
                                                station.myseqno+=station.stationseqno; /* increase my seqno by adding agent seq no */
                                                sampacket.endiancheck=1;                                                /* This is an endian indicator for Snortsam */
                                                sampacket.snortseqno[0]=(char)station.myseqno;
                                                sampacket.snortseqno[1]=(char)(station.myseqno>>8);
                                                sampacket.fwseqno[0]=(char)station.stationseqno;/* fill station seqno */
                                                sampacket.fwseqno[1]=(char)(station.stationseqno>>8);
                                                sampacket.status=blockmode;                     /* set block action */
                                                sampacket.version=station.packetversion;                        /* set packet version */
                                                sampacket.duration[0]=(char)blockduration;              /* set duration */
                                                sampacket.duration[1]=(char)(blockduration>>8);
                                                sampacket.duration[2]=(char)(blockduration>>16);
                                                sampacket.duration[3]=(char)(blockduration>>24);
                                                sampacket.fwmode=blocklog|blockhow|FWSAM_WHO_SRC; /* set the mode */
                                                sampacket.dstip[0]=(char)blockpeer[peeridx]; /* destination IP */
                                                sampacket.dstip[1]=(char)(blockpeer[peeridx]>>8);
                                                sampacket.dstip[2]=(char)(blockpeer[peeridx]>>16);
                                                sampacket.dstip[3]=(char)(blockpeer[peeridx]>>24);
                                                sampacket.srcip[0]=(char)blockip[ipidx];        /* source IP */
                                                sampacket.srcip[1]=(char)(blockip[ipidx]>>8);
                                                sampacket.srcip[2]=(char)(blockip[ipidx]>>16);
                                                sampacket.srcip[3]=(char)(blockip[ipidx]>>24);
                                                sampacket.protocol[0]=(char)blockproto; /* protocol */
                                                sampacket.protocol[1]=(char)(blockproto>>8);/* protocol */

                                                if(blockproto==6 || blockproto==17)
                                                {       sampacket.dstport[0]=(char)blockport;
                                                        sampacket.dstport[1]=(char)(blockport>>8);
                                                }
                                                else
                                                        sampacket.dstport[0]=sampacket.dstport[1]=0;
                                                sampacket.srcport[0]=sampacket.srcport[1]=0;

                                                sampacket.sig_id[0]=(char)blocksid;             /* set signature ID */
                                                sampacket.sig_id[1]=(char)(blocksid>>8);
                                                sampacket.sig_id[2]=(char)(blocksid>>16);
                                                sampacket.sig_id[3]=(char)(blocksid>>24);

                                                if( debug->debugfwsam )
                                                {       Sagan_Log(0, "[FWsamBlock] Sending %s",blockmode==FWSAM_STATUS_BLOCK?"BLOCK":"UNBLOCK");
                                                        Sagan_Log(0, "[FWsamBlock] Snort SeqNo:  %x",station.myseqno);
                                                        Sagan_Log(0, "[FWsamBlock] Mgmt SeqNo :  %x",station.stationseqno);
                                                        Sagan_Log(0, "[FWsamBlock] Status     :  %i",blockmode);
                                                        Sagan_Log(0, "[FWsamBlock] Version    :  %i",station.packetversion);
                                                        Sagan_Log(0, "[FWsamBlock] Mode       :  %i",blocklog|blockhow|FWSAM_WHO_SRC);
                                                        Sagan_Log(0, "[FWsamBlock] Duration   :  %li",blockduration);
                                                        Sagan_Log(0, "[FWsamBlock] Protocol   :  %i",blockproto);
                                                        Sagan_Log(0, "[FWsamBlock] Src IP     :  %s",inettoa(blockip[ipidx]));
                                                        Sagan_Log(0, "[FWsamBlock] Src Port   :  %i",0);
                                                        Sagan_Log(0, "[FWsamBlock] Dest IP    :  %s",inettoa(blockpeer[peeridx]));
                                                        Sagan_Log(0, "[FWsamBlock] Dest Port  :  %i",blockport);
                                                        Sagan_Log(0, "[FWsamBlock] Sig_ID     :  %lu",blocksid);
                                                }

                                                encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station.stationfish); /* get the encryption buffer */
                                                len=TwoFishEncrypt((char *)&sampacket,(char **)&encbuf,sizeof(FWsamPacket),FALSE,station.stationfish); /* encrypt the packet with current key */

                                                if(send(station.stationsocket,encbuf,len,0)!=len) /* weird...could not send */
                                                {
							Sagan_Log(0, "[%s, line %d] Could not send to host %s" , __FILE__, __LINE__, inet_ntoa(station.stationip));	
                                                        closesocket(station.stationsocket);
                                                       error=TRUE;
                                                }
                                                else
                                                {       i=FWSAM_NETWAIT;
                                                        ioctlsocket(station.stationsocket,FIONBIO,&i);  /* set non blocking and wait for  */
                                                        while(i-- >1)                                                   /* the response packet   */
                                                        {       waitms(10); /* wait for response (default maximum 3 secs */
                                                                if(recv(station.stationsocket,encbuf,len,0)==len)
                                                                        i=0; /* if we received packet we set the counter to 0. */
                                                                                 /* by the time we check with if, it's already dec'ed to -1 */
                                                        }
                                                        if(!i) /* id we timed out (i was one, then dec'ed)... */
                                                        {
							
								Sagan_Log(0, "[%s, line %d] Did not receive response from host %s" , __FILE__, __LINE__, inet_ntoa(station.stationip) );
                                                                closesocket(station.stationsocket);
                                                                error=TRUE;
                                                        }
                                                        else /* got a packet */
                                                        {       decbuf=(char *)&sampacket; /* get the pointer to the packet struct */
                                                                len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station.stationfish); /* try to decrypt the packet with current key */

                                                                if(len!=sizeof(FWsamPacket)) /* invalid decryption */
                                                                {       strlcpy(station.stationkey,station.initialkey,sizeof(station.stationkey)); /* try the intial key */
                                                                        TwoFishDestroy(station.stationfish);
                                                                        station.stationfish=TwoFishInit(station.stationkey); /* re-initialize the TwoFish with the intial key */
                                                                        len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station.stationfish); /* try again to decrypt */
                                                                        if ( debug->debugfwsam )
                                                                                Sagan_Log(0, "FWsamCheckOut] Had to use initial key!");
                                                                }
                                                                if(len==sizeof(FWsamPacket)) /* valid decryption */
                                                                {       if(sampacket.version==station.packetversion)/* master speaks my language */
                                                                        {       if(sampacket.status==FWSAM_STATUS_OK || sampacket.status==FWSAM_STATUS_NEWKEY
                                                                                || sampacket.status==FWSAM_STATUS_RESYNC || sampacket.status==FWSAM_STATUS_HOLD)
                                                                                {       station.stationseqno=sampacket.fwseqno[0] | (sampacket.fwseqno[1]<<8); /* get stations seqno */
                                                                                        station.lastcontact=(unsigned long)time(NULL); /* set the last contact time (not used yet) */
                                                                                        if ( debug->debugfwsam )
                                                                                        {
                                                                                                Sagan_Log(0, "[FWsamBlock] Received %s",sampacket.status==FWSAM_STATUS_OK?"OK":
                                                                                                                                                                                  sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
                                                                                                                                                                              sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
                                                                                                                                                                              sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
                                                                                                Sagan_Log(0, "[FWsamBlock] Snort SeqNo:  %x",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
                                                                                                Sagan_Log(0, "[FWsamBlock] Mgmt SeqNo :  %x",station.stationseqno);
                                                                                                Sagan_Log(0, "[FWsamBlock] Status     :  %i",sampacket.status);
                                                                                                Sagan_Log(0, "[FWsamBlock] Version    :  %i",sampacket.version);
                                                                                        }

                                                                                        if(sampacket.status==FWSAM_STATUS_HOLD)
                                                                                        {       i=FWSAM_NETHOLD;                        /* Stay on hold for a maximum of 60 secs (default) */
                                                                                                while(i-- >1)                                                   /* the response packet   */
                                                                                                {       waitms(10); /* wait for response  */
                                                                                                        if(recv(station.stationsocket,encbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,0)==sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE)
                                                                                                          i=0; /* if we received packet we set the counter to 0. */
                                                                                                }
                                                                                                if(!i) /* id we timed out (i was one, then dec'ed)... */
                                                                                                {       
												
													Sagan_Log(0, "[%s, line %d] Did not receive response from host %s" , __FILE__, __LINE__, inet_ntoa(station.stationip) );
                                                                                                        error=TRUE;
                                                                                                        sampacket.status=FWSAM_STATUS_ERROR;
                                                                                                }
                                                                                                else /* got a packet */
                                                                                                {       decbuf=(char *)&sampacket; /* get the pointer to the packet struct */
                                                                                                        len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station.stationfish); /* try to decrypt the packet with current key */

                                                                                                        if(len!=sizeof(FWsamPacket)) /* invalid decryption */
                                                                                                        {       strlcpy(station.stationkey,station.initialkey,sizeof(station.stationkey)); /* try the intial key */
                                                                                                                TwoFishDestroy(station.stationfish);
                                                                                                                station.stationfish=TwoFishInit(station.stationkey); /* re-initialize the TwoFish with the intial key */
                                                                                                                len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station.stationfish); /* try again to decrypt */
                                                                                                                if ( debug->debugfwsam )
                                                                                                                        Sagan_Log(0, "[FWsamBlock] Had to use initial key again!");
                                                                                                        }
                                                                                                        if( debug->debugfwsam )
                                                                                                        {       
													
														Sagan_Log(0, "[FWsamBlock] Received %s", sampacket.status==FWSAM_STATUS_OK?"OK": sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY": sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC": sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
                                                                                                                Sagan_Log(0, "[FWsamBlock] Snort SeqNo:  %x",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
                                                                                                                Sagan_Log(0, "[FWsamBlock] Mgmt SeqNo :  %x",station.stationseqno);
                                                                                                                Sagan_Log(0, "[FWsamBlock] Status     :  %i",sampacket.status);
                                                                                                                Sagan_Log(0, "[FWsamBlock] Version    :  %i",sampacket.version);
                                                                                                        }
                                                                                                        if(len!=sizeof(FWsamPacket)) /* invalid decryption */
                                                                                                        {       
												
														Sagan_Log(0, "[%s, line %d] Password mismatch! Ignoring host %s" , __FILE__, __LINE__, inet_ntoa(station.stationip));
                                                                                                                error=TRUE;
                                                                                                                sampacket.status=FWSAM_STATUS_ERROR;
                                                                                                        }
                                                                                                        else if(sampacket.version!=station.packetversion) /* invalid protocol version */
                                                                                                        {       
														Sagan_Log(0, "[%s, line %d] Protocol version error! Ignoring host %s" , __FILE__, __LINE__, inet_ntoa(station.stationip));
                                                                                                                error=TRUE;
                                                                                                                sampacket.status=FWSAM_STATUS_ERROR;
                                                                                                        }
                                                                                                        else if(sampacket.status!=FWSAM_STATUS_OK && sampacket.status!=FWSAM_STATUS_NEWKEY && sampacket.status!=FWSAM_STATUS_RESYNC)
                                                                                                        {       
														Sagan_Log(0, "[%s, line %d] Funky handshake error! Ignoring host %s" , __FILE__, __LINE__, inet_ntoa(station.stationip));
                                                                                                                error=TRUE;
                                                                                                                sampacket.status=FWSAM_STATUS_ERROR;
                                                                                                        }
                                                                                                }
                                                                                        }
                                                                                        if(sampacket.status==FWSAM_STATUS_RESYNC)  /* if station want's to resync... */
                                                                                        {       strlcpy(station.stationkey,station.initialkey,sizeof(station.stationkey)); /* ...we use the intial key... */
                                                                                                memcpy(station.fwkeymod,sampacket.duration,4);   /* and note the random key modifier */
                                                                                        }
                                                                                        if(sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)
                                                                                        {
                                                                                                FWsamNewStationKey(&station,&sampacket); /* generate new TwoFish keys */
                                                                                                if( debug->debugfwsam )
													Sagan_Log(0, "[%s, line %d] Generated new encryption key.... " , __FILE__, __LINE__);
                                                                                        }
                                                                                        if(!station.persistentsocket)
                                                                                                closesocket(station.stationsocket);
                                                                                }
                                                                                else if(sampacket.status==FWSAM_STATUS_ERROR) /* if SnortSam reports an error on second try, */
                                                                                {       closesocket(station.stationsocket);                               /* something is messed up and ... */
                                                                                        error=TRUE;
											Sagan_Log(0, "[%s, line %d] Undetermined error right after CheckIn! Ignoring host %s" , __FILE__, __LINE__, inet_ntoa(station.stationip));
                                                                                }
                                                                                else /* an unknown status means trouble... */
                                                                                {       
											Sagan_Log(0, "[%s, line %d] Funky handshake error! Ignoring host %s!" , __FILE__, __LINE__, inet_ntoa(station.stationip));	
                                                                                        closesocket(station.stationsocket);
                                                                                        error=TRUE;
                                                                                }
                                                                        }
                                                                        else   /* if the SnortSam agent uses a different packet version, we have no choice but to ignore it. */
                                                                        {       

										Sagan_Log(0, "[%s, line %d] Protocol version errror! Ignoring host %s!" , __FILE__, __LINE__, inet_ntoa(station.stationip));
                                                                                closesocket(station.stationsocket);
                                                                                error=TRUE;
                                                                        }
                                                                }
                                                                else /* if the intial key failed to decrypt as well, the keys are not configured the same, and we ignore that SnortSam station. */
                                                                {       
									Sagan_Log(0, "[%s, line %d] Password mismatch! Ignoring host %s!" , __FILE__, __LINE__, inet_ntoa(station.stationip));

                                                                        closesocket(station.stationsocket);
                                                                        error=TRUE;
                                                                }
                                                        }
                                                }
                                                free(encbuf); /* release of the TwoFishAlloc'ed encryption buffer */
                                        }
                                }

                                ipidx++;
                        }while(!error && ipidx<NUM_HOSTS && blockip[ipidx]);
                        peeridx++;
                }while(!error && peeridx<NUM_HOSTS && blockpeer[peeridx]);

                if(!error)
                {       if(checkout)
                                FWsamCheckOut(&station);
                        else
                        {       closesocket(station.stationsocket);
                                station.persistentsocket=FALSE;
                        }
                }
        }
        TwoFishDestroy(station.stationfish);

        return error;
}


int FWsamCheckIn(FWsamStation *station) {

int i,len,stationok=FALSE,again;
FWsamPacket sampacket;
char *encbuf,*decbuf;

        do
        {       
		again=FALSE;
                station->stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
                if(station->stationsocket==INVALID_SOCKET)
                {       
			Sagan_Log(0, "[%s, line %d] Invalid Socket errror!" , __FILE__, __LINE__);
                        return FALSE;
                }
                if(bind(station->stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
                {       
			Sagan_Log(0, "[%s, line %d] Can not bind to socket!" , __FILE__, __LINE__);
                        return FALSE;
                }

                /* let's connect to the agent */
                if(connect(station->stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr)))
                {       
			Sagan_Log(0, "[%s, line %d] Could not connect to host %s", __FILE__, __LINE__, inet_ntoa(station->stationip));
                        return FALSE;
                }
                else
                {       if ( debug->debugfwsam )
				Sagan_Log(0, "[FWsamCheckIn] Connected to host %s", inet_ntoa(station->stationip));
                        
			/* now build the packet */
                        sampacket.endiancheck=1;
                        sampacket.snortseqno[0]=(char)station->myseqno; /* fill my sequence number number */
                        sampacket.snortseqno[1]=(char)(station->myseqno>>8); /* fill my sequence number number */
                        sampacket.status=FWSAM_STATUS_CHECKIN; /* let's check in */
                        sampacket.version=station->packetversion; /* set the packet version */
                        memcpy(sampacket.duration,station->mykeymod,4);  /* we'll send SnortSam our key modifier in the duration slot */
                                                                                                   /* (the checkin packet is just the plain initial key) */
                        if ( debug->debugfwsam )
                        {       Sagan_Log(0, "[FWsamCheckIn] Sending CHECKIN");
                                Sagan_Log(0, "[FWsamCheckIn] Snort SeqNo:  %x",station->myseqno);
                                Sagan_Log(0, "[FWsamCheckIn] Mode       :  %i",sampacket.status);
                                Sagan_Log(0, "[FWsamCheckIn] Version    :  %i",sampacket.version);
                        }

                        encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get buffer for encryption */
                        len=TwoFishEncrypt((char *)&sampacket,(char **)&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt with initial key */
                        if(send(station->stationsocket,encbuf,len,0)!=len) /* weird...could not send */
				Sagan_Log(0, "Could not send to host %s", inet_ntoa(station->stationip));
                        else
                        {       i=FWSAM_NETWAIT;
                                ioctlsocket(station->stationsocket,FIONBIO,&i); /* set non blocking and wait for  */
                                while(i-- >1)
                                {       waitms(10); /* wait a maximum of 3 secs for response */
                                        if(recv(station->stationsocket,encbuf,len,0)==len)
                                                i=0;
                                }
                                if(!i) /* time up? */
					Sagan_Log(0, "Dis not receive response from host %s", inet_ntoa(station->stationip));
                                else
                                {       decbuf=(char *)&sampacket; /* got status packet */
                                        len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* try to decrypt with initial key */
                                        if(len==sizeof(FWsamPacket)) /* valid decryption */
                                        {       if ( debug->debugfwsam )
                                                {
                                                        Sagan_Log(0, "[FWsamCheckIn] Received %s",sampacket.status==FWSAM_STATUS_OK?"OK":
                                                                                                                                           sampacket.status==FWSAM_STATUS_NEWKEY?"NEWKEY":
                                                                                                                                           sampacket.status==FWSAM_STATUS_RESYNC?"RESYNC":
                                                                                                                                           sampacket.status==FWSAM_STATUS_HOLD?"HOLD":"ERROR");
                                                        Sagan_Log(0, "[FWsamCheckIn] Snort SeqNo:  %x",sampacket.snortseqno[0]|(sampacket.snortseqno[1]<<8));
                                                        Sagan_Log(0, "[FWsamCheckIn] Mgmt SeqNo :  %x",sampacket.fwseqno[0]|(sampacket.fwseqno[1]<<8));
                                                        Sagan_Log(0, "[FWsamCheckIn] Status     :  %i",sampacket.status);
                                                        Sagan_Log(0, "[FWsamCheckIn] Version    :  %i",sampacket.version);
                                                }

                                                if(sampacket.version==FWSAM_PACKETVERSION_PERSISTENT_CONN || sampacket.version==FWSAM_PACKETVERSION) /* master speaks my language */
                                                {       if(sampacket.status==FWSAM_STATUS_OK || sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)
                                                        {       station->stationseqno=sampacket.fwseqno[0]|(sampacket.fwseqno[1]<<8); /* get stations seqno */
                                                                station->lastcontact=(unsigned long)time(NULL);
                                                                stationok=TRUE;
                                                                station->packetversion=sampacket.version;
                                                                if(sampacket.version==FWSAM_PACKETVERSION)
                                                                        station->persistentsocket=FALSE;

                                                                if(sampacket.status==FWSAM_STATUS_NEWKEY || sampacket.status==FWSAM_STATUS_RESYNC)      /* generate new keys */
                                                                {       memcpy(station->fwkeymod,sampacket.duration,4); /* note the key modifier */
                                                                        FWsamNewStationKey(station,&sampacket); /* and generate new TwoFish keys (with key modifiers) */
                                                                        if ( debug->debugfwsam )
										Sagan_Log(0, "[FWsamCheckIn] Generated new encryption key.....");
                                                                }
                                                        }
                                                        else if(sampacket.status==FWSAM_STATUS_ERROR && sampacket.version==FWSAM_PACKETVERSION)
                                                        {       if(station->persistentsocket)
                                                                {      
									Sagan_Log(0, "[%s, line %d] Host %s doesn't support packet version %i for persistent connections. Trying packet version %i!" , __FILE__, __LINE__, inet_ntoa(station->stationip),FWSAM_PACKETVERSION_PERSISTENT_CONN,FWSAM_PACKETVERSION);
                                                                        station->persistentsocket=FALSE;
                                                                        station->packetversion=FWSAM_PACKETVERSION;
                                                                        again=TRUE;
                                                                }
                                                                else	
									Sagan_Log(0, "[%s, line %d] Protocol version mismatch! Ignoring host %s", __FILE__, __LINE__, inet_ntoa(station->stationip));
                                                        }
                                                        else /* weird, got a strange status back */
                                                                Sagan_Log(0, "[%s, line %d] Funky handshake error! Ignoring host %s!", __FILE__, __LINE__, inet_ntoa(station->stationip));
                                                }
                                                else /* packet version does not match */
                                                        Sagan_Log(0, "[%s, line %d] Potocol version error! Ignoring host %s!", __FILE__, __LINE__, inet_ntoa(station->stationip));
                                        }
                                        else /* key does not match */
                                                Sagan_Log(0, "[%s, line %d] Password mismatch! Ignoring host %s!",__FILE__, __LINE__, inet_ntoa(station->stationip));
                                }
                        }
                        free(encbuf); /* release TwoFishAlloc'ed buffer */
                }
                if(!(stationok && station->persistentsocket))
                        closesocket(station->stationsocket);
        }while(again);
        return stationok;
}


void waitms(unsigned int dur)
{
        usleep(dur*1000);
}


/*  Generates a new encryption key for TwoFish based on seq numbers and a random that
 *  the SnortSam agents send on checkin (in protocol)
*/
void FWsamNewStationKey(FWsamStation *station,FWsamPacket *packet)
{       unsigned char newkey[TwoFish_KEY_LENGTH+2];
        int i;

        newkey[0]=packet->snortseqno[0];                /* current snort seq # (which both know) */
        newkey[1]=packet->snortseqno[1];
        newkey[2]=packet->fwseqno[0];                   /* current SnortSam seq # (which both know) */
        newkey[3]=packet->fwseqno[1];
        newkey[4]=packet->protocol[0];          /* the random SnortSam chose */
        newkey[5]=packet->protocol[1];

        strncpy(newkey+6,station->stationkey,TwoFish_KEY_LENGTH-6); /* append old key */
        newkey[TwoFish_KEY_LENGTH]=0;

        newkey[0]^=station->mykeymod[0];                /* modify key with key modifiers which were */
        newkey[1]^=station->mykeymod[1];                /* exchanged during the check-in handshake. */
        newkey[2]^=station->mykeymod[2];
        newkey[3]^=station->mykeymod[3];
        newkey[4]^=station->fwkeymod[0];
        newkey[5]^=station->fwkeymod[1];
        newkey[6]^=station->fwkeymod[2];
        newkey[7]^=station->fwkeymod[3];

        for(i=0;i<=7;i++)
                if(newkey[i]==0)
                        newkey[i]++;

//        safecopy(station->stationkey,newkey);
	strlcpy(station->stationkey,newkey,sizeof(station->stationkey));
        TwoFishDestroy(station->stationfish);
        station->stationfish=TwoFishInit(newkey);
}


/*      This function (together with the define in snortsam.h) attempts
*      to prevent buffer overflows by checking the destination buffer size.
*/

/* This does nothing else than inet_ntoa, but it keeps 256 results in a static string
 * unlike inet_ntoa which keeps only one. This is used for (s)printf's were two IP
 * addresses are printed (this has been increased from four while multithreading the app).
*/
char *inettoa(unsigned long ip)
{       struct in_addr ips;
        static char addr[20];

        ips.s_addr=ip;
        strncpy(addr,inet_ntoa(ips),19);
        addr[19]=0;
        return addr;
}


/*  FWsamCheckOut will be called when samtool exists. It de-registeres this tool 
 *  from the list of sensor that the SnortSam agent keeps. 
*/
void FWsamCheckOut(FWsamStation *station)
{       FWsamPacket sampacket;
        int i,len;
        char *encbuf,*decbuf;


        if(!station->persistentsocket)
        {       station->stationsocket=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
                if(station->stationsocket==INVALID_SOCKET)
                {       
			Sagan_Log(0, "[%s, line %d] Invalid socket error!" , __FILE__, __LINE__);	
                        return;
                }
                if(bind(station->stationsocket,(struct sockaddr *)&(station->localsocketaddr),sizeof(struct sockaddr)))
                {       
			Sagan_Log(0, "[%s, line %d] Can not bind socket!" , __FILE__, __LINE__);
                        return;
                }
                /* let's connect to the agent */
                i=!connect(station->stationsocket,(struct sockaddr *)&station->stationsocketaddr,sizeof(struct sockaddr));
        }
        else
                i=TRUE;
        if(i)
        {       if( debug->debugfwsam )
			Sagan_Log(0, "[FWsamCheckOut] Disconnecting from host %s",inet_ntoa(station->stationip));

                /* now build the packet */
                station->myseqno+=station->stationseqno; /* increase my seqno */
                sampacket.endiancheck=1;
                sampacket.snortseqno[0]=(char)station->myseqno;
                sampacket.snortseqno[1]=(char)(station->myseqno>>8);
                sampacket.fwseqno[0]=(char)station->stationseqno; /* fill station seqno */
                sampacket.fwseqno[1]=(char)(station->stationseqno>>8);
                sampacket.status=FWSAM_STATUS_CHECKOUT;  /* checking out... */
                sampacket.version=station->packetversion;

                if( debug->debugfwsam )
                {       
			Sagan_Log(0, "[FWsamCheckOut] Sending CHECKOUT");
                        Sagan_Log(0, "[FWsamCheckOut] Snort SeqNo:  %x",station->myseqno);
                        Sagan_Log(0, "[FWsamCheckOut] Mgmt SeqNo :  %x",station->stationseqno);
                        Sagan_Log(0, "[FWsamCheckOut] Status     :  %i",sampacket.status);
                }

                encbuf=TwoFishAlloc(sizeof(FWsamPacket),FALSE,FALSE,station->stationfish); /* get encryption buffer */
                len=TwoFishEncrypt((char *)&sampacket,(char **)&encbuf,sizeof(FWsamPacket),FALSE,station->stationfish); /* encrypt packet with current key */
                if(send(station->stationsocket,encbuf,len,0)==len)
                {       i=FWSAM_NETWAIT;
                        ioctlsocket(station->stationsocket,FIONBIO,&i); /* set non blocking and wait for  */
                        while(i-- >1)
                        {       waitms(10);                                     /* ...wait a maximum of 3 secs for response... */
                                if(recv(station->stationsocket,encbuf,len,0)==len) /* ... for the status packet */
                                        i=0;
                        }
                        if(i) /* if we got the packet */
                        {       decbuf=(char *)&sampacket;
                                len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish);

                                if(len!=sizeof(FWsamPacket)) /* invalid decryption */
                                {       strlcpy(station->stationkey,station->initialkey,sizeof(station->stationkey)); /* try initial key */
                                        TwoFishDestroy(station->stationfish);                    /* toss this fish */
                                        station->stationfish=TwoFishInit(station->stationkey); /* re-initialze TwoFish with initial key */
                                        len=TwoFishDecrypt(encbuf,(char **)&decbuf,sizeof(FWsamPacket)+TwoFish_BLOCK_SIZE,FALSE,station->stationfish); /* and try to decrypt again */
                                        if( debug->debugfwsam )
						Sagan_Log(0, "[FWsamCheckOut] Had to use initial key!");
                                }
                                if(len==sizeof(FWsamPacket)) /* valid decryption */
                                {       if(sampacket.version!=station->packetversion) /* but don't really care since we are on the way out */
                                                Sagan_Log(0, "[%s, line %d] Protocol version error!", __FILE__, __LINE__ );
                                }
                                else
					Sagan_Log(0, "[%s, line %d] Password mismatch!", __FILE__, __LINE__); 
                        }
                }
                free(encbuf); /* release TwoFishAlloc'ed buffer */
        }
        else
		Sagan_Log(0, "[%s, line %d] Could not connect to host %s for CheckOut", __FILE__, __LINE__, inet_ntoa(station->stationip)); 

        closesocket(station->stationsocket);
        station->persistentsocket=FALSE;
}
#endif
