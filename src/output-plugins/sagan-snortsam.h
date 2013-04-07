/* $Id: snortsam.h,v 2.41 2009/10/16 22:19:36 fknobbe Exp $
 *
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
 * Header file for SnortSam.c
 *
 */

#ifndef		__SNORTSAM_H__
#define		__SNORTSAM_H__

#ifdef	_DEBUG
#define FWSAMDEBUG
#endif
#ifdef	DEBUG
#define FWSAMDEBUG
#endif



/* #define	DISABLE_REVERSE_LOOKUPS	*/		/*  Set this if you want Snortsam to
											avoid doing reverse DNS lookups
											for hosts in log files.
											Only used in email plugin at the moment. */

/* #define ENABLE_OPSEC */  /* Now a compiler flag */


/* room for platform defines, if any necessary */

#ifndef SOLARIS 	/* Addtl Solaris defines */
#if defined(SUN) || defined(SunOS) || defined(SPARC)
#define SOLARIS
#endif
#endif


#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>


#ifdef WIN32		/* ------------------ Windows platform specific stuff ----------------------- */

#include "win32_service.h"
#include <winsock.h>

/* 	included to provide compatibility with plugins not written under Windows 
	(although I'm mainly developing under FreeBSD now...)*/

#define SIGKILL				9		/* kill (cannot be caught or ignored) */
#define SIGQUIT				3		/* quit */
#define SIGHUP 				1		/* hangup */
#define SIGUSR1				30		/* user defined signal 1 */
#define SIGUSR2 				31		/* user defined signal 2 */
#define SIGPIPE 				13		/* write on a pipe with no one to read it */
#define strncasecmp			strnicmp
#define strcasecmp			stricmp
#define snprintf 			_snprintf
#define vsnprintf 			_vsnprintf
#define bzero(x, y) 			memset((x), 0, (y))
#define execv    			_execv
#define getpid  				_getpid
#define index  				strchr
#define bcopy(x, y, z) 		memcpy((void *)x, (const void *)y, (size_t) z)
#define mkdir(x, y) 			_mkdir(x)
#define read					_read
#define write				_write
#define lseek				_lseek

#ifndef ssize_t
typedef size_t ssize_t;
#endif
#ifndef pid_t
typedef int pid_t;
#endif
#ifndef pthread_mutex_t
typedef HANDLE pthread_mutex_t;
#endif
#ifndef pthread_t
typedef HANDLE pthread_t;
#endif


#ifndef u_long
typedef unsigned long u_long;
#endif
#ifndef u_int32_t
typedef unsigned long u_int32_t;
#endif
#ifndef u_word
typedef unsigned short u_word;
#endif
#ifndef u_int16_t
typedef unsigned short u_int16_t;
#endif
#ifndef u_char
typedef unsigned char u_char;
#endif
#ifndef u_int8_t
typedef unsigned char u_int8_t;
#endif



#else		/* ------------------ Other platform specific stuff ----------------------- */

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>		
#include <netdb.h>
#include <pthread.h>

#ifdef SOLARIS
#include <sys/filio.h>
#ifndef _uint_defined
#include <stdint.h>
typedef uint32_t u_int32_t;
typedef uint16_t u_int16_t;
typedef uint8_t u_int8_t;
#define _uint_defined
#endif /* _uint_defined */
#endif



#define stricmp			strcasecmp
#define strnicmp		strncasecmp		

/* PLUGIN WRITER: Please use the following for socket stuff */
typedef int				SOCKET;
#define ioctlsocket		ioctl
#define closesocket		close

#endif		/* ------------------ End platform specific stuff ----------------------- */



#include "sagan-twofish.h"


/* compatibilty stuff */
#ifndef INVALID_SOCKET
#define INVALID_SOCKET	-1
#endif
#ifndef INADDR_NONE
#define INADDR_NONE	-1
#endif

#ifndef	FALSE
#define FALSE	0
#endif
#ifndef	TRUE
#define	TRUE	!FALSE
#endif
#ifndef	bool
#define	bool	int
#endif


/*  Use only if necessary */
/*
#ifndef _TIME_T_DEFINED
typedef long time_t;        
#define _TIME_T_DEFINED     
#endif
*/ 



#ifdef ENABLE_OPSEC
#define _MYLIBCSTUFF		/*	Resolves a conflict between libc.lib and msvcrt.lib under Windows */
#endif


#ifndef _MYLIBCSTUFF
#define myisdigit(x) isdigit(x)
#define myisspace(x) isspace(x)
#define mytolower(x) tolower(x)
#endif



/* defines */
#define safecopy(dst,src)		_safecp(dst,sizeof(dst),src)

#ifdef WIN32
#define FWSAMCONFIGFILE			"snortsam.cfg"
#define FWSAMHISTORYFILE			"snortsam.sta"
#else
#define FWSAMCONFIGFILE			"/etc/snortsam.conf"
#define FWSAMHISTORYFILE			"/var/db/snortsam.state"  
#endif

#define FWSAMHISTORYVERSION		"SSSF01"	/* Magic is probably better word. Records filetype and version in header of state file. */

#define BLOCKQUEUESIZE			20000		/* Create a blocking queue with this many blocking requests.
											It's set a bit high to accomodate the rollback field */
#define QUEUE_RETRYTIME			3000		/* If the queue is full, wait three seconds and check again for a
											free slot for a blocking request */
#define STRBUFSIZE				1024
#define FILEBUFSIZE				512

#define FWSAM_DEFAULTPORT		898	/* Default port if user does not specify one in snort.conf */
									/* (Was unused last time I checked...) */
#define FWSAM_PACKETVERSION		14
#define FWSAM_PACKETVERSION_PERSISTENT_CONN		15

#define FWSAM_STATUS_CHECKIN	1	/* snort to fw */
#define FWSAM_STATUS_CHECKOUT	2
#define FWSAM_STATUS_BLOCK		3
#define FWSAM_STATUS_UNBLOCK	9

#define FWSAM_STATUS_OK			4	/* fw to snort */
#define FWSAM_STATUS_ERROR		5
#define FWSAM_STATUS_NEWKEY		6
#define FWSAM_STATUS_RESYNC		7
#define FWSAM_STATUS_HOLD		8

#define FWSAM_LOG_NONE			0
#define FWSAM_LOG_SHORTLOG		1
#define FWSAM_LOG_SHORTALERT	2
#define FWSAM_LOG_LONGLOG		3
#define FWSAM_LOG_LONGALERT		4
#define FWSAM_LOG				(FWSAM_LOG_SHORTLOG|FWSAM_LOG_SHORTALERT|FWSAM_LOG_LONGLOG|FWSAM_LOG_LONGALERT)
#define	FWSAM_WHO_DST			8
#define FWSAM_WHO_SRC			16
#define FWSAM_WHO				(FWSAM_WHO_DST|FWSAM_WHO_SRC)
#define FWSAM_HOW_IN			32
#define FWSAM_HOW_OUT			64
#define FWSAM_HOW_INOUT			(FWSAM_HOW_IN|FWSAM_HOW_OUT)
#define FWSAM_HOW_THIS			128
#define FWSAM_HOW				(FWSAM_HOW_IN|FWSAM_HOW_OUT|FWSAM_HOW_THIS)


/* Plugin status */
#define ACTIVE			2
#define INACTIVE			1
#define DISABLED			0

/* Checkpoint SAM packet offsets */
#define CP_DATALEN		27	/* byte */
#define CP_IPADDR		40	/* long */
#define CP_ACTION		47	/* byte */
#define CP_DURATION		48	/* long */
#define CP_LOGTYPE		55	/* byte */
#define CP_MODSTR		60	/* string */
	
 
/* Variable Definitions */

typedef struct _blockinfo		/* Block info structure */
{	unsigned long sig_id;		/* Snort Signature ID (for logging/presentation) */
	unsigned long blockip;		/* IP to be blocked */
	unsigned long peerip;		/* Peer IP (if connection) */
	time_t duration;				/* Duration of block */
	time_t blocktime;			/* Time when block started */
	unsigned short port;			/* Port (if connection) */
	unsigned short proto;		/* Protocol (if connection) */
	unsigned short mode;			/* Blocking mode (src, dst, connection) */
	short block;					/* block or unblock flag --- this flag is dynamically changed */
}	BLOCKINFO;

typedef struct _oldblockinfo		/* Block info structure */
{	unsigned long blockip;		/* IP to be blocked */
	unsigned long peerip;		/* Peer IP (if connection) */
	time_t duration;				/* Duration of block */
	time_t blocktime;			/* Time when block started */
	unsigned short port;			/* Port (if connection) */
	unsigned short proto;		/* Protocol (if connection) */
	unsigned short mode;			/* Blocking mode (src, dst, connection) */
	short block;					/* block or unblock flag --- this flag is dynamically changed */
}	OLDBLOCKINFO;

typedef struct _blockqueue		/* queue for blocking requests */
{	BLOCKINFO blockinfo;			/* COPY of block request (not just pointer) */
	volatile unsigned long processing;		/* how many plugins are processing this request */
	unsigned long originator;	/* Orignating IP address so that forwarder can skip sending a request back to another Snortsam if it received it from there. */
	int forceunblock;			/* Unblocking can be forced even if plugin does expiration itself. */
	int extension;				/* On devices that don't time-out, skip the repeated block. On devices that time-out themselves, block again. */
	int reload;					/* Set TRUE on a queue entry caused by a USR1 reload. */
}	BLOCKQUEUE;
	
typedef struct _datalist					/* List of plugin devices/parameters */
{	void *data;							/* Pointer to list data */
	volatile unsigned long readpointer;	/* Pointer to queue request */
	volatile int busy;					/* Busy/Free flag */
	struct _datalist *next;				/* Pointer to next element */
}	DATALIST;

typedef struct _threadtable		/* This table is allocated with room for all possible threads. It keeps track of: */
{	volatile pthread_t threadid;	/* a) the Thread ID so that getout() can cancel all running threads before exit (handle under Windows), */
	volatile unsigned long winthreadid;	/*    Also, the Windows thread ID. Under Windows, this is the ID, above is the handle. */
	unsigned long plugin;		/* b) the plugin parameter for a thread, */
	DATALIST *datap;				/* c) the data pointer parameter for a thread. */
}	THREADTABLE;

typedef struct _snortsensor					/* structure for a snort sensor */
{	struct _snortsensor		*next;
	struct in_addr			snortip;			/* IP address of sensor */
	BLOCKINFO				*rbfield;		/* an array of block structs for rollback */
	TWOFISH					*snortfish;		/* the TwoFish of the sensor */
	time_t					*rbmeterfield;	/* array of times, for threshold metering */
	time_t					lastcontact;		/* last contact not used yet */
	time_t					lastkeytime;		/* Last time keys got negotiated */
	time_t					sleepstart;		/*  */
	unsigned long			actrb;			/* pointer to the next empty slot to note blocking info */
	unsigned long			actrbmeter;		/* pointer to the next emtpy meter slot */
	int						persistentsocket; /* Flag for permanent connection */
	int						toberemoved;	/* Flag to schedule sensor for removal. */
	unsigned short 			myseqno;			/* the SnortSam packet sequence number */
	unsigned short 			snortseqno;		/* and the one from the snort box */
	SOCKET					snortsocket;		/* the socket of that sensor */
	unsigned char			snortkeymod[4];	/* snortbox key modifier (random, supplied at check-in) */
	unsigned char			mykeymod[4];		/* SnortSam key modifier (random, returned at check-in) */
	unsigned char			currentkey[TwoFish_KEY_LENGTH+2];	/* the current key (intial key kept in accept list) */
	unsigned char			packetversion;	/* The packet version the sensor uses. */
}	SENSORLIST;

typedef struct _FWsampacket				/* 2 blocks (3rd block is header from TwoFish) */
{	unsigned short		endiancheck;		/* 0  */
	unsigned char		srcip[4];		/* 2  */
	unsigned char		dstip[4];		/* 6  */
	unsigned char		duration[4];		/* 10 */
	unsigned char		snortseqno[2];	/* 14 */
	unsigned char		fwseqno[2];		/* 16 */
	unsigned char		srcport[2];		/* 18 */
	unsigned char		dstport[2];		/* 20 */
	unsigned char		protocol[2];		/* 22 */
	unsigned char		fwmode;			/* 24 */
	unsigned char		version;			/* 25 */
	unsigned char		status;			/* 26 */
	unsigned char		sig_id[4];		/* 27 */
	unsigned char		fluff;			/* 31 */
}	FWsamPacket;							/* 32 bytes in size */

typedef struct _Old13FWsampacket			/* about 2 blocks (3rd block is header from TwoFish) */
{	unsigned short		endiancheck;		/* 0  */
	unsigned char		srcip[4];		/* 2  */
	unsigned char		dstip[4];		/* 6  */
	unsigned char		duration[4];		/* 10 */
	unsigned char		snortseqno[2];	/* 14 */
	unsigned char		fwseqno[2];		/* 16 */
	unsigned char		srcport[2];		/* 18 */
	unsigned char		dstport[2];		/* 20 */
	unsigned char		protocol[2];		/* 22 */
	unsigned char		fwmode;			/* 24 */
	unsigned char		version;			/* 25 */
	unsigned char		status;			/* 26 */
}	Old13FWsamPacket;					/* 27 */

typedef struct _dontblocklist		/* list of IP's/nets never to be blocked */
{	struct _dontblocklist	*next;
	struct in_addr			ip;
	unsigned long			mask;
	int						block;
}	DONTBLOCKLIST;

typedef struct _onlyblocklist		/* list of IP's/nets never to be blocked */
{	struct _onlyblocklist	*next;
	struct in_addr			ip;
	unsigned long			mask;
	int						block;
}	ONLYBLOCKLIST;

typedef struct _overridelist		/* list of IP's/nets where block duration is overridden */
{	struct _overridelist	*next;
	struct in_addr			ip;
	unsigned long			mask;
	time_t					newduration;
}	OVERRIDELIST;

typedef struct _limitlist		/* list of IP's/nets where block duration is limited */
{	struct _limitlist		*next;
	struct in_addr			ip;
	unsigned long			mask;
	time_t					limit;
	int						upper;
}	LIMITLIST;

typedef struct _acceptlist			/* list of authorized snort sensors (with their initial key) */
{	struct _acceptlist		*next;
	struct in_addr			ip;
	unsigned long			mask;
	unsigned char			initialkey[TwoFish_KEY_LENGTH+2];
}	ACCEPTLIST;

typedef struct _sidfilterlist			/* list of accepted or denied SIDs from listed sensor/network */
{	struct _sidfilterlist	*next;
	struct in_addr			ip;
	unsigned long			mask;
	unsigned long			*sidarray;
	unsigned long			sidcount;
	int						typedenied;
}	SIDFILTERLIST;

typedef struct _fwdata
{	struct in_addr		ip;
}   FWDATA;

typedef struct _blockhistory
{	struct _blockhistory	*next;
	BLOCKINFO				blockinfo;
}	BLOCKHISTORY;


/* Global Vars */

#if !defined( __SNORTSAM_C__) && !defined(__SAMTOOL_C__)
extern unsigned long netmask[2][33];
extern unsigned short netmaskbigendian;
extern char myhostname[STRBUFSIZE+2];
#endif


/* Functions */

#define getnetmask(x)	(netmask[netmaskbigendian][(((unsigned int)atoi(x))>32?32:(unsigned int)atoi(x))])


#ifdef _MYLIBCSTUFF
char mytolower(char c);
int myisspace(unsigned char c);
int myisdigit(char c);
#endif

void _safecp(char *dst,unsigned long max,char *src);
void *safemalloc(unsigned long,char *,char *);
void waitms(unsigned int);
void showerror(void);
void getout(int ret);
char *inettoa(unsigned long ip);
void logmessage(unsigned int level,char *logmsg,char *module,unsigned long ip);
unsigned long parseduration(char *p);
unsigned long getip(char *ipstr);
char *gethstname(unsigned long ip);
void parseline(char *arg,bool first,char *file,unsigned long line);
void parsefile(char *cfgfile,bool first,char *callingfile,unsigned long callingline);
void adddontblock(unsigned long ip, unsigned long mask,int block, char *func, char *what);
void addoverride(unsigned long ip, unsigned long mask, unsigned long dur, char *func, char *what);
void sortacceptlist(void);
void sortdontblocklist(void);
void sortoverridelist(void);
void sortlimitlist(void);
void sortsidfilterlist(void);
void sortpluginindex(void);
ACCEPTLIST *allowedhost(unsigned long addr);
int dontblockhost(unsigned long addr,int block);
unsigned long override_duration_on_host(unsigned long addr,unsigned long duration);
unsigned long limit_duration_on_sensor(unsigned long addr,unsigned long duration);
int sid_denied_from_sensor(unsigned long addr, unsigned long sid);
SENSORLIST *getsnorty(unsigned long addr,ACCEPTLIST *ap);
void removesnort(SENSORLIST *snorty) ;
void newkey(SENSORLIST *snortbox,FWsamPacket *packet);
int sendpacket(SENSORLIST *snortbox,char *packet,unsigned long packetsize);
void rollback(SENSORLIST *sensor);
BLOCKHISTORY *inhistory(BLOCKINFO *bd);
int isrepetitive(BLOCKINFO *bd);
#if !defined(__SSP_ISA_CPP__) && !defined(__SSP_ISA2004_CPP__)
void savehistory(void);
#endif
void block(SENSORLIST *snortbox,unsigned long bsip,unsigned short bsport,
		   unsigned long bdip,unsigned short bdport,
		   unsigned short bproto,time_t bduration,unsigned char bmode,
		   time_t btime,unsigned long bsig_id);
void unblock(BLOCKINFO *bhp,char *comment,unsigned long reqip,int force);
void addtohistory(BLOCKHISTORY *,int);
void clearhistory(void);
void reloadhistory(int reblock);
int processincomingrequest(SENSORLIST *snortbox,char *buf,unsigned long packetsize,ACCEPTLIST *acceptp);
//int main(int argc,char *argv[]);
int waitfor(SOCKET sock,char *text,unsigned long timeout);
int sendreceive(SOCKET socket,unsigned int timeout,char *plugin,struct in_addr ip,char *sendmsg,char *response,char *errmsg1,char *errmsg2);
void addrequesttoqueue(short,BLOCKINFO *,int,int,int,unsigned long);
void queuehandler(void);
int moreinqueue(unsigned long);
void multithreadhandler(THREADTABLE *);
void singlethreadhandler(THREADTABLE *);
signed long getfreethreadindex(void);
void sig_usr1_flagger(int i);
void sig_usr2_flagger(int i);

#endif  /* __SNORTSAM_H__ */


int FWsamBlock(char *);

/* Typedefs */

typedef struct _FWsamstation            /* structure of a mgmt station */
{       unsigned short                  myseqno;
        unsigned short                  stationseqno;
        unsigned char                   mykeymod[4];
        unsigned char                   fwkeymod[4];
        unsigned short                  stationport;
        struct in_addr                  stationip;
        struct sockaddr_in              localsocketaddr;
        struct sockaddr_in              stationsocketaddr;
        SOCKET                          stationsocket;          /* the socket of that station */
        TWOFISH                         *stationfish;
        char                            initialkey[TwoFish_KEY_LENGTH+2];
        char                            stationkey[TwoFish_KEY_LENGTH+2];
        time_t                          lastcontact;
/*      time_t                          sleepstart; */
        int                             persistentsocket; /* Flag for permanent connection */
        unsigned char                   packetversion;  /* The packet version the sensor uses. */
}       FWsamStation;

void FWsamNewStationKey(FWsamStation *,FWsamPacket *);
void FWsamCheckOut(FWsamStation *);
int FWsamCheckIn(FWsamStation *);


