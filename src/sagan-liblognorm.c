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

/* sagan-liblognorm.c 
 *
 * These functions deal with liblognorm / data normalization.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBLOGNORM

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


#include <liblognorm.h>
#include <ptree.h>
#include <lognorm.h>

#include "sagan.h"
#include "sagan-liblognorm.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;

struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm = NULL;

pthread_mutex_t Lognorm_Mutex = PTHREAD_MUTEX_INITIALIZER;

/************************************************************************
 * liblognorm GLOBALS
 ************************************************************************/

struct stat liblognorm_fileinfo;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;

static ln_ctx ctx;
//static ee_ctx eectx;


struct _SaganCounters *counters;


/************************************************************************ 
 * sagan_liblognorm_load 
 *
 * Load in the normalization files into memory
 ************************************************************************/

void sagan_liblognorm_load(void) {

int i;

SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));
memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));

if((ctx = ln_initCtx()) == NULL) Sagan_Log(1, "[%s, line %d] Cannot initialize liblognorm context.", __FILE__, __LINE__);
//if((eectx = ee_initCtx()) == NULL) Sagan_Log(1, "[%s, line %d] Cannot initialize libee context.", __FILE__, __LINE__);

//ln_setEECtx(ctx, eectx);

for (i=0; i < counters->liblognormtoload_count; i++) {
	Sagan_Log(0, "Loading %s for normalization.", liblognormtoloadstruct[i].filepath);
	if (stat(liblognormtoloadstruct[i].filepath, &liblognorm_fileinfo)) Sagan_Log(1, "%s was not fonnd.", liblognormtoloadstruct[i].filepath);
	ln_loadSamples(ctx, liblognormtoloadstruct[i].filepath);
	}

}

/***********************************************************************
 * sagan_normalize_liblognom
 *
 * Locates interesting log data via Rainer's liblognorm library
 ***********************************************************************/

void sagan_normalize_liblognorm(char *syslog_msg)
{

char buf[10*1024];
const char *cstr;
const char *username;
const char *src_ip;

const char *src_host;
const char *dst_host;

char ipbuf_src[64] = { 0 }; 
char ipbuf_dst[64] = { 0 }; 

char *tmp;

struct json_object *json = NULL;

snprintf(buf, sizeof(buf),"%s", syslog_msg);

//printf("to normlize: %s\n", syslog_msg);
ln_normalize(ctx, buf, strlen(buf), &json);

cstr = (char*)json_object_to_json_string(json);

SaganNormalizeLiblognorm->ip_src = json_object_get_string(json_object_object_get(json, "src-ip"));
SaganNormalizeLiblognorm->ip_dst = json_object_get_string(json_object_object_get(json, "dst-ip"));
SaganNormalizeLiblognorm->username = json_object_get_string(json_object_object_get(json, "username"));

/*
src_host = json_object_get_string(json_object_object_get(json, "src-host"));

/* If a src/dst host is found,  do a reverse lookup */

if ( src_host != NULL ) { 
	strlcpy(ipbuf_src, DNS_Lookup(src_host), sizeof(ipbuf_src));
	SaganNormalizeLiblognorm->ip_src=ipbuf_src;
	}

dst_host = json_object_get_string(json_object_object_get(json, "dst-host"));

if ( dst_host != NULL ) {
        strlcpy(ipbuf_dst, DNS_Lookup(dst_host), sizeof(ipbuf_dst));
        SaganNormalizeLiblognorm->ip_src=ipbuf_dst;
        }

/* Get port information */

tmp = json_object_get_string(json_object_object_get(json, "src-port")); 

if ( tmp != NULL ) 
	SaganNormalizeLiblognorm->src_port = atoi(tmp); 

tmp = json_object_get_string(json_object_object_get(json, "dst-port"));

if ( tmp != NULL ) { 
	SaganNormalizeLiblognorm->dst_port = atoi(tmp);
	}


if (SaganNormalizeLiblognorm->ip_src != NULL ) {
	if (!strcmp(SaganNormalizeLiblognorm->ip_src, "127.0.0.1" )) SaganNormalizeLiblognorm->ip_src=config->sagan_host;
	}

if (SaganNormalizeLiblognorm->ip_dst != NULL ) { 
	if (!strcmp(SaganNormalizeLiblognorm->ip_dst, "127.0.0.1" )) SaganNormalizeLiblognorm->ip_dst=config->sagan_host;
	}

if ( debug->debugnormalize ) { 
     Sagan_Log(0, "Liblognorm DEBUG output:");
     Sagan_Log(0, "---------------------------------------------------");
     Sagan_Log(0, "Log message to normalize: %s", syslog_msg); 
     Sagan_Log(0, "Parsed: %s", cstr);
     Sagan_Log(0, "Source IP: %s", SaganNormalizeLiblognorm->ip_src); 
     Sagan_Log(0, "Destination IP: %s", SaganNormalizeLiblognorm->ip_dst);
     Sagan_Log(0, "Source Port: %d", SaganNormalizeLiblognorm->src_port);
     Sagan_Log(0, "Destination Port: %d", SaganNormalizeLiblognorm->dst_port);
     Sagan_Log(0, "Username: %s", SaganNormalizeLiblognorm->username);
     Sagan_Log(0, ""); 
     }


//free(cstr);
//json_object_put(json);
//free(json);

}

#endif
