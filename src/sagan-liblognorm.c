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
#include <pthread.h>


#include <liblognorm.h>
#include <ptree.h>
#include <lognorm.h>

#include "sagan.h"
#include "sagan-liblognorm.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;

/************************************************************************
 * liblognorm GLOBALS
 ************************************************************************/

struct stat liblognorm_fileinfo;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;

static ln_ctx ctx;
static ee_ctx eectx;


struct _SaganCounters *counters;


/************************************************************************ 
 * sagan_liblognorm_load 
 *
 * Load in the normalization files into memory
 ************************************************************************/

void sagan_liblognorm_load(void) {

int i;

if((ctx = ln_initCtx()) == NULL) Sagan_Log(1, "[%s, line %d] Cannot initialize liblognorm context.", __FILE__, __LINE__);
if((eectx = ee_initCtx()) == NULL) Sagan_Log(1, "[%s, line %d] Cannot initialize libee context.", __FILE__, __LINE__);

ln_setEECtx(ctx, eectx);

for (i=0; i < counters->liblognormtoload_count; i++) {
	Sagan_Log(0, "Loading %s for normalization.", liblognormtoloadstruct[i].filepath);
	if (stat(liblognormtoloadstruct[i].filepath, &liblognorm_fileinfo)) Sagan_Log(1, "%s was not fonnd.", liblognormtoloadstruct[i].filepath);
	ln_loadSamples(ctx, liblognormtoloadstruct[i].filepath);
	}

}

struct _SaganNormalizeLiblognorm *sagan_normalize_liblognorm(char *syslog_msg)
{

pthread_mutex_t liblognorm_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_lock(&liblognorm_mutex);

es_str_t *str = NULL;
es_str_t *propName = NULL;
struct ee_event *lnevent = NULL;
struct ee_field *field = NULL;
char *cstr=NULL;


struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm = NULL;
SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));
memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));

char ipbuf_src[128];
char ipbuf_dst[128];


                      str = es_newStrFromCStr(syslog_msg, strlen(syslog_msg ));

                      ln_normalize(ctx, str, &lnevent);
                        if(lnevent != NULL) {
                        es_emptyStr(str);
                        ee_fmtEventToRFC5424(lnevent, &str);
                        cstr = es_str2cstr(str, NULL);
                        
                        if ( debug->debugnormalize ) Sagan_Log(0, "Normalize output: %s", cstr);

                        propName = es_newStrFromBuf("src-ip", 6);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
			   SaganNormalizeLiblognorm->ip_src = es_str2cstr(str, NULL);
                           }

                        propName = es_newStrFromBuf("dst-ip", 6);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
			   SaganNormalizeLiblognorm->ip_dst = es_str2cstr(str, NULL);
                           }

                        propName = es_newStrFromBuf("src-port", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           cstr = es_str2cstr(str, NULL);
                           SaganNormalizeLiblognorm->src_port = atoi(cstr);
                           }

                        propName = es_newStrFromBuf("dst-port", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           cstr = es_str2cstr(str, NULL);
                           SaganNormalizeLiblognorm->dst_port = atoi(cstr);
                           }

                        propName = es_newStrFromBuf("username", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           SaganNormalizeLiblognorm->username = es_str2cstr(str, NULL);
                           }

                        propName = es_newStrFromBuf("uid", 3);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           SaganNormalizeLiblognorm->uid = es_str2cstr(str, NULL);
                           }

                        propName = es_newStrFromBuf("src-host", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           snprintf(ipbuf_src, sizeof(ipbuf_src), "%s", DNS_Lookup(es_str2cstr(str, NULL)));
                           SaganNormalizeLiblognorm->ip_src=ipbuf_src;
                           }
                       propName = es_newStrFromBuf("dst-host", 8);
                        if((field = ee_getEventField(lnevent, propName)) != NULL) {
                           str = ee_getFieldValueAsStr(field, 0);
                           snprintf(ipbuf_dst, sizeof(ipbuf_dst), "%s", DNS_Lookup(es_str2cstr(str, NULL)));
                           SaganNormalizeLiblognorm->ip_dst=ipbuf_dst;

                           }

                        free(cstr);
                        ee_deleteEvent(lnevent);
                        lnevent = NULL;
			}

pthread_mutex_unlock(&liblognorm_mutex);
return(SaganNormalizeLiblognorm);
}

#endif
