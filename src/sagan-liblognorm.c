/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
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
#include <json.h>
#include <lognorm.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-liblognorm.h"
#include "sagan-config.h"

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

struct _SaganCounters *counters;


/************************************************************************
 * Sagan_Liblognorm_Load
 *
 * Load in the normalization files into memory
 ************************************************************************/

void Sagan_Liblognorm_Load(void)
{

    int i;

    SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));
    memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));

    if((ctx = ln_initCtx()) == NULL) Sagan_Log(S_ERROR, "[%s, line %d] Cannot initialize liblognorm context.", __FILE__, __LINE__);

    for (i=0; i < counters->liblognormtoload_count; i++)
        {
            Sagan_Log(S_NORMAL, "Loading %s for normalization.", liblognormtoloadstruct[i].filepath);
            if (stat(liblognormtoloadstruct[i].filepath, &liblognorm_fileinfo)) Sagan_Log(S_ERROR, "%s was not fonnd.", liblognormtoloadstruct[i].filepath);
            ln_loadSamples(ctx, liblognormtoloadstruct[i].filepath);
        }

}

/***********************************************************************
 * sagan_normalize_liblognom
 *
 * Locates interesting log data via Rainer's liblognorm library
 ***********************************************************************/

void Sagan_Normalize_Liblognorm(char *syslog_msg)
{

    char buf[10*1024] = { 0 };
/*    char tmp_host[254] = { 0 }; */

    const char *cstr = NULL;
    const char *tmp = NULL;

    struct json_object *json = NULL;

    SaganNormalizeLiblognorm->ip_src[0] = '0';
    SaganNormalizeLiblognorm->ip_src[1] = '\0';
    SaganNormalizeLiblognorm->ip_dst[0] = '0';
    SaganNormalizeLiblognorm->ip_dst[1] = '\0';

    SaganNormalizeLiblognorm->src_host[0] = '\0';
    SaganNormalizeLiblognorm->dst_host[0] = '\0';

    snprintf(buf, sizeof(buf),"%s", syslog_msg);

    ln_normalize(ctx, buf, strlen(buf), &json);

    //int ln_normalize(ln_ctx ctx, const char *str, size_t strLen, struct json_object **json_p);

    cstr = (char*)json_object_to_json_string(json);

    /* Get source address information */

    tmp = json_object_get_string(json_object_object_get(json, "src-ip"));
    if ( tmp != NULL) snprintf(SaganNormalizeLiblognorm->ip_src, sizeof(SaganNormalizeLiblognorm->ip_src), "%s", tmp);

    tmp = json_object_get_string(json_object_object_get(json, "dst-ip"));
    if ( tmp != NULL ) snprintf(SaganNormalizeLiblognorm->ip_dst, sizeof(SaganNormalizeLiblognorm->ip_dst), "%s", tmp);

    /* Make sure it returns something values,  if not, populate with config->sagan_host */

    if (!strcmp(SaganNormalizeLiblognorm->ip_src, "127.0.0.1" ) ||
            !strcmp(SaganNormalizeLiblognorm->ip_src, "")) strlcpy(SaganNormalizeLiblognorm->ip_src, config->sagan_host, sizeof(SaganNormalizeLiblognorm->ip_src));

    if (!strcmp(SaganNormalizeLiblognorm->ip_dst, "127.0.0.1" ) ||
            !strcmp(SaganNormalizeLiblognorm->ip_dst, "")) strlcpy(SaganNormalizeLiblognorm->ip_dst, config->sagan_host, sizeof(SaganNormalizeLiblognorm->ip_dst));

    /* Get username information (not currently used) 

    tmp = json_object_get_string(json_object_object_get(json, "username"));
    if ( tmp != NULL ) snprintf(SaganNormalizeLiblognorm->username, sizeof(SaganNormalizeLiblognorm->username), "%s", tmp);

    */

    /* Do DNS lookup for source hostname */

    tmp = json_object_get_string(json_object_object_get(json, "src-host"));

    if ( tmp != NULL )
        strlcpy(SaganNormalizeLiblognorm->src_host, tmp, sizeof(SaganNormalizeLiblognorm->src_host));


    tmp = json_object_get_string(json_object_object_get(json, "dst-host"));

    if ( tmp != NULL )
        strlcpy(SaganNormalizeLiblognorm->dst_host, tmp, sizeof(SaganNormalizeLiblognorm->dst_host));


/*
        if ( tmp != NULL && strcmp(tmp, "::1") && strcmp(tmp, "localhost") && strcmp(tmp, "127.0.0.1"))
            {
*/

	      /* Avoid const char * warning */

/*              snprintf(tmp_host, sizeof(tmp_host), "%s", tmp); 	
                strlcpy(SaganNormalizeLiblognorm->ip_src, DNS_Lookup(tmp_host), sizeof(SaganNormalizeLiblognorm->ip_src));
             }
*/

    /*
        tmp = json_object_get_string(json_object_object_get(json, "dst-host"));

        if ( tmp != NULL && strcmp(tmp, "::1") && strcmp(tmp, "localhost") && strcmp(tmp, "127.0.0.1"))
            {
*/
	    
	    /* Avoid const char * warning */

/*
              snprintf(tmp_host, sizeof(tmp_host), "%s", tmp);        
              strlcpy(SaganNormalizeLiblognorm->ip_dst, DNS_Lookup(tmp_host), sizeof(SaganNormalizeLiblognorm->ip_dst));
        }

*/

    /* Get port information */

    tmp = json_object_get_string(json_object_object_get(json, "src-port"));
    if ( tmp != NULL ) SaganNormalizeLiblognorm->src_port = atoi(tmp);

    tmp = json_object_get_string(json_object_object_get(json, "dst-port"));
    if ( tmp != NULL )  SaganNormalizeLiblognorm->dst_port = atoi(tmp);

    if ( debug->debugnormalize )
        {
            Sagan_Log(S_DEBUG, "Liblognorm DEBUG output:");
            Sagan_Log(S_DEBUG, "---------------------------------------------------");
            Sagan_Log(S_DEBUG, "Log message to normalize: %s", syslog_msg);
            Sagan_Log(S_DEBUG, "Parsed: %s", cstr);
            Sagan_Log(S_DEBUG, "Source IP: %s", SaganNormalizeLiblognorm->ip_src);
            Sagan_Log(S_DEBUG, "Destination IP: %s", SaganNormalizeLiblognorm->ip_dst);
            Sagan_Log(S_DEBUG, "Source Port: %d", SaganNormalizeLiblognorm->src_port);
            Sagan_Log(S_DEBUG, "Destination Port: %d", SaganNormalizeLiblognorm->dst_port);
            Sagan_Log(S_DEBUG, "Source Host: %s", SaganNormalizeLiblognorm->src_host);
            Sagan_Log(S_DEBUG, "Destination Host: %s", SaganNormalizeLiblognorm->dst_host);
//     Sagan_Log(S_DEBUG, "Username: %s", SaganNormalizeLiblognorm->username);
            Sagan_Log(S_DEBUG, "");
        }


    json_object_put(json);
}

#endif
