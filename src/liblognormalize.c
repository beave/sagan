/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
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

/* liblognormalize.c
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
#include <json.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "liblognormalize.h"
#include "sagan-config.h"

struct _SaganConfig *config;
struct _SaganDebug *debug;

struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm = NULL;

/************************************************************************
 * liblognorm GLOBALS
 ************************************************************************/

struct stat liblognorm_fileinfo;
struct liblognorm_toload_struct *liblognormtoloadstruct;
int liblognorm_count;

static ln_ctx ctx;

struct _SaganCounters *counters;


/************************************************************************
 * Liblognorm_Load
 *
 * Load in the normalization files into memory
 ************************************************************************/

void Liblognorm_Load(char *infile)
{

    SaganNormalizeLiblognorm = malloc(sizeof(struct _SaganNormalizeLiblognorm));

    if ( SaganNormalizeLiblognorm == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for SaganNormalizeLiblognorm. Abort!", __FILE__, __LINE__);
        }

    memset(SaganNormalizeLiblognorm, 0, sizeof(_SaganNormalizeLiblognorm));

    if((ctx = ln_initCtx()) == NULL)
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot initialize liblognorm context.", __FILE__, __LINE__);
        }

    Sagan_Log(NORMAL, "Loading %s for normalization.", infile);

    /* Remember - On reload,  file access will be by the "sagan" user! */

    if (stat(infile, &liblognorm_fileinfo))
        {
            Sagan_Log(ERROR, "[%s, line %d] Error accessing '%s'. Abort.", __FILE__, __LINE__, infile);
        }

    ln_loadSamples(ctx, infile);

}

/***********************************************************************
 * sagan_normalize_liblognom
 *
 * Locates interesting log data via Rainer's liblognorm library
 ***********************************************************************/

void Normalize_Liblognorm(char *syslog_msg, struct _SaganNormalizeLiblognorm *SaganNormalizeLiblognorm)
{

    char buf[MAX_SYSLOGMSG] = { 0 };
    char tmp_host[254] = { 0 };

    int rc_normalize = 0;

    const char *cstr = NULL;
    const char *tmp = NULL;

    struct json_object *json = NULL;
    struct json_object *string_obj = NULL;

    SaganNormalizeLiblognorm->status = false;

    SaganNormalizeLiblognorm->ip_src[0] = '0';
    SaganNormalizeLiblognorm->ip_src[1] = '\0';
    SaganNormalizeLiblognorm->ip_dst[0] = '0';
    SaganNormalizeLiblognorm->ip_dst[1] = '\0';

    SaganNormalizeLiblognorm->username[0] = '\0';
    SaganNormalizeLiblognorm->src_host[0] = '\0';
    SaganNormalizeLiblognorm->dst_host[0] = '\0';

    SaganNormalizeLiblognorm->hash_sha1[0] = '\0';
    SaganNormalizeLiblognorm->hash_sha256[0] = '\0';
    SaganNormalizeLiblognorm->hash_md5[0] = '\0';

    SaganNormalizeLiblognorm->http_uri[0] = '\0';
    SaganNormalizeLiblognorm->http_hostname[0] = '\0';

    SaganNormalizeLiblognorm->ja3[0] = '\0';
    SaganNormalizeLiblognorm->event_id[0] = '\0';

    SaganNormalizeLiblognorm->src_port = 0;
    SaganNormalizeLiblognorm->dst_port = 0;

    SaganNormalizeLiblognorm->json_normalize[0] = '\0';

    snprintf(buf, sizeof(buf),"%s", syslog_msg);

    /* int ln_normalize(ln_ctx ctx, const char *str, size_t strLen, struct json_object **json_p); */

    rc_normalize = ln_normalize(ctx, buf, strlen(buf), &json);

    if (json == NULL)
        {
            return;
        }

    cstr = (char*)json_object_to_json_string(json);

    /* Get source address information */

    json_object_object_get_ex(json, "src-ip", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL)
        {
            snprintf(SaganNormalizeLiblognorm->ip_src, sizeof(SaganNormalizeLiblognorm->ip_src), "%s", tmp);
        }

    json_object_object_get_ex(json, "dst-ip", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            snprintf(SaganNormalizeLiblognorm->ip_dst, sizeof(SaganNormalizeLiblognorm->ip_dst), "%s", tmp);
            SaganNormalizeLiblognorm->status = true;
        }

    /* Get username information - Will be used in the future */

    json_object_object_get_ex(json, "username", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            snprintf(SaganNormalizeLiblognorm->username, sizeof(SaganNormalizeLiblognorm->username), "%s", tmp);
            SaganNormalizeLiblognorm->status = true;
        }


    /* Do DNS lookup for source hostname */

    json_object_object_get_ex(json, "src-host", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->src_host, tmp, sizeof(SaganNormalizeLiblognorm->src_host));
            SaganNormalizeLiblognorm->status = true;

            if ( SaganNormalizeLiblognorm->ip_src[0] == '0' && config->syslog_src_lookup)
                {

                    if (!DNS_Lookup(SaganNormalizeLiblognorm->src_host, tmp_host, sizeof(tmp_host)))
                        {
                            strlcpy(SaganNormalizeLiblognorm->ip_src, tmp_host, sizeof(SaganNormalizeLiblognorm->ip_src));
                        }

                }

        }

    json_object_object_get_ex(json, "dst-host", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->dst_host, tmp, sizeof(SaganNormalizeLiblognorm->dst_host));
            SaganNormalizeLiblognorm->status = true;

            if ( SaganNormalizeLiblognorm->ip_dst[0] == '0' && config->syslog_src_lookup)
                {

                    if (!DNS_Lookup(SaganNormalizeLiblognorm->dst_host, tmp_host, sizeof(tmp_host)))
                        {
                            strlcpy(SaganNormalizeLiblognorm->ip_dst, tmp_host, sizeof(SaganNormalizeLiblognorm->ip_dst));
                        }
                }
        }

    /* Get port information */

    json_object_object_get_ex(json, "src-port", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            SaganNormalizeLiblognorm->src_port = atoi(tmp);
            SaganNormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "dst-port", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            SaganNormalizeLiblognorm->dst_port = atoi(tmp);
            SaganNormalizeLiblognorm->status = true;
        }


    json_object_object_get_ex(json, "hash-md5", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->hash_md5, tmp, sizeof(SaganNormalizeLiblognorm->hash_md5));
            SaganNormalizeLiblognorm->status = true;
        }


    json_object_object_get_ex(json, "hash-sha1", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->hash_sha1, tmp, sizeof(SaganNormalizeLiblognorm->hash_sha1));
            SaganNormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "hash-sha256", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->hash_sha256, tmp, sizeof(SaganNormalizeLiblognorm->hash_sha256));
            SaganNormalizeLiblognorm->status = true;
        }


    json_object_object_get_ex(json, "http_uri", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->http_uri, tmp, sizeof(SaganNormalizeLiblognorm->http_uri));
            SaganNormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "http_hostname", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->http_hostname, tmp, sizeof(SaganNormalizeLiblognorm->http_hostname));
            SaganNormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "filename", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->filename, tmp, sizeof(SaganNormalizeLiblognorm->filename));
            SaganNormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "ja3", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->ja3, tmp, sizeof(SaganNormalizeLiblognorm->ja3));
            SaganNormalizeLiblognorm->status = true;
        }

    json_object_object_get_ex(json, "event_id", &string_obj);
    tmp = json_object_get_string(string_obj);

    if ( tmp != NULL )
        {
            strlcpy(SaganNormalizeLiblognorm->event_id, tmp, sizeof(SaganNormalizeLiblognorm->event_id));
            SaganNormalizeLiblognorm->status = true;
        }

    strlcpy(SaganNormalizeLiblognorm->json_normalize, json_object_to_json_string_ext(json, FJSON_TO_STRING_PLAIN), sizeof(SaganNormalizeLiblognorm->json_normalize) );

    if ( debug->debugnormalize )
        {

            Sagan_Log(DEBUG, "Liblognorm DEBUG output: %d", rc_normalize);
            Sagan_Log(DEBUG, "---------------------------------------------------");
            Sagan_Log(DEBUG, "Status: %s", SaganNormalizeLiblognorm->status == true ? "true":"false");
            Sagan_Log(DEBUG, "Log message to normalize: |%s|", syslog_msg);
            Sagan_Log(DEBUG, "Parsed: %s", SaganNormalizeLiblognorm->json_normalize);
            Sagan_Log(DEBUG, "Source IP: %s", SaganNormalizeLiblognorm->ip_src);
            Sagan_Log(DEBUG, "Destination IP: %s", SaganNormalizeLiblognorm->ip_dst);
            Sagan_Log(DEBUG, "Source Port: %d", SaganNormalizeLiblognorm->src_port);
            Sagan_Log(DEBUG, "Destination Port: %d", SaganNormalizeLiblognorm->dst_port);
            Sagan_Log(DEBUG, "Source Host: %s", SaganNormalizeLiblognorm->src_host);
            Sagan_Log(DEBUG, "Destination Host: %s", SaganNormalizeLiblognorm->dst_host);
            Sagan_Log(DEBUG, "Username: %s", SaganNormalizeLiblognorm->username);
            Sagan_Log(DEBUG, "MD5 Hash: %s", SaganNormalizeLiblognorm->hash_md5);
            Sagan_Log(DEBUG, "SHA1 Hash: %s", SaganNormalizeLiblognorm->hash_sha1);
            Sagan_Log(DEBUG, "SHA265 Hash: %s", SaganNormalizeLiblognorm->hash_sha256);
            Sagan_Log(DEBUG, "HTTP URI: %s", SaganNormalizeLiblognorm->http_uri);
            Sagan_Log(DEBUG, "HTTP HOSTNAME: %s", SaganNormalizeLiblognorm->http_hostname);
            Sagan_Log(DEBUG, "Filename: %s", SaganNormalizeLiblognorm->filename);
            Sagan_Log(DEBUG, "JA3: %s",  SaganNormalizeLiblognorm->ja3);
            Sagan_Log(DEBUG, "Event ID: %s",  SaganNormalizeLiblognorm->event_id);

            Sagan_Log(DEBUG, "");
        }


    json_object_put(json);
    json_object_put(string_obj);
}

#endif
