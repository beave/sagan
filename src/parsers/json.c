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

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBFASTJSON

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "debug.h"

struct _SaganCounters *counters;
struct _SaganDebug *debug;



typedef struct _JSON_Key_String _JSON_Key_String;
struct _JSON_Key_String
{
    char key[JSON_MAX_KEY_SIZE];
    char json[JSON_MAX_VALUE_SIZE];
};


void Parse_JSON ( char *syslog_string, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    struct json_object *json_obj = NULL;

    uint16_t i;
    uint16_t array_count = 1;   /* Start at one! */

    int json_count = 1;
    int new_json_count = 0;

    struct json_object_iterator it;
    struct json_object_iterator itEnd;

    char new_key[JSON_MAX_KEY_SIZE] = { 0 };
    char tmp_key[JSON_MAX_KEY_SIZE] = { 0 };

    const char *key = NULL;
    const char *val_str = NULL;
    struct json_object *val;

    struct _JSON_Key_String *JSON_Key_String;

    JSON_Key_String = malloc(sizeof(_JSON_Key_String) * JSON_MAX_NEST );

    if ( JSON_Key_String == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _JSON_Key_String", __FILE__, __LINE__);
        }

    // ZERO IT

    struct _JSON_Key_String *JSON_Key_String_J;

    JSON_Key_String_J = malloc(sizeof(_JSON_Key_String) * JSON_MAX_NEST );

    if ( JSON_Key_String_J == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Failed to allocate memory for _JSON_Key_String_J", __FILE__, __LINE__);
        }

    // ZERO IT

    SaganProcSyslog_LOCAL->json_count = 0;

    /* The raw syslog is the first "nested" level".  Copy that.  This will be the
       first entry in the array  */

    JSON_Key_String[0].key[0] = '\0';
    JSON_Key_String_J[0].key[0] = '\0';

    memcpy(JSON_Key_String[0].json, syslog_string, JSON_MAX_VALUE_SIZE);
    memcpy(JSON_Key_String_J[0].json, syslog_string, JSON_MAX_VALUE_SIZE);

    __atomic_add_fetch(&counters->json_input_count, 1, __ATOMIC_SEQ_CST);

    /* Search through all key/values looking for embedded JSON */

    while ( json_count != 0 )
        {

            for ( i = 0; i < json_count; i++ )
                {

                    new_json_count = 0;

                    json_obj = json_tokener_parse(JSON_Key_String[i].json);

                    /* Did we parse the JSON okay? */

                    if ( json_obj == NULL )
                        {

                            if ( debug->debugmalformed )
                                {
                                    Sagan_Log(WARN, "[%s, line %d] Libfastjson failed to decode JSON input. The log line was: \"%s\"", __FILE__, __LINE__, JSON_Key_String[i].json);
                                }

                            json_object_put(json_obj);

                            __atomic_add_fetch(&counters->malformed_json_input_count, 1, __ATOMIC_SEQ_CST);
                            return;
                        }

                    it = json_object_iter_begin(json_obj);
                    itEnd = json_object_iter_end(json_obj);

                    while (!json_object_iter_equal(&it, &itEnd))
                        {

                            key = json_object_iter_peek_name(&it);
                            val = json_object_iter_peek_value(&it);
                            val_str = json_object_get_string(val);

                            /* New nest ? */

                            if ( val_str[0] == '{' )
                                {
                                    /* Is this a nest within a nest? */

                                    if ( new_json_count == 0 )
                                        {
                                            snprintf(tmp_key, JSON_MAX_KEY_SIZE, ".%s", key);
                                            tmp_key[JSON_MAX_KEY_SIZE - 1] = '\0';
                                            strlcpy(new_key, tmp_key, JSON_MAX_KEY_SIZE);
                                        }
                                    else
                                        {
                                            snprintf(new_key, JSON_MAX_KEY_SIZE, ".%s", key);
                                            new_key[JSON_MAX_KEY_SIZE - 1] = '\0';
                                        }


                                    /* Store found nested JSON */

                                    strlcpy(JSON_Key_String_J[array_count].key, new_key, JSON_MAX_KEY_SIZE);
                                    strlcpy(JSON_Key_String_J[array_count].json, val_str, JSON_MAX_VALUE_SIZE);
                                    /* Continue searching array */

                                    strlcpy(JSON_Key_String[new_json_count].key, new_key, JSON_MAX_KEY_SIZE);
                                    strlcpy(JSON_Key_String[new_json_count].json, val_str, JSON_MAX_VALUE_SIZE);

                                    new_json_count++;           /* json found this loop */
                                    array_count++;              /* Total nested/json found */

                                }

                            json_object_iter_next(&it);
                        }
                }

            json_count = new_json_count;        /* Are we still finding json? */

        }  /* end of while */

    json_object_put(json_obj);

    /* Copy objects into memory */

    for (i = 0; i < array_count; i++ )
        {
            json_obj = json_tokener_parse(JSON_Key_String_J[i].json);
            it = json_object_iter_begin(json_obj);
            itEnd = json_object_iter_end(json_obj);

            while (!json_object_iter_equal(&it, &itEnd))
                {

                    key = json_object_iter_peek_name(&it);
                    val = json_object_iter_peek_value(&it);
                    val_str = json_object_get_string(val);

                    if ( val_str[0] != '{' )
                        {

                            snprintf(new_key, JSON_MAX_KEY_SIZE, "%s.%s", JSON_Key_String_J[i].key, key);
                            new_key[ JSON_MAX_KEY_SIZE - 1] = '\0';

                            strlcpy( SaganProcSyslog_LOCAL->json_key[SaganProcSyslog_LOCAL->json_count], new_key, JSON_MAX_KEY_SIZE);
                            strlcpy( SaganProcSyslog_LOCAL->json_value[SaganProcSyslog_LOCAL->json_count], val_str, JSON_MAX_VALUE_SIZE);
                            SaganProcSyslog_LOCAL->json_count++;

                        }

                    json_object_iter_next(&it);
                }
        }

    json_object_put(json_obj);
    free(JSON_Key_String);
    free(JSON_Key_String_J);

}

#endif


