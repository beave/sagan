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

void Parse_JSON ( char *syslog_string, struct _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL )
{

    struct json_object *json_obj = NULL;

    uint16_t i;
    uint16_t json_count = 1;

    struct json_object_iterator it;
    struct json_object_iterator itEnd;

    const char *key = NULL;
    const char *val_str = NULL;

    struct json_object *val;

    /* The raw syslog is the first "nested" level".  Copy that.  This will be the
       first entry in the array  */

    json_count = 1;

    SaganProcSyslog_LOCAL->json_key[0][0] = '\0';
    strlcpy(SaganProcSyslog_LOCAL->json_value[0], syslog_string, sizeof(SaganProcSyslog_LOCAL->json_value[0]));

    for (i = 0; i < json_count; i++ )
        {


            if ( SaganProcSyslog_LOCAL->json_value[i][0] == '{' || SaganProcSyslog_LOCAL->json_value[i][1] == '{' )
                {

                    json_obj = json_tokener_parse(SaganProcSyslog_LOCAL->json_value[i]);

                    if ( json_obj != NULL )
                        {

                            it = json_object_iter_begin(json_obj);
                            itEnd = json_object_iter_end(json_obj);

                            while (!json_object_iter_equal(&it, &itEnd))
                                {

                                    key = json_object_iter_peek_name(&it);
                                    val = json_object_iter_peek_value(&it);
                                    val_str = json_object_get_string(val);

                                    snprintf(SaganProcSyslog_LOCAL->json_key[json_count], sizeof(SaganProcSyslog_LOCAL->json_key[json_count]), "%s.%s", SaganProcSyslog_LOCAL->json_key[i], key);
                                    SaganProcSyslog_LOCAL->json_key[json_count][sizeof(SaganProcSyslog_LOCAL->json_key[json_count]) - 1] = '\0';
                                    strlcpy(SaganProcSyslog_LOCAL->json_value[json_count], val_str, sizeof(SaganProcSyslog_LOCAL->json_value[json_count]));

                                    json_count++;

                                    json_object_iter_next(&it);

                                }
                        }

                    json_object_put(json_obj);

                }
        }


    SaganProcSyslog_LOCAL->json_count = json_count;

}

#endif


