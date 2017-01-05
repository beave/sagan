/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-alert-json.c
 *
 * Write alerts in a JSON/Suricata like format
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
//#include <stdlib.h>
//#include <pthread.h>
//#include <string.h>

#include "sagan.h"
#include "sagan-json.h"
#include "sagan-eve.h"
//#include "sagan-references.h"
#include "sagan-config.h"

struct _SaganConfig *config;

void Sagan_Alert_JSON( _Sagan_Event *event )
{

    char alert_data[1024];

    strlcpy(alert_data, (const char*)Format_Sagan_JSON_Alert(event), sizeof(alert_data));
    fprintf(config->eve_stream, "%s\n", alert_data);

    fflush(config->eve_stream);

}
