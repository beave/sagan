/*
** Copyright (C) 2009-2019 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2019 Champ Clark III <cclark@quadrantsec.com>
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

/* output.c
*
* This becomes a threaded operation.  This handles all I/O intensive output plugins
*/
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

#include "sagan.h"
#include "output.h"
#include "rules.h"
#include "sagan-config.h"

#include "output-plugins/alert.h"
#include "output-plugins/external.h"
#include "output-plugins/fast.h"
#include "output-plugins/eve.h"

#ifdef WITH_SNORTSAM
#include "output-plugins/snortsam.h"
#endif

#ifdef WITH_SYSLOG
#include "output-plugins/syslog-handler.h"
#endif

#ifdef HAVE_LIBESMTP
#include "output-plugins/esmtp.h"
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
#include "output-plugins/unified2.h"
uint64_t unified_event_id;
#endif

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganConfig *config;

bool nonthread_alert_lock = false;

pthread_mutex_t SaganOutputNonThreadMutex=PTHREAD_MUTEX_INITIALIZER;

void Output( _Sagan_Event *Event )
{

    /******************************/
    /* Single threaded operations */
    /******************************/

    /* Single threaded */

    pthread_mutex_lock(&SaganOutputNonThreadMutex);
    nonthread_alert_lock = true;

    if ( config->alert_flag )
        {
            Alert_File(Event);
        }

    if ( config->eve_flag && config->eve_alerts && rulestruct[Event->found].xbit_noeve == false )
        {
            Alert_JSON(Event);
        }

    if ( config->fast_flag )
        {
            Fast_File(Event);
        }

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)

    if ( config->sagan_unified2_flag && rulestruct[Event->found].xbit_nounified2 == false )
        {

            Unified2( Event );
            Unified2LogPacketAlert( Event );

            if ( Event->host[0] != '\0' )
                {
                    Unified2WriteExtraData( Event, Is_IP(Event->host, IPv6) ?  EVENT_INFO_XFF_IPV6 : EVENT_INFO_XFF_IPV4 );
                }

            /* Write IPv6 data to "extra" data */

            if ( Is_IP(Event->ip_src, IPv6 ) )
                {
                    Unified2WriteExtraData( Event, EVENT_INFO_IPV6_SRC );
                }

            if ( Is_IP(Event->ip_dst, IPv6 ) )
                {
                    Unified2WriteExtraData( Event, EVENT_INFO_IPV6_DST );
                }

            /* These get normalized in engine.c and passed via
             * send-alert.c.  When adding more,  remember to add
             * them there! */

            if ( Event->normalize_http_uri != NULL )
                {
                    Unified2WriteExtraData( Event, EVENT_INFO_HTTP_URI );
                }

            if ( Event->normalize_http_hostname != NULL )
                {
                    Unified2WriteExtraData( Event, EVENT_INFO_HTTP_HOSTNAME );
                }

            unified_event_id++;
        }

#endif

    nonthread_alert_lock = false;
    pthread_mutex_unlock(&SaganOutputNonThreadMutex);

    /* End single threaded */

    /****************************************************************************/
    /* Syslog output                                                            */
    /****************************************************************************/

#ifdef WITH_SYSLOG

    if ( config->sagan_syslog_flag )
        {
            Alert_Syslog( Event );
        }

#endif

    /****************************************************************************/
    /* Snortsam Support	                                                        */
    /****************************************************************************/

    /* If we have a snortsam server && the rule requires snortsam..... */

#ifdef WITH_SNORTSAM

    if ( config->sagan_fwsam_flag && rulestruct[Event->found].fwsam_src_or_dst )
        {
            FWSam( Event );
        }

#endif

    /****************************************************************************/
    /* SMTP/Email support (libesmtp)                                            */
    /****************************************************************************/

#ifdef HAVE_LIBESMTP

    if ( config->sagan_esmtp_flag && rulestruct[Event->found].email_flag )
        {
            ESMTP_Thread( Event );
        }

#endif

    /****************************************************************************/
    /* External program via rule                                                */
    /****************************************************************************/

    if (  rulestruct[Event->found].external_flag )
        {
            External_Thread( Event, rulestruct[Event->found].external_program );
        }
}

