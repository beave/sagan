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

/* esmtp.c
 *
 * Threaded output for e-mail support via the libesmtp.  For more information
 * about libesmtp,  please see: http://www.stafford.uklinux.net/libesmtp.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#ifdef HAVE_LIBESMTP

#include <stdio.h>
#include <signal.h>
#include <libesmtp.h>		/* Needs to be after above headers */
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "references.h"
#include "rules.h"
#include "esmtp.h"
#include "util-time.h"
#include "version.h"

extern struct _Rule_Struct *rulestruct;
extern struct _SaganDebug *debug;
extern struct _SaganConfig *config;
extern struct _SaganCounters *counters;

int ESMTP_Thread ( _Sagan_Event *Event )
{

    char tmpref[256];
    char timebuf[64];

    char tmpa[MAX_EMAILSIZE];
    char tmpb[MAX_EMAILSIZE];
    int r = 0;

    Reference_Lookup( Event->found, 0, tmpref, sizeof(tmpref));
    CreateTimeString(&Event->event_time, timebuf, sizeof(timebuf), 1);

    if ((r = snprintf(tmpa, sizeof(tmpa),
                      "MIME-Version: 1.0\r\n"
                      "Content-Type: text/plain;\r\n"
                      "Content-Transfer-Encoding: 8bit\r\n"
                      "From: %s\r\n"
                      "To: %s\r\n"
                      "Subject: %s%s\r\n"
                      "\r\n\n"
                      "[**] [%lu:%" PRIu64" ] %s [**]\n"
                      "[Classification: %s] [Priority: %d] [%s]\n"
                      "[Alert Time: %s]\n"
                      "%s %s %s:%d [%s] -> %s:%d [%s] %s %s %s\n"
                      "Syslog message: %s\r\n%s\n\r",
                      config->sagan_esmtp_from,
                      rulestruct[Event->found].email,
                      config->sagan_email_subject,
                      Event->f_msg,
                      Event->generatorid,
                      Event->sid,
                      Event->f_msg,
                      Event->class,
                      Event->pri,
                      Event->host,
                      timebuf,
                      Event->date,
                      Event->time,
                      Event->ip_src,
                      Event->src_port,
                      Event->country_src,
                      Event->ip_dst,
                      Event->dst_port,
                      Event->country_dst,
                      Event->facility,
                      Event->priority,
                      Event->program,
                      Event->message,
                      tmpref)) < 0)
        {
            Sagan_Log(NORMAL, "[%s, line %d] Cannot build mail.",  __FILE__, __LINE__);
            goto failure;
        }

    /* Start building libesmtp connection information */

    smtp_session_t session;
    smtp_message_t message;
    smtp_recipient_t recipient;

    const smtp_status_t *status;
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sigemptyset (&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction (SIGPIPE, &sa, NULL);

    if((session = smtp_create_session ()) == NULL)
        {
            Sagan_Log(WARN, "[%s, line %d] Cannot create smtp session.",  __FILE__, __LINE__);
            __atomic_add_fetch(&counters->esmtp_count_failed, 1, __ATOMIC_SEQ_CST);
            goto failure;
        }
    if((message = smtp_add_message (session)) == NULL)
        {
            Sagan_Log(WARN, "[%s, line %d] Cannot add message to smtp session.",  __FILE__, __LINE__);
            __atomic_add_fetch(&counters->esmtp_count_failed, 1, __ATOMIC_SEQ_CST);

            goto failure;
        }
    if(!smtp_set_server (session, config->sagan_esmtp_server))
        {
            Sagan_Log(WARN, "[%s, line %d] Cannot set smtp server.",  __FILE__, __LINE__);
            __atomic_add_fetch(&counters->esmtp_count_failed, 1, __ATOMIC_SEQ_CST);
            goto failure;
        }
    if((r = FixLF(config, tmpb, tmpa)) <= 0)
        {
            Sagan_Log(WARN, "[%s, line %d] Cannot FixLF.",  __FILE__, __LINE__);
            __atomic_add_fetch(&counters->esmtp_count_failed, 1, __ATOMIC_SEQ_CST);
            goto failure;
        }
    if(!smtp_set_message_str (message, tmpb))
        {
            Sagan_Log(WARN, "[%s, line %d] Cannot set message string.",  __FILE__, __LINE__);
            __atomic_add_fetch(&counters->esmtp_count_failed, 1, __ATOMIC_SEQ_CST);
            goto failure;
        }
    if(!smtp_set_reverse_path (message, config->sagan_esmtp_from))
        {
            Sagan_Log(WARN, "[%s, line %d] Cannot reverse path.",  __FILE__, __LINE__);
            __atomic_add_fetch(&counters->esmtp_count_failed, 1, __ATOMIC_SEQ_CST);
            goto failure;
        }
    if((recipient = smtp_add_recipient (message, rulestruct[Event->found].email)) == NULL)
        {
            Sagan_Log(WARN, "[%s, line %d] Cannot add recipient.",  __FILE__, __LINE__);
            __atomic_add_fetch(&counters->esmtp_count_failed, 1, __ATOMIC_SEQ_CST);
            goto failure;
        }

    if (!smtp_start_session (session))
        {
            char errtmp[128];
            smtp_strerror (smtp_errno (), errtmp, sizeof(errtmp));

            /* We log the error,  but keep going.  While SMTP failed,
             * we might be storing alerts another way
             */

            Sagan_Log(WARN, "[%s, line %d] SMTP Error: %s", __FILE__, __LINE__, smtp_strerror (smtp_errno (), errtmp, sizeof(errtmp)));
            __atomic_add_fetch(&counters->esmtp_count_failed, 1, __ATOMIC_SEQ_CST);

        }
    else
        {

            /* SMTP sent successful */

            status = smtp_message_transfer_status (message);
            __atomic_add_fetch(&counters->esmtp_count_success, 1, __ATOMIC_SEQ_CST);

            if ( debug->debugesmtp ) Sagan_Log(DEBUG, "SMTP %d %s", status->code, (status->text != NULL) ? status->text : "\n");

        }

failure:
    if (session != NULL)
        smtp_destroy_session (session);
    return(0);
}

int
FixLF( _SaganConfig *config, char *d, char *s)
{
    int sl=0;
    int i=0;
    int j=0;

    if(d == NULL)
        {
            return 0;
        }

    if(s == NULL)
        {
            d[0] = '\0';
            return 0;
        }

    if((sl=strlen(s)) >= MAX_EMAILSIZE)
        {
            s[MAX_EMAILSIZE]='\0';
            sl=MAX_EMAILSIZE;
            Sagan_Log(WARN, "[%s, line %d] Mail too large.", __FILE__, __LINE__);
        }

    for(i=0; i<sl; i++)
        {
            if(j>=MAX_EMAILSIZE)
                {
                    d[MAX_EMAILSIZE]='\0';
                    Sagan_Log(WARN, "[%s, line %d] Mail too large.", __FILE__, __LINE__);
                    break;
                }
            if(i>0 && s[i] == '\n' && s[i-1] != '\r')
                {
                    d[j++] = '\r';
                }
            d[j++] = s[i];
        }

    if(j<MAX_EMAILSIZE)
        {
            d[j++] = '\0';
        }

    return j;
}

#endif
