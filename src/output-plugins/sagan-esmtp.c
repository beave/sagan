/*
** Copyright (C) 2009-2010 Softwink, Inc. 
** Copyright (C) 2009-2010 Champ Clark III <champ@softwink.com>
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

/* sagan-esmtp.c 
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

#include "sagan.h"
#include "version.h"

char *data=NULL;
char sagan_path[255];

char sagan_esmtp_from[ESMTPFROM];
char sagan_esmtp_to[ESMTPTO];
char sagan_esmtp_server[ESMTPSERVER];
int threademailc;

void *sagan_esmtp_thread( void *emailthreadargs ) {

pthread_mutex_t email_mutex = PTHREAD_MUTEX_INITIALIZER;

struct email_thread_args * emailargs = (struct email_thread_args *) emailthreadargs;

char subject[255];
char tmpdata[MAX_EMAILSIZE];
char *host = NULL;

const char *sdn = sagan_path;
char sfn[MAXPATH];
FILE *sfp;

/* I absolutely hate this part.   We create a tmp file for storing the alert
 * data.  This should all be done in memory,  without a tmp file!  However,
 * the code to do that resulted in e-mails proper content (not NULL) about 
 * 80% of the time.  No, I'm not sure why.  Yes,  it was probably something
 * I was doing wrong with libesmtp.
 */

snprintf(sfn, sizeof(sfn), "%s/sagan-esmtp-XXXXXXX", sdn);
int fd = mkstemp(sfn);

sfp = fdopen(fd, "w+");
if (sfp == NULL) {
  close(fd);
  removelockfile();
  sagan_log(1, "[%s, line %d] Unable to open temporary file for Sagan libesmtp support", __FILE__, __LINE__);
}

snprintf(tmpdata, sizeof(tmpdata), "\r\n\n[**] [%s] %s [**]\n[Classification: %s] [Priority: %d]\n%s %s %s:%d -> %s:%d %s %s\n\nSyslog message: %s\n\r", emailargs->sid, emailargs->msg, emailargs->classtype, emailargs->pri, emailargs->date, emailargs->time, emailargs->ip_src, emailargs->src_port, emailargs->ip_dst, emailargs->dst_port, emailargs->facility, emailargs->fpri, emailargs->sysmsg);
data = tmpdata;
fprintf(sfp, "%s", tmpdata);	

/* Start building libesmtp connection information */

smtp_session_t session;
smtp_message_t message;
smtp_recipient_t recipient;

const smtp_status_t *status;
struct sigaction sa;

session = smtp_create_session ();
message = smtp_add_message (session);

sa.sa_handler = SIG_IGN;
sigemptyset (&sa.sa_mask);
sa.sa_flags = 0;
sigaction (SIGPIPE, &sa, NULL);

smtp_set_server (session, host ? host : sagan_esmtp_server);
snprintf(subject, sizeof(subject), "[Sagan] %s", emailargs->msg);
smtp_set_reverse_path (message, sagan_esmtp_from);
smtp_set_header (message, "To", NULL, NULL);
smtp_set_header (message, "Subject", subject);
smtp_set_header_option (message, "Subject", Hdr_OVERRIDE, 1);

smtp_set_messagecb (message, esmtp_cb, sfp );

recipient = smtp_add_recipient (message, sagan_esmtp_to);

if (!smtp_start_session (session)) {
   char errtmp[128];
   smtp_strerror (smtp_errno (), errtmp, sizeof(errtmp)); 

   /* We log the error,  but keep going.  While SMTP failed,  
    * we might be storing alerts another way 
    */

   sagan_log(0, "[%s, line %d] SMTP Error: %s", __FILE__, __LINE__, smtp_strerror (smtp_errno (), errtmp, sizeof(errtmp)));

   } else {

   /* SMTP sent successful */

status = smtp_message_transfer_status (message);
}


if (unlink(sfn) == -1) {
  removelockfile();
  sagan_log(1, "[%s, line %d] Cannot remove temporary file %s", __FILE__, __LINE__, sfn );
}

fclose(sfp);

smtp_destroy_session (session);

pthread_mutex_lock ( &email_mutex );
threademailc--;
pthread_mutex_unlock ( &email_mutex );


pthread_exit(NULL);

}


const char *esmtp_cb (void **buf, int *len, void *arg)
{

  int octets;

  if (*buf == NULL)
    *buf = malloc (BUFLEN);

  if (len == NULL)
    {
      rewind ((FILE *) arg);
      return NULL;
    }

  if (fgets (*buf, BUFLEN - 2, (FILE *) arg) == NULL)
    octets = 0;
  else
    {
      char *p = strchr (*buf, '\0');

      if (p[-1] == '\n' && p[-2] != '\r')
        {
          strlcpy (p - 1, "\r\n", sizeof(p));
          p++;
        }
      octets = p - (char *) *buf;
    }
  *len = octets;
  return *buf;
}

#endif

