#include <stdio.h>
#include "sagan.h"

unsigned long long int sagantotal;
unsigned long long int saganfound;
unsigned long long int sagandrop;
unsigned long long threshold_total;

char sagan_extern[MAXPATH];

#ifdef HAVE_LIBESMTP
char sagan_esmtp_server[ESMTPSERVER];
#endif

int threadmaxextc;
int threadmaxdbc;
int  dbtype;
int  logzilla_log;
int threadmaxlogzillac;
int threadmaxemailc;

void sagan_statistics() { 


                 sagan_log(0, "Total number of events processed: %lu", sagantotal);
                    sagan_log(0, "Total number of events thresholded: %lu", threshold_total);
                    sagan_log(0, "Total number of signatures matched: %lu", saganfound);

                    if ( strcmp(sagan_extern, "" )) sagan_log(0, "Max external threads reached: %d", threadmaxextc);

#if defined(HAVE_LIBMYSQLCLIENT_R) || defined(HAVE_LIBPQ)
                       if ( dbtype != 0 ) {
                       sagan_log(0, "Max database threads reached: %d", threadmaxdbc);
                       }

                       if ( logzilla_log != 0 ) sagan_log(0, "Max Logzilla threads reached: %d", threadmaxlogzillac );
#endif

#ifdef HAVE_LIBESMTP
                       if ( strcmp(sagan_esmtp_server, "" )) sagan_log(0, "Max SMTP threads reached: %d", threadmaxemailc);
#endif
                    sagan_log(0, "Events dropped: %d", sagandrop);

}
