/*
** Copyright (C) 2009-2018 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2018 Champ Clark III <cclark@quadrantsec.com>
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

/* Read data from Sagan's traditional pipe delimited format */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "version.h"
#include "input-pipe.h"

struct _SaganCounters *counters;
struct _SaganDebug *debug;
struct _SaganConfig *config;
struct _SaganDNSCache *dnscache;

void SyslogInput_Pipe( char *syslog_string, struct _SyslogInput *SyslogInput )
{

    bool dns_flag;

    char src_dns_lookup[20] = { 0 };

    int i;
    int rc;

    memset(SyslogInput, 0, sizeof(_SyslogInput));

    SyslogInput->syslog_host = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    /* If we're using DNS (and we shouldn't be!),  we start DNS checks and lookups
     * here.  We cache both good and bad lookups to not over load our DNS server(s).
     * The only way DNS cache can be cleared is to restart Sagan */

    if (config->syslog_src_lookup )
        {

            if ( !Is_IP(SyslogInput->syslog_host, IPv4) || !Is_IP(SyslogInput->syslog_host, IPv6) )   	/* Is inbound a valid IP? */
                {
                    dns_flag = false;

                    for(i=0; i <= counters->dns_cache_count ; i++)  			/* Check cache first */
                        {
                            if (!strcmp( dnscache[i].hostname, SyslogInput->syslog_host))
                                {
                                    SyslogInput->syslog_host = dnscache[i].src_ip;
                                    dns_flag = true;
                                }
                        }

                    /* If entry was not found in cache,  look it up */

                    if ( dns_flag == false )
                        {

                            /* Do a DNS lookup */

                            rc = DNS_Lookup(SyslogInput->syslog_host, src_dns_lookup, sizeof(src_dns_lookup));

                            /* Invalid lookups get the config->sagan_host value */

                            if ( rc == -1 )
                                {

                                    strlcpy(src_dns_lookup, config->sagan_host, sizeof(src_dns_lookup));
                                    counters->dns_miss_count++;

                                }


                            /* Add entry to DNS Cache */

                            dnscache = (_SaganDNSCache *) realloc(dnscache, (counters->dns_cache_count+1) * sizeof(_SaganDNSCache));

                            if ( dnscache == NULL )
                                {

                                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for dnscache. Abort!", __FILE__, __LINE__);

                                }

                            memset(&dnscache[counters->dns_cache_count], 0, sizeof(_SaganDNSCache));

                            strlcpy(dnscache[counters->dns_cache_count].hostname, SyslogInput->syslog_host, sizeof(dnscache[counters->dns_cache_count].hostname));
                            strlcpy(dnscache[counters->dns_cache_count].src_ip, src_dns_lookup, sizeof(dnscache[counters->dns_cache_count].src_ip));
                            counters->dns_cache_count++;
                            SyslogInput->syslog_host = src_dns_lookup;

                        }
                }

        }
    else
        {

            /* We check to see if values from our FIFO are valid.  If we aren't doing DNS related
            * stuff (above),  we start basic check with the SyslogInput->syslog_host */

            if (SyslogInput->syslog_host == NULL || !Is_IP(SyslogInput->syslog_host, IPv4) || !Is_IP(SyslogInput->syslog_host, IPv6) )
                {
                    SyslogInput->syslog_host = config->sagan_host;

                    counters->malformed_host++;

                    if ( debug->debugmalformed )
                        {
                            Sagan_Log(DEBUG, "Sagan received a malformed 'host': '%s' (replaced with %s)", SyslogInput->syslog_host, config->sagan_host);
                            Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                        }
                }
        }


    /* We now check the rest of the values */

    SyslogInput->syslog_facility = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( SyslogInput->syslog_facility == NULL )
        {

            SyslogInput->syslog_facility = "SAGAN: FACILITY ERROR";

            counters->malformed_facility++;

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'facility' from %s.", SyslogInput->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }

    SyslogInput->syslog_priority = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( SyslogInput->syslog_priority == NULL )
        {

            SyslogInput->syslog_priority = "SAGAN: PRIORITY ERROR";

            counters->malformed_priority++;

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'priority' from %s.", SyslogInput->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }

    SyslogInput->syslog_level = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( SyslogInput->syslog_level == NULL )
        {

            SyslogInput->syslog_level = "SAGAN: LEVEL ERROR";

            counters->malformed_level++;

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'level' from %s.", SyslogInput->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }

    SyslogInput->syslog_tag = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( SyslogInput->syslog_tag == NULL )
        {

            SyslogInput->syslog_tag = "SAGAN: TAG ERROR";

            counters->malformed_tag++;

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'tag' from %s.", SyslogInput->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }

    SyslogInput->syslog_date = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( SyslogInput->syslog_date == NULL )
        {

            SyslogInput->syslog_date = "SAGAN: DATE ERROR";

            counters->malformed_date++;

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'date' from %s.", SyslogInput->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }

    SyslogInput->syslog_time = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( SyslogInput->syslog_time == NULL )
        {

            SyslogInput->syslog_time = "SAGAN: TIME ERROR";

            counters->malformed_time++;

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'time' from %s.", SyslogInput->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }
        }


    SyslogInput->syslog_program = syslog_string != NULL ? strsep(&syslog_string, "|") : NULL;

    if ( SyslogInput->syslog_program == NULL )
        {

            SyslogInput->syslog_program = "SAGAN: PROGRAM ERROR";

            counters->malformed_program++;

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'program' from %s.", SyslogInput->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);

                }
        }

    SyslogInput->syslog_message = syslog_string != NULL ? strsep(&syslog_string, "") : NULL; /* In case the message has | in it,  we delimit on "" */

    if (  SyslogInput->syslog_message == NULL )
        {

            SyslogInput->syslog_message = "SAGAN: MESSAGE ERROR";

            counters->malformed_message++;

            if ( debug->debugmalformed )
                {
                    Sagan_Log(DEBUG, "Sagan received a malformed 'message' from %s.", SyslogInput->syslog_host);
                    Sagan_Log(DEBUG, "Raw malformed log: \"%s\"", syslog_string);
                }

            /* If the message is lost,  all is lost.  Typically,  you don't lose part of the message,
             * it's more likely to lose all  - Champ Clark III 11/17/2011 */

            counters->sagan_log_drop++;

        }

    /* Strip any \n or \r from the syslog_message */

    if ( strcspn ( SyslogInput->syslog_message, "\n" ) < strlen( SyslogInput->syslog_message ) )
        {
            SyslogInput->syslog_message[strcspn (  SyslogInput->syslog_message, "\n" )] = '\0';
        }



}

