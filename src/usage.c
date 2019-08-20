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

/* usage.c
 *
 * Gives the user basic operation of the sagan binary.  Also displays
 * information of compile time options
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>

#include "sagan.h"
#include "version.h"

void Usage(void)
{
    fprintf(stderr, "\n--[Sagan version %s | Help/usage screen]--------------------------------\n\n", VERSION);
    fprintf(stderr, "-h, --help\t\tHelp (this screen).\n");
    fprintf(stderr, "-C, --credits\t\tSagan credits.\n");
    fprintf(stderr, "-d, --debug [type]\tTypes: engine, syslog, load, fwsam, external, threads,ipc, limits, malformed, xbit, flexbit, brointel, parse_ip, client-stats");

#ifdef HAVE_LIBESMTP
    fprintf(stderr, ", smtp");
#endif

#ifdef HAVE_LIBLOGNORM
    fprintf(stderr, ", normalize");
#endif

#ifdef HAVE_LIBPCAP
    fprintf(stderr, ", plog");
#endif

#ifdef WITH_BLUEDOT
    fprintf(stderr, ", bluedot");
#endif

#ifdef HAVE_LIBMAXMINDDB
    fprintf(stderr, ", geoip");
#endif

#ifdef HAVE_LIBHIREDIS
    fprintf(stderr, ", redis");
#endif

#if defined(HAVE_LIBFASTJSON) || defined(HAVE_LIBLOGNORM)
    fprintf(stderr, ", json");
#endif

    fprintf(stderr, ".\n");

    fprintf(stderr, "-D, --daemon\t\tMake process a daemon (fork to the background).\n");
    fprintf(stderr, "-u, --user [username]\tRun as user (defaults to 'sagan').\n");
    fprintf(stderr, "-c, --chroot [dir]\tChroot Sagan to specified directory.\n");
    fprintf(stderr, "-f, --config [file]\tSagan configuration file to load.\n");
    fprintf(stderr, "-F, --file [file]\tFIFO over ride.  This reads a file in rather than reading\n");
    fprintf(stderr, "\t\t\tfrom a FIFO.  The file must be in the Sagan format!\n");
    fprintf(stderr, "-l, --log [file]\tsagan.log location [default: %s].\n", SAGANLOG );
    fprintf(stderr, "-Q, --quiet\t\tRun Sagan in 'quiet' mode (no console output)\n");
    fprintf(stderr, "\n");

#ifdef HAVE_LIBESMTP
    fprintf(stderr, "* libesmtp (SMTP) support is included.\n");
#endif

#ifdef HAVE_LIBLOGNORM
    fprintf(stderr, "* liblognorm (log normalization) support is included.\n");
#endif

#ifdef HAVE_LIBPCAP
    fprintf(stderr, "* PLOG (syslog sniffer) support is included.\n");
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
    fprintf(stderr, "* libdnet (for unified2) support is included.\n");
#endif

#if defined(HAVE_LIBFASTJSON) || defined(HAVE_LIBLOGNORM)
    fprintf(stderr, "* libfastjson support is included.\n");
#endif

#ifdef HAVE_LIBMAXMINDDB
    fprintf(stderr, "* Maxmind GeoIP support is included.\n");
#endif

#ifdef WITH_SNORTSAM
    fprintf(stderr, "* Snortsam support is included.\n");
#endif

#ifdef WITH_SYSLOG
    fprintf(stderr, "* Syslog output is included.\n");
#endif

#ifdef WITH_BLUEDOT
    fprintf(stderr, "* Quadrant Information Security \"Bluedot\" is included.\n");
#endif

#ifdef WITH_SYSSTRSTR
    fprintf(stderr, "* Using Sagan's built in 'strstr' function.\n");
#endif

#ifdef PCRE_HAVE_JIT
    fprintf(stderr, "* Using PCRE JIT.\n");
#endif

#ifdef HAVE_LIBHIREDIS
    fprintf(stderr, "* Using HiRedis/Redis.\n");
#endif

    fprintf(stderr, "\n* Compiled on %s at %s.\n", __DATE__, __TIME__);
}
