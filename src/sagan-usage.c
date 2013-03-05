/*
** Copyright (C) 2009-2013 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2013 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-usage
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
fprintf(stderr, "-d, --debug [type]\tTypes: syslog, load, fwsam, external, threads");

#ifdef HAVE_LIBESMTP
fprintf(stderr, ", smtp");
#endif

#ifdef HAVE_LIBLOGNORM
fprintf(stderr, ", normalize");
#endif

#ifdef HAVE_LIBPCAP
fprintf(stderr, ", plog");
#endif

#ifdef WITH_WEBSENSE
fprintf(stderr, ", websense");
#endif

fprintf(stderr, ".\n");

fprintf(stderr, "-D, --daemon\t\tMake process a daemon (fork to the background).\n");
fprintf(stderr, "-u, --user [username]\tRun as user (defaults to 'sagan').\n");
fprintf(stderr, "-c, --chroot [dir]\tChroot Sagan to specified directory.\n");
fprintf(stderr, "-f, --config [file]\tSagan configuration file to load.\n");
fprintf(stderr, "-F, --file [file]\tFIFO over ride.  This reads a file in rather than reading\n");
fprintf(stderr, "\t\t\tfrom a FIFO.  The file must be in the Sagan format!\n");
fprintf(stderr, "-l, --log [file]\tsagan.log location [default: %s].\n\n", SAGANLOG );

#ifdef HAVE_LIBESMTP
fprintf(stderr, "* libesmtp (SMTP) support is included\n");
#endif

#ifdef HAVE_LIBLOGNORM
fprintf(stderr, "* liblognorm (log normalization) support is included\n");
#endif

#ifdef HAVE_LIBPCAP
fprintf(stderr, "* PLOG (syslog sniffer) support is included\n");
#endif

#if defined(HAVE_DNET_H) || defined(HAVE_DUMBNET_H)
fprintf(stderr, "* libdnet (for unified2) support is included\n");
#endif

fprintf(stderr, "* Compiled on %s at %s\n", __DATE__, __TIME__);
}
