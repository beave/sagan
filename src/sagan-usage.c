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


void sagan_usage(void)
{
fprintf(stderr, "\n--[Sagan version %s | Help/usage screen]--------------------------------\n\n", VERSION);
fprintf(stderr, "-h, --help\t\tHelp (this screen).\n");
fprintf(stderr, "-d, --debug [type]\tEnabled debugging. Valid types: syslog, normalize,\n"); 
fprintf(stderr, "\t\t\tsql, and smtp. Multiple values allowed.\n");
fprintf(stderr, "-D, --daemon\t\tMake process a daemon (fork to the background).\n");
fprintf(stderr, "-U, --user\t\tRun as user (defaults to 'sagan').\n");
fprintf(stderr, "-c, --chroot\t\tChroot to username 'sagan's home.\n");
fprintf(stderr, "-f, --config\t\tSagan configuration file to load.\n");
fprintf(stderr, "-p, --program\t\tRun Sagan in syslog-ng's 'program' mode.\n\n");

#ifdef HAVE_LIBPQ
fprintf(stderr, "* PostgreSQL support is included\n");
#endif

#ifdef HAVE_LIBMYSQLCLIENT_R
fprintf(stderr, "* MySQL support is included\n");
#endif

#ifdef HAVE_LIBESMTP
fprintf(stderr, "* libesmtp (SMTP) support is included\n");
#endif

#ifdef HAVE_LIBPRELUDE
fprintf(stderr, "* Prelude (libprelude) support is included\n");
#endif

#ifdef HAVE_LIBLOGNORM
fprintf(stderr, "* liblognorm (log normalization) is included\n");
#endif
}
