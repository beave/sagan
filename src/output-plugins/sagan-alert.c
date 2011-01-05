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

/* sagan-alert.c 
 *
 * Provides logging functionality in a 'snort like' format.  Usually in 
 * the /var/log/sagan directory named 'alert'
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "sagan.h"
#include "version.h"

FILE *alertfp;
int refcount;

struct rule_struct *rulestruct;
struct ref_struct *refstruct;

void *sagan_alert ( char *s_sid, 
 		    char *s_msg,
		    char *s_classtype,
		    int   s_pri,
		    char *s_date,  
		    char *s_time, 
		    char *s_src, 
		    char *s_dst,
		    char *s_facility, 
		    char *s_fpri, 
		    int  dst_port, 
		    int  src_port, 
		    char *message,
		    int  rulemem
		    ) {

char tmpref[2048]="";

fprintf(alertfp, "\n[**] [%s] %s [**]\n", s_sid, s_msg);
fprintf(alertfp, "[Classification: %s] [Priority: %d]\n", s_classtype, s_pri );
fprintf(alertfp, "%s %s %s:%d -> %s:%d %s %s\n", s_date, s_time, s_src, src_port,s_dst, dst_port, s_facility, s_fpri);
fprintf(alertfp, "Message: %s\n", message);
snprintf(tmpref, sizeof(tmpref), "%s", reflookup( rulemem, 0 ));
if ( strcmp(tmpref, "")) fprintf(alertfp, "%s\n", tmpref);

fflush(alertfp);

return(0);
}
