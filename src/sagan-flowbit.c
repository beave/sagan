/*
** Copyright (C) 2009-2014 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2014 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-meta-content.c - This allows content style "searching" that 
 * involve variables.  For example,  if we wanted to search for "bob", 
 * "frank" and "mary",  we'd typically need three content rules.  
 * This allows one rule with the $USER variable for "bob", "frank" and
 * "mary".  
 *
 * meta_content: "Username: ", $USERNAME"; meta_nocase; 
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sagan.h"
#include "sagan-defs.h"

struct _SaganCounters *counters;
struct _Rule_Struct *rulestruct;
struct _SaganDebug *debug;
struct _Sagan_Flowbits *flowbits;


struct _Rule_Struct *rulestruct;

int Sagan_Flowbit(int rule_position )
{

time_t t;
struct tm *now;
char  timet[20];
int i; 


                                    t = time(NULL);
                                    now=localtime(&t);
                                    strftime(timet, sizeof(timet), "%s",  now);

                                    /* Clean up expired flowbits */

                                    for (i=0; i<counters->flowbit_count; i++)
                                        {   
                                            if (  flowbits[i].flowbit_state == 1 && atol(timet) >= flowbits[i].flowbit_expire )
                                                {   
                                                    if (debug->debugflowbit) Sagan_Log(S_DEBUG, "[%s, line %d] Cleaning up expired flowbit %s", __FILE__, __LINE__, flowbits[i].flowbit_name);
                                                    flowbits[i].flowbit_state = 0;
                                                }
                                        }

                                    /* Flowbit "isset" */

                                    if ( rulestruct[rule_position].flowbit_flag == 3 && flowbits[rulestruct[rule_position].flowbit_memory_position].flowbit_state == 1 )
                                        {   
                                            if ( debug->debugflowbit ) Sagan_Log(S_DEBUG, "[%s, line %d] Flowbit \"%s\" has been set. TRIGGERING",  __FILE__, __LINE__, flowbits[rulestruct[rule_position].flowbit_memory_position].flowbit_name);
					    return(TRUE);
                                        }

                                    /* Flowbit "set" */

                                    if ( rulestruct[rule_position].flowbit_flag == 1 )
                                        {   
                                            flowbits[rulestruct[rule_position].flowbit_memory_position].flowbit_state = 1;
                                            flowbits[rulestruct[rule_position].flowbit_memory_position].flowbit_expire = atol(timet) + rulestruct[rule_position].flowbit_timeout;
                                        }

                                    /* Flowbit "unset" */

                                    if ( rulestruct[rule_position].flowbit_flag == 2 )
                                        {
                                            flowbits[rulestruct[rule_position].flowbit_memory_position].flowbit_state = 0;
					    return(FALSE);
                                        }

                                    /* Flowbit "isnotset" */

                                    if ( rulestruct[rule_position].flowbit_flag == 4 && flowbits[rulestruct[rule_position].flowbit_memory_position].flowbit_state == 0 )
                                        {
                                            if ( debug->debugflowbit ) Sagan_Log(S_DEBUG, "[%s, line %d] Flowbit \"%s\" ISNOTSET",  __FILE__, __LINE__, flowbits[rulestruct[rule_position].flowbit_memory_position].flowbit_name);
					    return(TRUE);
                                        }

                                    if ( debug->debugflowbit)
                                        {

                                            Sagan_Log(S_DEBUG, "[%s, line %d] -- All flowbits and values ---------------", __FILE__, __LINE__);

                                            for (i=0; i<counters->flowbit_count; i++)
                                                {
                                                    Sagan_Log(S_DEBUG, "[%s, line %d] Flowbit memory position: %d | Flowbit name: %s | Flowbit state: %d", __FILE__, __LINE__,  i, flowbits[i].flowbit_name, flowbits[i].flowbit_state);
                                                }
                                        }


return(FALSE);
}

