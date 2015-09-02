/*
** Copyright (C) 2009-2015 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2015 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-gen-msg.c
 *
 * Reads in the sagan-gen-msg.map.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-gen-msg.h"

struct _SaganCounters *counters;
struct _Sagan_Processor_Generator *generator;
struct _SaganConfig *config;
struct _SaganDebug *debug;

void Load_Gen_Map( const char *genmap )
{

    FILE *genmapfile;
    char genbuf[1024];

    char *saveptr=NULL;

    char *gen1=NULL;
    char *gen2=NULL;
    char *gen3=NULL;

    Sagan_Log(S_NORMAL, "Loading gen-msg.map file. [%s]", genmap);

    counters->genmapcount=0;

    if (( genmapfile = fopen(genmap, "r" )) == NULL )
        {
            Sagan_Log(S_ERROR, "[%s, line %d] Cannot open generator file (%s)", __FILE__, __LINE__, genmap);
        }

    while(fgets(genbuf, 1024, genmapfile) != NULL)
        {

            /* Skip comments and blank linkes */

            if (genbuf[0] == '#' || genbuf[0] == 10 || genbuf[0] == ';' || genbuf[0] == 32)
                {
                    continue;
                }
            else
                {
                    /* Allocate memory for references,  not comments */
                    generator = (_Sagan_Processor_Generator *) realloc(generator, (counters->genmapcount+1) * sizeof(_Sagan_Processor_Generator));
                }

            gen1 = Remove_Return(strtok_r(genbuf, "|", &saveptr));
            gen2 = Remove_Return(strtok_r(NULL, "|", &saveptr));
            gen3 = Remove_Return(strtok_r(NULL, "|", &saveptr));

            if ( gen1 == NULL || gen2 == NULL || gen3 == NULL )
                {
                    Sagan_Log(S_ERROR, "%s is incorrect or not correctly formated", genmap);
                }

            generator[counters->genmapcount].generatorid=atoi(gen1);
            generator[counters->genmapcount].alertid=atoi(gen2);
            strlcpy(generator[counters->genmapcount].generator_msg, Remove_Return(gen3), sizeof(generator[counters->genmapcount].generator_msg));

            counters->genmapcount++;
        }

    fclose(genmapfile);
    Sagan_Log(S_NORMAL, "%d generators loaded.", counters->genmapcount);
}


/****************************************************************************/
/* Sagan_Generator_Lookup - Looks up the "generator" ID (see the            */
/* "gen-msg.map") of a processor                                            */
/****************************************************************************/

char *Sagan_Generator_Lookup(int processor_id, int alert_id)
{

    int z=0;
    char *msg=NULL;

    for (z=0; z<counters->genmapcount; z++)
        {
            if ( generator[z].generatorid == processor_id && generator[z].alertid == alert_id)
                {
                    msg=generator[z].generator_msg;
                }
        }

    return(msg);
}

