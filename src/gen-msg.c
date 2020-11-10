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

/* gen-msg.c
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
#include <pthread.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "gen-msg.h"

extern struct _SaganCounters *counters;
extern struct _Sagan_Processor_Generator *generator;
extern struct _SaganConfig *config;
extern struct _SaganDebug *debug;

void Load_Gen_Map( const char *genmap )
{

    FILE *genmapfile;
    char genbuf[1024];

    char *saveptr=NULL;

    char *gen1=NULL;
    char *gen2=NULL;
    char *gen3=NULL;

    Sagan_Log(NORMAL, "Loading gen-msg.map file. [%s]", genmap);

    __atomic_store_n (&counters->genmapcount, 0, __ATOMIC_SEQ_CST);

    if (( genmapfile = fopen(genmap, "r" )) == NULL )
        {
            Sagan_Log(ERROR, "[%s, line %d] Cannot open generator file (%s)", __FILE__, __LINE__, genmap);
        }

    while(fgets(genbuf, 1024, genmapfile) != NULL)
        {

            /* Skip comments and blank linkes */

            if (genbuf[0] == '#' || genbuf[0] == 10 || genbuf[0] == ';' || genbuf[0] == 32)
                {
                    continue;
                }

            /* Allocate memory for references,  not comments */

            generator = (_Sagan_Processor_Generator *) realloc(generator, (counters->genmapcount+1) * sizeof(_Sagan_Processor_Generator));

            if ( generator == NULL )
                {
                    Sagan_Log(ERROR, "[%s, line %d] Failed to reallocate memory for generator. Abort!", __FILE__, __LINE__);
                }

            memset(&generator[counters->genmapcount], 0, sizeof(_Sagan_Processor_Generator));

            gen1 = strtok_r(genbuf, "|", &saveptr);

            if ( gen1 == NULL )
                {
                    Sagan_Log(ERROR, "%s is incorrect or not correctly formated (gen1) ", genmap);
                }

            Remove_Return(gen1);

            gen2 = strtok_r(NULL, "|", &saveptr);

            if ( gen2 == NULL )
                {
                    Sagan_Log(ERROR, "%s is incorrect or not correctly formated (gen2) ", genmap);
                }

            Remove_Return(gen2);

            gen3 = strtok_r(NULL, "|", &saveptr);

            if ( gen3 == NULL )
                {
                    Sagan_Log(ERROR, "%s is incorrect or not correctly formated (gen3) ", genmap);
                }

            Remove_Return(gen3);

            generator[counters->genmapcount].generatorid=atoi(gen1);
            generator[counters->genmapcount].alertid=atoi(gen2);
            strlcpy(generator[counters->genmapcount].generator_msg, gen3, sizeof(generator[counters->genmapcount].generator_msg));

            __atomic_add_fetch(&counters->genmapcount, 1, __ATOMIC_SEQ_CST);

        }

    fclose(genmapfile);
    Sagan_Log(NORMAL, "%d generators loaded.", counters->genmapcount);
}


/****************************************************************************/
/* Sagan_Generator_Lookup - Looks up the "generator" ID (see the            */
/* "gen-msg.map") of a processor                                            */
/****************************************************************************/

void Generator_Lookup(int processor_id, int alert_id, char *str, size_t size)
{

    int z=0;
    char *msg=NULL;

    for (z=0; z<counters->genmapcount; z++)
        {
            if ( generator[z].generatorid == processor_id && generator[z].alertid == alert_id)
                {
                    msg=generator[z].generator_msg;
                    break;
                }
        }

    snprintf(str, size, "%s", msg);
}

