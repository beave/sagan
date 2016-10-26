/*
** Copyright (C) 2009-2016 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2016 Champ Clark III <cclark@quadrantsec.com>
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

/* sagan-dynamic-load.c
 *
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <stdlib.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-rules.h"
#include "sagan-config.h"

struct _SaganConfig *config;
struct _Rule_Struct *rulestruct;
struct _Rules_Loaded *rules_loaded;
struct _SaganCounters *counters;

pthread_mutex_t SaganRulesLoadedMutex;

int Sagan_Dynamic_Rules ( _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL, int rule_position, _Sagan_Processor_Info *processor_info_engine, char *ip_src, char *ip_dst )
{

    int i;

    for (i=0; i<counters->rules_loaded_count; i++) {

        /* If the rule set is loaded (or in our array), nothing else needs to be done */

        if (!strcmp(rulestruct[rule_position].dynamic_ruleset, rules_loaded[i].ruleset)) {
            return(0);
        }
    }

    pthread_mutex_lock(&SaganRulesLoadedMutex);

    rules_loaded = (_Rules_Loaded *) realloc(rules_loaded, (counters->rules_loaded_count+1) * sizeof(_Rules_Loaded));

    if ( rules_loaded == NULL ) {
        Sagan_Log(S_ERROR, "[%s, line %d] Failed to reallocate memory for rules_loaded. Abort!", __FILE__, __LINE__);
    }

    strlcpy(rules_loaded[counters->rules_loaded_count].ruleset, rulestruct[rule_position].dynamic_ruleset, sizeof(rules_loaded[counters->rules_loaded_count].ruleset));

    counters->rules_loaded_count++;

    pthread_mutex_unlock(&SaganRulesLoadedMutex);

    /* Load rules, log and alert */

    if ( config->dynamic_load_type == 0 ) {

        Sagan_Log(S_NORMAL, "Detected dynamic signature '%s'. Dynamically loading '%s'.", rulestruct[rule_position].s_msg, rulestruct[rule_position].dynamic_ruleset);

        pthread_mutex_lock(&SaganRulesLoadedMutex);
        Load_Rules(rulestruct[rule_position].dynamic_ruleset);
        pthread_mutex_unlock(&SaganRulesLoadedMutex);

        Sagan_Send_Alert(SaganProcSyslog_LOCAL,
                         processor_info_engine,
                         ip_src,
                         ip_dst,
                         "",
                         "",
                         config->sagan_proto,
                         atoi(rulestruct[rule_position].s_sid),
                         config->sagan_port,
                         config->sagan_port,
                         rule_position );

    }

    /* Log only */

    else if ( config->dynamic_load_type == 1 ) {

        Sagan_Log(S_NORMAL, "Detected dynamic signature '%s'. Sagan would automatically load '%s' but the 'dynamic_load' processor is set to 'log_only'.", rulestruct[rule_position].s_msg, rulestruct[rule_position].dynamic_ruleset);

    }

    /* Alert only */

    else if ( config->dynamic_load_type == 2 ) {

        Sagan_Log(S_NORMAL, "Detected dynamic signature '%s'. Sagan would automatically load '%s' but the 'dynamic_load' processor is set to 'alert'.", rulestruct[rule_position].s_msg, rulestruct[rule_position].dynamic_ruleset);

        Sagan_Send_Alert(SaganProcSyslog_LOCAL,
                         processor_info_engine,
                         ip_src,
                         ip_dst,
                         "",
                         "",
                         config->sagan_proto,
                         atoi(rulestruct[rule_position].s_sid),
                         config->sagan_port,
                         config->sagan_port,
                         rule_position );

    }

    return(0);

}
