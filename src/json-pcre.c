
#include <stdio.h>


#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdbool.h>
#include <string.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "rules.h"
#include "json-content.h"

#include "parsers/parsers.h"

struct _Rule_Struct *rulestruct;

bool JSON_Pcre(int rule_position, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL)
{

    int i=0;
    int a=0;
    int rc=0;

    int ovector[PCRE_OVECCOUNT];

    int match = 0;

    for (i=0; i < rulestruct[rule_position].json_pcre_count; i++)
        {

            for (a=0; a < SaganProcSyslog_LOCAL->json_count; a++)
                {

                    if ( !strcmp(SaganProcSyslog_LOCAL->json_key[a], rulestruct[rule_position].json_pcre_key[i] ) )
                        {

                            rc = pcre_exec( rulestruct[rule_position].json_re_pcre[i], rulestruct[rule_position].json_pcre_extra[i], SaganProcSyslog_LOCAL->syslog_message, (int)strlen(SaganProcSyslog_LOCAL->syslog_message), 0, 0, ovector, PCRE_OVECCOUNT);

                            if ( rc > 0 )
                                {
                                    match++;
                                }




                        }

                }


        }

    if ( match == rulestruct[rule_position].json_pcre_count )
        {
            return(true);
        }


    return(false);
}

