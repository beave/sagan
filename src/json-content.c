
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

bool JSON_Content(int rule_position, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL)
{

    int i=0;
    int a=0;

    int match = 0;

    for (i=0; i < rulestruct[rule_position].json_content_count; i++)
        {

            for (a=0; a < SaganProcSyslog_LOCAL->json_count; a++)
                {

                    /* Search for the "key" specified in json_content */

                    if ( !strcmp(SaganProcSyslog_LOCAL->json_key[a], rulestruct[rule_position].json_content_key[i] ) )
                        {

                            /* Key was found,  is this a "nocase" rule or is it case sensitive */

                            if ( rulestruct[rule_position].json_content_case[i] == true )
                                {

                                    /* Is this a json_content or json_content:! */


                                    if ( rulestruct[rule_position].json_content_not[i] != 1 && Sagan_stristr(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_content_content[i], false))
                                        {
                                            match++;
                                        }
                                    else
                                        {

                                            /* json_content:! */

                                            if ( rulestruct[rule_position].json_content_not[i] == 1 && !Sagan_stristr(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_content_content[i], false))
                                                {
                                                    match++;
                                                }

                                        }

                                }
                            else
                                {

                                    /* Case sensitive */

                                    if ( rulestruct[rule_position].json_content_not[i] != 1 && Sagan_strstr(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_content_content[i] ))
                                        {
                                            match++;

                                        }
                                    else
                                        {

                                            /* json_content:! */

                                            if ( rulestruct[rule_position].json_content_not[i] == 1 && !Sagan_strstr(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_content_content[i]) )
                                                {
                                                    match++;
                                                }

                                        }
                                }

                        }
                }
        }

    /* If everything lines up,  we have a full json_content match */

    if ( match == rulestruct[rule_position].json_content_count )
        {
            return(true);
        }

    return(false);

}


