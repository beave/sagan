
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

bool JSON_Meta_Content(int rule_position, _Sagan_Proc_Syslog *SaganProcSyslog_LOCAL)
{

    int i=0;
    int a=0;
    int z=0;

    int match = 0;

    for (i=0; i < rulestruct[rule_position].json_meta_content_count; i++)
        {

            for (a=0; a < SaganProcSyslog_LOCAL->json_count; a++)
                {

                    if ( !strcmp(SaganProcSyslog_LOCAL->json_key[a], rulestruct[rule_position].json_meta_content_key[i] ) )
                        {

                            for ( z = 0; z < rulestruct[rule_position].json_meta_content_containers[i].json_meta_counter; z++ )
                                {

                                    if ( rulestruct[rule_position].json_meta_content_not[i] == false )
                                        {

                                            if ( rulestruct[rule_position].json_meta_content_case[i] == true )
                                                {

                                                    if (!strcasecmp(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z]))
                                                        {
                                                            match++;
                                                            break;
                                                        }
                                                }
                                            else
                                                {

                                                    if (!strcmp(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z]))
                                                        {
                                                            match++;
                                                            break;
                                                        }
                                                }

                                        }
                                    else
                                        {

                                            if ( rulestruct[rule_position].json_meta_content_case[i] == true )
                                                {

                                                    if (strcasecmp(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z]))
                                                        {
                                                            match++;
                                                            break;
                                                        }
                                                }
                                            else
                                                {

                                                    if (strcmp(SaganProcSyslog_LOCAL->json_value[a], rulestruct[rule_position].json_meta_content_containers[i].json_meta_content_converted[z]))
                                                        {
                                                            match++;
                                                            break;
                                                        }
                                                }


                                        }


                                }
                        }
                }
        }


    /* Got all matches */

    if ( match == rulestruct[rule_position].json_meta_content_count )
        {
            return(true);
        }

    return(false);

}

