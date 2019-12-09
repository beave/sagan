
#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-config.h"
#include "routing.h"
#include "rules.h"

struct _Rule_Struct *rulestruct;
struct _SaganConfig *config;


bool Sagan_Check_Routing(  _Sagan_Routing *SaganRouting )
{

    /* Check Flow */

    if ( rulestruct[SaganRouting->position].has_flow == true && SaganRouting->check_flow_return == false )
        {
            return false;
        }

    /* Event ID */

    /*
        if ( rulestruct[SaganRouting->position].event_id_count > 0 && SaganRouting->event_id_return == false )
            {
                return false;
            }
    */


    /* Flexbit */

    if ( rulestruct[SaganRouting->position].flexbit_flag == false ||
            ( rulestruct[SaganRouting->position].flexbit_set_count && rulestruct[SaganRouting->position].flexbit_condition_count == 0 ) ||
            ( rulestruct[SaganRouting->position].flexbit_set_count && rulestruct[SaganRouting->position].flexbit_condition_count && SaganRouting->flexbit_return ) ||
            ( rulestruct[SaganRouting->position].flexbit_set_count == false && rulestruct[SaganRouting->position].flexbit_condition_count && SaganRouting->flexbit_return ))
        {
            /* pass */
        }
    else
        {
            return false;
        }

    if ( rulestruct[SaganRouting->position].flexbit_count_flag == true && SaganRouting->flexbit_count_return == false )
        {
            return false;
        }

    /* Xbit */

    if ( rulestruct[SaganRouting->position].xbit_flag == true &&
            ( rulestruct[SaganRouting->position].xbit_set_count != 0 || rulestruct[SaganRouting->position].xbit_unset_count != 0 )  )
        {
            /* pass */
        }
    else
        {

            if ( rulestruct[SaganRouting->position].xbit_flag == true && SaganRouting->xbit_return == false )
                {
                    return(false);
                }
        }


    /* Aetas */

    if ( rulestruct[SaganRouting->position].alert_time_flag == true && SaganRouting->alert_time_trigger == false )
        {
            return false;
        }

    /* Blacklist */

    if ( rulestruct[SaganRouting->position].blacklist_flag == true && SaganRouting->blacklist_results == false )
        {
            return false;
        }

    /* Zeek intel */

    if ( rulestruct[SaganRouting->position].brointel_flag == true && SaganRouting->brointel_results == false )
        {
            return false;
        }

    /* GeoIP */

#ifdef HAVE_LIBMAXMINDDB

    if ( rulestruct[SaganRouting->position].geoip2_flag == true && SaganRouting->geoip2_isset == false )
        {
            return false;
        }
#endif

#ifdef WITH_BLUEDOT

    if ( config->bluedot_flag == true )
        {

            if ( rulestruct[SaganRouting->position].bluedot_file_hash == true && SaganRouting->bluedot_hash_flag == false )
                {
                    return false;
                }

            if ( rulestruct[SaganRouting->position].bluedot_filename == true && SaganRouting->bluedot_filename_flag == false )
                {
                    return false;
                }

            if ( rulestruct[SaganRouting->position].bluedot_url == true && SaganRouting->bluedot_url_flag == false )
                {
                    return false;
                }

            if ( rulestruct[SaganRouting->position].bluedot_ja3 == true && SaganRouting->bluedot_ja3_flag == false )
                {
                    return false;
                }

            /* bluedot_ipaddr_type == 0 = disabled,  1 = src,  2 = dst,  3 = both,  4 = all  */

            if ( rulestruct[SaganRouting->position].bluedot_ipaddr_type != 0 && SaganRouting->bluedot_ip_flag == false )
                {
                    return false;
                }

        }

#endif

    return(true);

}
