
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

    bool ret = false;

    /* Check Flow */

    if ( SaganRouting->check_flow_return == true )
        {

            /* Flexbit */

            if ( rulestruct[SaganRouting->position].flexbit_flag == false ||
                    ( rulestruct[SaganRouting->position].flexbit_set_count && rulestruct[SaganRouting->position].flexbit_condition_count == 0 ) ||
                    ( rulestruct[SaganRouting->position].flexbit_set_count && rulestruct[SaganRouting->position].flexbit_condition_count && SaganRouting->flexbit_return ) ||
                    ( rulestruct[SaganRouting->position].flexbit_set_count == false && rulestruct[SaganRouting->position].flexbit_condition_count && SaganRouting->flexbit_return ))
                {


                    if ( rulestruct[SaganRouting->position].flexbit_count_flag == false || SaganRouting->flexbit_count_return == true )
                        {

                            /* Xbit */


                            if ( rulestruct[SaganRouting->position].xbit_flag == false || SaganRouting->xbit_return == true ||
                                    ( rulestruct[SaganRouting->position].xbit_isset_count == 0
                                      && rulestruct[SaganRouting->position].xbit_isnotset_count == 0 ))
                                {

                                    /* Aetas */


                                    if ( rulestruct[SaganRouting->position].alert_time_flag == false || SaganRouting->alert_time_trigger == true )
                                        {

                                            /* GeoIP */


#ifdef HAVE_LIBMAXMINDDB

                                            if ( rulestruct[SaganRouting->position].geoip2_flag == false || SaganRouting->geoip2_isset == true )
                                                {
#endif

                                                    if ( rulestruct[SaganRouting->position].blacklist_flag == false || SaganRouting->blacklist_results == true )
                                                        {

                                                            if ( rulestruct[SaganRouting->position].brointel_flag == false || SaganRouting->brointel_results == true )
                                                                {

#ifdef WITH_BLUEDOT

                                                                    /* Needs JA3 and re-write */

                                                                    if ( config->bluedot_flag == false || rulestruct[SaganRouting->position].bluedot_file_hash == false || ( rulestruct[SaganRouting->position].bluedot_file_hash == true && SaganRouting->bluedot_hash_flag == true ))
                                                                        {

                                                                            if ( config->bluedot_flag == false || rulestruct[SaganRouting->position].bluedot_filename == false || ( rulestruct[SaganRouting->position].bluedot_filename == true && SaganRouting->bluedot_filename_flag == true ))
                                                                                {

                                                                                    if ( config->bluedot_flag == false || rulestruct[SaganRouting->position].bluedot_url == false || ( rulestruct[SaganRouting->position].bluedot_url == true && SaganRouting->bluedot_url_flag == true ))
                                                                                        {

                                                                                            if ( config->bluedot_flag == false || rulestruct[SaganRouting->position].bluedot_ipaddr_type == false || ( rulestruct[SaganRouting->position].bluedot_ipaddr_type != 0 && SaganRouting->bluedot_ip_flag == true ))
                                                                                                {

                                                                                                    ret = true;

                                                                                                }
                                                                                        }
                                                                                }
                                                                        }
#endif
                                                                }
                                                        }
#ifdef HAVE_LIBMAXMINDDB
                                                }
#endif

                                        }
                                }
                        }
                }
        }


    return(ret);

}
