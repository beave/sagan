




typedef struct _Sagan_Routing _Sagan_Routing;
struct _Sagan_Routing
{
    int  position;
    bool check_flow_return;
    bool flexbit_count_return;
    bool flexbit_return;
    bool xbit_return;
    bool event_id_return;
    bool alert_time_trigger;
    bool geoip2_isset;
    bool blacklist_results;
    bool brointel_results;

#ifdef WITH_BLUEDOT

    bool bluedot_hash_flag;
    bool bluedot_filename_flag;
    bool bluedot_url_flag;
    bool bluedot_ip_flag;
    bool bluedot_ja3_flag;

#endif

};

bool Sagan_Check_Routing(  _Sagan_Routing *SaganRouting );

