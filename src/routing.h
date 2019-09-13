




typedef struct _Sagan_Routing _Sagan_Routing;
struct _Sagan_Routing
{
    int  position;
    bool check_flow_return;

    bool flexbit_count_return;
    bool flexbit_return;

    bool xbit_return;

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


//    char syslog_host[MAX_SYSLOG_HOST];
//    char syslog_facility[MAX_SYSLOG_FACILITY];
//    char syslog_priority[MAX_SYSLOG_PRIORITY];
//    char syslog_level[MAX_SYSLOG_LEVEL];
//    char syslog_tag[MAX_SYSLOG_TAG];
//    char syslog_date[MAX_SYSLOG_DATE];
//    char syslog_time[MAX_SYSLOG_TIME];
//    char syslog_program[MAX_SYSLOG_PROGRAM];
//    char syslog_message[MAX_SYSLOGMSG];
};

bool Sagan_Check_Routing(  _Sagan_Routing *SaganRouting );

