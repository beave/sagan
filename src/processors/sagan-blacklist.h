
#define BLACKLIST_PROCESSOR_NAME "Blacklist"
#define BLACKLIST_PROCESSOR_FACILITY "daemon"
#define BLACKLIST_PROCESSOR_PRIORITY "warning"
#define BLACKLIST_PROCESSOR_PRI 1
#define BLACKLIST_PROCESSOR_CLASS "Backlist"
#define BLACKLIST_PROCESSOR_REV "1"
#define BLACKLIST_PROCESSOR_TAG NULL
#define BLACKLIST_PROCESSOR_GENERATOR_ID 1001


int Sagan_Blacklist ( _SaganProcSyslog * );

void Sagan_Blacklist_Send_Alert ( _SaganProcSyslog *, char *, char *, int );

typedef struct _Sagan_Blacklist _Sagan_Blacklist;
struct _Sagan_Blacklist {

uint32_t u32_lower;
uint32_t u32_higher;

};

