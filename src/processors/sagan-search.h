#define SEARCH_PROCESSOR_NAME "Sagan_Search"
#define SEARCH_PROCESSOR_FACILITY "daemon"
#define SEARCH_PROCESSOR_PRIORITY "warning"
#define SEARCH_PROCESSOR_PRI 1
#define SEARCH_PROCESSOR_CLASS "Search"
#define SEARCH_PROCESSOR_REV "1"
#define SEARCH_PROCESSOR_TAG NULL
#define SEARCH_PROCESSOR_GENERATOR_ID 1002


typedef struct _Sagan_Nocase_Searchlist _Sagan_Nocase_Searchlist;
struct _Sagan_Nocase_Searchlist {
char search[512];
};

typedef struct _Sagan_Case_Searchlist _Sagan_Case_Searchlist;
struct _Sagan_Case_Searchlist {
char search[512];
};

int Sagan_Search ( _SaganProcSyslog *, int );
void Sagan_Search_Send_Alert ( _SaganProcSyslog *, int );


