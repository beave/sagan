
void Client_Stats_Init( void );
void Client_Stats_Handler( void );
void Client_Stats_Add_Update_IP( char *ip );

/* Client Stats strucure */

typedef struct _Client_Stats_Struct _Client_Stats_Struct;
struct _Client_Stats_Struct
{
    uint32_t hash;
    char ip[64];
    uint64_t epoch;
};
