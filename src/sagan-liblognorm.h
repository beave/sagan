#include "sagan-defs.h"

#ifdef HAVE_LIBLOGNORM
typedef struct _SaganNormalizeLiblognorm
{
    char ip_src[MAXIP];
    char ip_dst[MAXIP];

    int  src_port;
    int  dst_port;

//const char username[256];
//const char uid[10];

} _SaganNormalizeLiblognorm;
#endif


void sagan_liblognorm_load( void );
void sagan_normalize_liblognorm( char *);
