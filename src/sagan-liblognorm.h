

#ifdef HAVE_LIBLOGNORM
typedef struct _SaganNormalizeLiblognorm
{
const char *ip_src;
const char *ip_dst;

int  src_port;
int  dst_port;

const char *username;
const char *uid;

} _SaganNormalizeLiblognorm;
#endif


void sagan_liblognorm_load( void );
void sagan_normalize_liblognorm( char *);
