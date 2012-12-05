

#ifdef HAVE_LIBLOGNORM
typedef struct _SaganNormalizeLiblognorm
{
char *ip_src;
char *ip_dst;

int  src_port;
int  dst_port;

char *username;
char *uid;

} _SaganNormalizeLiblognorm;
#endif


void sagan_liblognorm_load( void );
struct _SaganNormalizeLiblognorm *sagan_normalize_liblognorm( char *);
