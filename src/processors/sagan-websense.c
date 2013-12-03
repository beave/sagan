#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>

#include "sagan.h"
#include "sagan-defs.h"

#ifdef WITH_WEBSENSE

Sagan_Log(S_ERROR, "Websense support is not included with this version of Sagan.  For more\ninformation,  please e-mail info@quadrantsec.com.  Aborting!");

#endif
