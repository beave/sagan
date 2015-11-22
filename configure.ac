#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT
AC_CONFIG_SRCDIR([src])
AC_CANONICAL_SYSTEM
AC_GNU_SOURCE
AC_CONFIG_MACRO_DIRS([m4])

AM_MAINTAINER_MODE([disable])


#VERSION=`cat $srcdir/version.h | grep "#define VERSION " | sed -e 's/^.*\"\(.*\)\"/\1/'`

VERSION=`cat src/version.h | grep "#define VERSION " | sed -e 's/^.*\"\(.*\)\"/\1/'`

AC_C_BIGENDIAN(AC_SUBST([ENDIAN],[big]),AC_SUBST([ENDIAN],[little]))

AC_ARG_ENABLE(snortsam,
  [  --disable-snortsam      Disable Snortsam support.],
  [ SNORTSAM="$enableval"],
  [ SNORTSAM="yes" ]
)

AC_ARG_ENABLE(bluedot,
  [  --enable-bluedot        Enable Quadrant\'s "Bluedot" lookups.],
  [ BLUEDOT="$enableval"],
  [ BLUEDOT="no" ]
)

AC_ARG_ENABLE(esmtp,
  [  --enable-esmtp	  Enable libesmtp support.],
  [ ESMTP="$enableval"],
  [ ESMTP="no" ]
)

AC_ARG_ENABLE(geoip2,
  [  --enable-geoip2          Enable Maxmind GeoIP2 support.],
  [ GEOIP2="$enableval"],
  [ GEOIP2="no" ]
)

AC_ARG_ENABLE(syslog,
  [  --disable-syslog        Disable syslog support.],
  [ SYSLOG="$enableval"],
  [ SYSLOG="yes" ]
)

AC_ARG_ENABLE(system-strstr,
  [  --enable-system-strstr  Enable system strstr.],
  [ SYSSTRSTR="$enableval"],
  [ SYSSTRSTR="no" ]
)

AC_ARG_WITH(esmtp_includes,
        [  --with-esmtp-includes=DIR    libesmtp include directory],
        [with_esmtp_includes="$withval"],[with_esmtp_includes="no"])

AC_ARG_WITH(esmtp_libraries,
        [  --with-esmtp-libraries=DIR   libesmtp library directory],
        [with_esmtp_libraries="$withval"],[with_esmtp_libraries="no"])

if test "x$with_esmtp_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_esmtp_includes}"
   fi

if test "x$with_esmtp_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS}  -L${with_esmtp_libraries}"
fi

AC_ARG_WITH(geoip2_includes,
        [  --with-geoip2-includes=DIR    Maxmind GeoIP2 include directory],
        [with_geoip2_includes="$withval"],[with_geoip2_includes="no"])

AC_ARG_WITH(geoip2_libraries,
        [  --with-geoip2-libraries=DIR   Maxmind GeoIP2 library directory],
        [with_geoip2_libraries="$withval"],[with_geoip2_libraries="no"])

if test "x$with_geoip2_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_geoip2_includes}"
   fi

if test "x$with_geoip2_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS}  -L${with_geoip2_libraries}"
fi

AC_ARG_ENABLE(lognorm,
  [  --disable-lognorm       Disable Lognorm (liblognorm) support.],
  [ LOGNORM="$enableval"],
  [ LOGNORM="yes" ]
)

AC_ARG_WITH(lognorm_includes,
        [  --with-lognorm-includes=DIR    liblognorm include directory],
        [with_lognorm_includes="$withval"],[with_lognorm_includes="no"])

AC_ARG_WITH(lognorm_libraries,
        [  --with-lognorm-libraries=DIR   liblognorm library directory],
        [with_lognorm_libraries="$withval"],[with_lognorm_libraries="no"])

if test "x$with_lognorm_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_lognorm_includes}"
   fi

if test "x$with_lognorm_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS}  -L${with_lognorm_libraries}"
fi

# -- 

AC_ARG_ENABLE(jsonc,
  [  --disable-jsonc         Disable jsonc (liblognorm) support.],
  [ JSONC="$enableval"],
  [ JSONC="yes" ]
)

AC_ARG_WITH(json_c_includes,
        [  --with-jsonc-includes=DIR    jsonc include directory],
        [with_jsonc_includes="$withval"],[with_jsonc_includes="no"])

AC_ARG_WITH(json_c_libraries,
        [  --with-jsonc-libraries=DIR   jsonc library directory],
        [with_jsonc_libraries="$withval"],[with_jsonc_libraries="no"])

if test "x$with_jsonc_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_jsonc_includes}"
   fi

if test "x$with_jsonc_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS}  -L${with_jsonc_libraries}"
fi

# --

AC_ARG_ENABLE(libpcap,
  [  --disable-libpcap       Disable libpcap (plog) support.],
  [ LIBPCAP="$enableval"],
  [ LIBPCAP="no" ]
)

AC_ARG_WITH(libpcap_includes,
        [  --with-libpcap-includes=DIR    libpcap include directory],
        [with_libpcap_includes="$withval"],[with_libpcap_includes="no"])

AC_ARG_WITH(libpcap_libraries,
        [  --with-libpcap-libraries=DIR   libpcap library directory],
        [with_libpcap_libraries="$withval"],[with_libpcap_libraries="no"])

if test "x$with_libpcap_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
   fi

if test "x$with_libpcap_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
fi

AC_ARG_ENABLE(libdnet,
  [  --disable-libdnet       Disable libdnet (unified2) support.],
  [ LIBDNET="$enableval"],
  [ LIBDNET="yes" ]
)

AC_ARG_WITH(libdnet_includes,
        [  --with-libdnet-includes=DIR    libdnet include directory],
        [with_libdnet_includes="$withval"],[with_libdnet_includes="no"])

AC_ARG_WITH(libdnet_libraries,
        [  --with-libdnet-libraries=DIR   libdnet library directory],
        [with_libdnet_libraries="$withval"],[with_libdnet_libraries="no"])

if test "x$with_libdnet_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_libdnet_includes}"
   fi

if test "x$with_libdnet_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS}  -L${with_libdnet_libraries}"
fi

AC_SUBST(VERSION)
AM_INIT_AUTOMAKE(sagan, ${VERSION})
AC_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_LANG_C
AC_PROG_MAKE_SET

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_CHECK_HEADERS([stdio.h stdlib.h sys/types.h unistd.h stdint.h inttypes.h pthread.h ctype.h errno.h fcntl.h sys/stat.h string.h getopt.h time.h pcre.h stdarg.h limits.h stdbool.h arpa/inet.h netinet/in.h sys/time.h sys/socket.h sys/mmap.h])

AC_CHECK_SIZEOF([size_t])


# F_SETPIPE_SZ in fcntl.h
AC_MSG_CHECKING([for F_SETPIPE_SZ in fcntl.h])
AC_EGREP_CPP([yes_have_f_setpipe_sz], [
  #define _GNU_SOURCE
  #include <fcntl.h>
  #ifdef F_SETPIPE_SZ
  yes_have_f_setpipe_sz
  #endif
], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_SETPIPE_SZ], [], [F_SETPIPE_SZ is supported])
], [
  AC_MSG_RESULT([no])
  AC_MSG_NOTICE([F_SETPIPE_SZ not found, cannot alter FIFO])
])

# F_GETPIPE_SZ in fcntl.h
AC_MSG_CHECKING([for F_GETPIPE_SZ in fcntl.h])
AC_EGREP_CPP([yes_have_f_getpipe_sz], [
  #define _GNU_SOURCE
  #include <fcntl.h>
  #ifdef F_GETPIPE_SZ
  yes_have_f_getpipe_sz
  #endif
], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_GETPIPE_SZ], [], [F_GETPIPE_SZ is supported])
], [
  AC_MSG_RESULT([no])
  AC_MSG_NOTICE([F_GETPIPE_SZ not found, cannot alter FIFO])
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STAT
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_FUNC_FORK
AC_FUNC_REALLOC
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TM 

AX_EXT
AM_PROG_AS

AC_CHECK_FUNCS([select strstr strchr strcmp strlen sizeof write snprintf strncat strlcat strlcpy getopt_long gethostbyname socket htons connect send recv dup2 strspn strdup memset access ftruncate strerror mmap shm_open])

AC_CHECK_LIB(pcre, main,,AC_MSG_ERROR(Sagan needs PCRE installed.  Please see http://www.pcre.org.))
AC_CHECK_LIB(pthread, main,,AC_MSG_ERROR(Sagan needs pthreads!))
AC_CHECK_LIB(m, main,,AC_MSG_ERROR(Sagan needs libm!))
AC_CHECK_LIB(rt, main,,AC_MSG_ERROR(Sagan needs librt!))

if test "$SYSSTRSTR" = "yes"; then
	AC_MSG_RESULT([using build in strstr()...])
	AC_DEFINE(WITH_SYSSTRSTR, 1, With system strstr)
	fi

if test "$SYSLOG" = "yes"; then
	AC_MSG_RESULT([------- Syslog support is enabled -------])
	AC_CHECK_HEADER([syslog.h])
	AC_DEFINE(WITH_SYSLOG, 1, With Syslog)
	fi

if test "$GEOIP2" = "yes"; then
       AC_MSG_RESULT([------- Maxmind GeoIP2 support is enabled -------])
       AC_CHECK_HEADER([maxminddb.h])
       AC_CHECK_LIB(maxminddb, main,,AC_MSG_ERROR(The Maxmind GeoIP2 library cannot be found.
If you're not interested in GeoIP2 support use the --disable-geoip2 flag.))
       fi

if test "$ESMTP" = "yes"; then
       AC_MSG_RESULT([------- libesmtp support is enabled -------])
       AC_CHECK_HEADER([libesmtp.h])
       AC_CHECK_LIB(esmtp, main,,AC_MSG_ERROR(The libesmtp library cannot be found.
If you're not interested in libesmtp support use the --disable-esmtp flag.))
       fi


if test "$JSONC" = "yes"; then
	AC_MSG_RESULT([------- jsonc support is enabled -------])
        PKG_CHECK_MODULES(JSONC, json-c,, [PKG_CHECK_MODULES(JSONC, json)])
	
AC_CHECK_LIB([json], [json_object_new_string],,
	[AC_CHECK_LIB([json-c], [json_object_new_string],,
	[AC_MSG_ERROR([
Cannot find required library: libjson-c (aka libjson0, libjson)
	])])])


	fi

if test "$LOGNORM" = "yes"; then
       AC_MSG_RESULT([------- liblognorm support is enabled -------])
       PKG_CHECK_MODULES(LIBESTR, libestr >= 0.0.0)
       PKG_CHECK_MODULES(LIBLOGNORM, lognorm >= 1.0.0)
       PKG_CHECK_MODULES(JSON_C, json-c,, [PKG_CHECK_MODULES(JSON_C, json)])
       AC_CHECK_HEADER([liblognorm.h])
       AC_CHECK_HEADER([libestr.h])
       AC_CHECK_LIB(estr, main,,AC_MSG_ERROR(The libestr library cannot be found.
This library is important for the correlation aspects of Sagan! Please see
https://wiki.quadrantsec.com/bin/view/Main/LibLogNorm. To disable this feature
use the --disable-lognorm flag. ))
      AC_CHECK_LIB(lognorm, main,,AC_MSG_ERROR(The liblognorm library cannot be found.
This library is important for the correlation aspects of Sagan! Please see
https://wiki.quadrantsec.com/bin/view/Main/LibLogNorm. To disable this feature
use the --disable-lognorm flag. ))
       fi

if test "$LIBPCAP" = "yes"; then
       AC_MSG_RESULT([------- libpcap support is enabled -------])
       AC_CHECK_HEADER([pcap.h])
       AC_CHECK_HEADER([net/if.h])
       AC_CHECK_HEADER([net/if_arp.h])
       AC_CHECK_HEADER([netinet/in_systm.h])
       AC_CHECK_HEADER([netinet/if_ether.h])
       AC_CHECK_HEADER([netinet/ip.h])
       AC_CHECK_HEADER([netinet/udp.h])
       AC_CHECK_LIB(pcap, main,,AC_MSG_ERROR(The libpcap library cannot be found.
This library is used to run Sagan in a syslog 'sniffer' mode.  Please see
https://wiki.quadrantsec.com/bin/view/Main/PLog.  To disable this feature use
the --disable-libpcap flag. ))
       fi

if test "$LIBDNET" = "yes"; then
       AC_MSG_RESULT([------- libdnet support is enabled -------])

AC_CHECK_HEADERS(dnet.h,,DNET_H="no")
AC_CHECK_HEADERS(dumbnet.h,,DUMBNET_H="no")

if test "x$DNET_H" = "xno" -a "x$DUMBNET_H" = "xno"; then
    echo
    echo "The libdnet headers cannot be found.  This library is used for Sagan's"
    echo "Unified2 output support.  Please see:" 
    echo "https://wiki.quadrantsec.com/bin/view/Main/Unified2Output"
    echo "To disable this feature use the --disable-libdnet flag."
    exit
fi

AC_CHECK_LIB(dnet, eth_set,,[DNET="no"])
AC_CHECK_LIB(dumbnet, eth_set,,[DUMBNET="no"])

if test "x$DNET" = "xno" -a "x$DUMBNET" = "xno"; then
    echo
    echo "The libdnet headers cannot be found.  This library is used for Sagan's" 
    echo "Unified2 output support.  Please see:"
    echo "https://wiki.quadrantsec.com/bin/view/Main/Unified2Output"
    echo "To disable this feature use the --disable-libdnet flag."
    exit
fi

fi

if test "$BLUEDOT" = "yes"; then
        AC_MSG_RESULT([------- Quadrant "Bluedot" is enabled -------])
        AC_CHECK_LIB(curl, main,,AC_MSG_ERROR(The libcurl library cannot be found.
This library is used for Sagan's / "Bluedot" support.  Please see
https://quadrantsec.com for more information.
To disable this feature use the --disable-bluedot flag. ))
        AC_DEFINE(WITH_BLUEDOT, 1, With Bluedot)
        AC_CHECK_HEADER([curl/curl.h])
        PKG_CHECK_MODULES(JSON_C, json-c,, [PKG_CHECK_MODULES(JSON_C, json)])
        fi

if test "$SNORTSAM" = "yes"; then
        AC_MSG_RESULT([------- Snortsam support is enabled -------])
        AC_DEFINE(WITH_SNORTSAM, 1, With Snortsam)
        fi

test "x$prefix" = x. || test "x$prefix" = xNONE && prefix=/usr/local
AC_DEFINE_UNQUOTED(CONFIG_FILE_PATH, "`eval echo "${sysconfdir}/sagan.conf"`", [Sagan configuration file]) 

AC_DEFINE_UNQUOTED(PACKAGE_NAME, "sagan" )
AC_DEFINE_UNQUOTED(PACKAGE_STRING, "Sagan $VERSION")
AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "cclark@quadrantsec.com" )
AC_DEFINE_UNQUOTED(PACKAGE_TARNAME, "sagan" )
AC_DEFINE_UNQUOTED(PACKAGE_VERSION, "$VERSION" )

AC_CONFIG_FILES([ \
Makefile \
src/Makefile])


# AC_OUTPUT(Makefile)
AC_OUTPUT

AC_MSG_RESULT([])
AC_MSG_RESULT([  ,-._,-.    Sagan has been configured!])
AC_MSG_RESULT([  \/)"(\/ ])
AC_MSG_RESULT([   (_o_)     Champ Clark III & The Quadrant InfoSec Team [[quadrantsec.com]]])
AC_MSG_RESULT([   /   \/)   Copyright (C) 2009-2015 Quadrant Information Security, et al.])
AC_MSG_RESULT([  (|| ||) ])
AC_MSG_RESULT([   oo-oo  ]) 
AC_MSG_RESULT([])


