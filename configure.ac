#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

VERSION=`cat src/version.h | grep "#define VERSION " | sed -e 's/^.*\"\(.*\)\"/\1/'`

AC_INIT([sagan], m4_esyscmd_s([cat src/version.h | cut -d\" -f2]))
AC_CONFIG_SRCDIR([src])
AC_CANONICAL_SYSTEM
AC_GNU_SOURCE
AC_CONFIG_MACRO_DIR([m4])
AM_MAINTAINER_MODE([disable])

# Check OS

AC_MSG_CHECKING([host os])

# If no host OS,  try uname

if test -z "$host" ; then
        host="`uname`"
fi

echo -n "installation for $host OS... "

    case "$host" in
        *-*-*freebsd*)
            CFLAGS="${CFLAGS} -D__FreeBSD__"
            CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libnet11"
            LDFLAGS="${LDFLAGS} -L/usr/local/lib -L/usr/local/lib/libnet11"
            ;;
        *-*-openbsd*)
            CFLAGS="${CFLAGS} -D__OpenBSD__"
            CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libnet-1.1"
            LDFLAGS="${LDFLAGS} -L/usr/local/lib -I/usr/local/lib/libnet-1.1"
            ;;
        *darwin*|*Darwin*)
            CFLAGS="${CFLAGS} -D__Darwin__"
            CPPFLAGS="${CPPFLAGS} -I/opt/local/include"
            LDFLAGS="${LDFLAGS} -L/opt/local/lib"
            ;;
        *-*-linux*)
	    CFLAGS="${CFLAGS} -D__Linux__"
            #for now do nothing
            ;;
#        *-*-mingw32*)
#            CFLAGS="${CFLAGS} -DOS_WIN32"
#            LDFLAGS="${LDFLAGS} -lws2_32"
#            WINDOWS_PATH="yes"
#            ;;
#        *-*-cygwin)
#            WINDOWS_PATH="yes"
#            ;;
#        *-*-solaris*)
#            AC_MSG_WARN([support for Solaris/Illumos/SunOS is experimental])
#            LDFLAGS="${LDFLAGS} -lsocket -lnsl"
#            ;;
        *)
            AC_MSG_WARN([unsupported OS this may or may not work])
            ;;
    esac
    AC_MSG_RESULT(ok)



AC_C_BIGENDIAN(AC_SUBST([ENDIAN],[big]),AC_SUBST([ENDIAN],[little]))

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

AC_ARG_ENABLE(geoip,
  [  --enable-geoip          Enable Maxmind GeoIP support.],
  [ GEOIP="$enableval"],
  [ GEOIP="no" ]
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

AC_ARG_ENABLE(redis,
  [  --enable-redis  Enable Redis support.],
  [ REDIS="$enableval"],
  [ REDIS="no" ]
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

AC_ARG_WITH(geoip_includes,
        [  --with-geoip-includes=DIR    Maxmind GeoIP include directory],
        [with_geoip_includes="$withval"],[with_geoip_includes="no"])

AC_ARG_WITH(geoip_libraries,
        [  --with-geoip-libraries=DIR   Maxmind GeoIP library directory],
        [with_geoip_libraries="$withval"],[with_geoip_libraries="no"])

if test "x$with_geoip_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_geoip_includes}"
   fi

if test "x$with_geoip_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS}  -L${with_geoip_libraries}"
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

AC_ARG_ENABLE(libfastjson,
  [  --disable-libfastjson         Disable libfastjson support.],
  [ FASTJSON="$enableval"],
  [ FASTJSON="yes" ]
)

AC_ARG_WITH(libfastjson_includes,
        [  --with-libfastjson-includes=DIR    libfastjson include directory],
        [with_libfastjson_includes="$withval"],[with_libfastjson_includes="no"])

AC_ARG_WITH(libfastjson_c_libraries,
        [  --with-libfastjson-libraries=DIR   libfastjson library directory],
        [with_libfastjson_libraries="$withval"],[with_libfastjson_libraries="no"])

if test "x$with_libfastjson_includes" != "xno"; then
   CPPFLAGS="${CPPFLAGS} -I${with_libfastjson_includes}"
   fi

if test "x$with_libfastjson_libraries" != "xno"; then
   LDFLAGS="${LDFLAGS}  -L${with_libfastjson_libraries}"
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

AC_SUBST(VERSION)
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_LANG_C
AC_PROG_MAKE_SET

AM_PROG_CC_C_O

PKG_PROG_PKG_CONFIG

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_CHECK_HEADERS([stdio.h stdlib.h sys/types.h unistd.h stdint.h inttypes.h ctype.h errno.h fcntl.h sys/stat.h string.h getopt.h time.h stdarg.h limits.h stdbool.h arpa/inet.h netinet/in.h sys/time.h sys/socket.h sys/mmap.h sys/mman.h sys/prctl.h libgen.h])

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

AC_CHECK_FUNCS([select strstr strchr strcmp strlen sizeof write snprintf strncat strlcat strlcpy getopt_long gethostbyname socket htons connect send recv dup2 strspn strdup memset access ftruncate strerror mmap shm_open gettimeofday])

AC_CHECK_LIB(m, main,,AC_MSG_ERROR(Sagan needs libm!))

# OSX doesn't have librt - this needs to be fixed!

AC_CHECK_LIB(rt, main,,AC_MSG_ERROR(Sagan needs librt!))

# libpthread
AC_ARG_WITH(libpthread_includes,
        [  --with-libpthread-includes=DIR  libpthread include directory],
        [with_libpthread_includes="$withval"],[with_libpthread_includes=no])
AC_ARG_WITH(libpthread_libraries,
        [  --with-libpthread-libraries=DIR    libpthread library directory],
        [with_libpthread_libraries="$withval"],[with_libpthread_libraries="no"])

if test "$with_libpthread_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libpthread_includes}"
fi

dnl AC_CHECK_HEADER(pthread.h,,[AC_ERROR(pthread.h not found ...)])

if test "$with_libpthread_libraries" != "no"; then
    LDFLAGS="${LDFLAGS}  -L${with_libpthread_libraries}"
fi

PTHREAD=""
AC_CHECK_LIB(pthread, pthread_create,, PTHREAD="no")

if test "$PTHREAD" = "no"; then
    echo
    echo "   ERROR! libpthread library not found,"
    echo
    exit 1
fi

# libyaml

AC_ARG_WITH(libyaml_includes,
        [  --with-libyaml-includes=DIR  libyaml include directory],
        [with_libyaml_includes="$withval"],[with_libyaml_includes=no])
AC_ARG_WITH(libyaml_libraries,
        [  --with-libyaml-libraries=DIR    libyaml library directory],
        [with_libyaml_libraries="$withval"],[with_libyaml_libraries="no"])

if test "$with_libyaml_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libyaml_includes}"
fi

AC_CHECK_HEADER(yaml.h,,LIBYAML="no")

if test "$with_libyaml_libraries" != "no"; then
    LDFLAGS="${LDFLAGS} -L${with_libyaml_libraries}"
fi

LIBYAML=""
AC_CHECK_LIB(yaml,yaml_parser_initialize,,LIBYAML="no")

if test "$LIBYAML" = "no"; then
    echo
    echo "   ERROR!  libyaml library not found, go get it"
    echo "   from http://pyyaml.org/wiki/LibYAML "
    echo "   or your distribution:"
    echo
    echo "   Debian/Ubuntu: apt-get install libyaml-dev"
    echo "   Fedora: yum install libyaml-devel"
    echo
    exit 1
fi


##############################################################################
# libpcre - This section was taken from the Suricata configure.ac.  It does
# some extra checks and enabled PCRE JIT - 2016/11/01
##############################################################################

AC_ARG_WITH(libpcre_includes,
        [  --with-libpcre-includes=DIR  libpcre include directory],
        [with_libpcre_includes="$withval"],[with_libpcre_includes=no])
AC_ARG_WITH(libpcre_libraries,
        [  --with-libpcre-libraries=DIR    libpcre library directory],
        [with_libpcre_libraries="$withval"],[with_libpcre_libraries="no"])

if test "$with_libpcre_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libpcre_includes}"
fi

AC_CHECK_HEADER(pcre.h,,[AC_ERROR(pcre.h not found ...)])

if test "$with_libpcre_libraries" != "no"; then
    LDFLAGS="${LDFLAGS} -L${with_libpcre_libraries}"
fi

PCRE=""
AC_CHECK_LIB(pcre, pcre_get_substring,, PCRE="no")
if test "$PCRE" = "no"; then
    echo
    echo "   ERROR!  pcre library not found, go get it"
    echo "   from www.pcre.org."
    echo
    exit 1
fi

# libpcre 8.35 (especially on debian) has a known issue that results in segfaults
if test "$with_libpcre_libraries" = "no"; then
    PKG_CHECK_MODULES(LIBPCREVERSION, [libpcre = 8.35],[libpcre_buggy_found="yes"],[libprce_buggy_found="no"])
    if test "$libpcre_buggy_found" = "yes"; then
        echo
        echo "   Warning! vulnerable libpcre version 8.35 found"
        echo "   This version has a known issue that could result in segfaults"
        echo "   please upgrade to a newer version of pcre which you can get from"
        echo "   www.pcre.org. For more information, see issue #1693"
        echo
        echo "   Continuing for now with JIT disabled..."
        echo
    fi
fi

# To prevent duping the lib link we reset LIBS after this check. Setting action-if-found to NULL doesn't seem to work
# see: http://blog.flameeyes.eu/2008/04/29/i-consider-ac_check_lib-harmful
PCRE=""
TMPLIBS="${LIBS}"
AC_CHECK_LIB(pcre, pcre_dfa_exec,, PCRE="no")
if test "$PCRE" = "no"; then
    echo
    echo "   ERROR!  pcre library was found but version was < 6.0"
    echo "   please upgrade to a newer version of pcre which you can get from"
    echo "   www.pcre.org."
    echo
    exit 1
fi
LIBS="${TMPLIBS}"

AC_TRY_COMPILE([ #include <pcre.h> ],
    [ int eo = 0; eo |= PCRE_EXTRA_MATCH_LIMIT_RECURSION; ],
    [ pcre_match_limit_recursion_available=yes ], [:]
)

if test "$pcre_match_limit_recursion_available" != "yes"; then
    echo
    echo "   Warning! pcre extra opt PCRE_EXTRA_MATCH_LIMIT_RECURSION not found"
    echo "   This could lead to potential DoS please upgrade to pcre >= 6.5"
    echo "   from www.pcre.org."
    echo "   Continuing for now...."
    echo
    AC_DEFINE([NO_PCRE_MATCH_RLIMIT],[1],[Pcre PCRE_EXTRA_MATCH_LIMIT_RECURSION not available])
fi

TMPCFLAGS="${CFLAGS}"
CFLAGS="-O0 -g -Werror -Wall"
AC_TRY_COMPILE([ #include <pcre.h> ],
    [ pcre_extra *extra = NULL; pcre_free_study(extra); ],
    [ AC_DEFINE([HAVE_PCRE_FREE_STUDY], [1], [Pcre pcre_free_study supported])], [:]
)
CFLAGS="${TMPCFLAGS}"


#enable support for PCRE-jit available since pcre-8.20
AC_MSG_CHECKING(for PCRE JIT support)
AC_TRY_COMPILE([ #include <pcre.h> ],
    [
    int jit = 0;
    pcre_config(PCRE_CONFIG_JIT, &jit);
    ],
    [ pcre_jit_available=yes ], [ pcre_jit_available=no ]
    )

# bug 1693, libpcre 8.35 is broken and debian jessie is still using that
if test "$libpcre_buggy_found" = "yes"; then
    pcre_jit_available="no, libpcre 8.35 blacklisted"
fi


if test "x$pcre_jit_available" = "xyes"; then
   AC_MSG_RESULT(yes)
   AC_DEFINE([PCRE_HAVE_JIT], [1], [Pcre with JIT compiler support enabled])

   AC_MSG_CHECKING(for PCRE JIT support usability)
   AC_TRY_COMPILE([ #include <pcre.h> ],
       [
       const char* regexstr = "(a|b|c|d)";
       pcre *re;
       const char *error;
       pcre_extra *extra;
       int err_offset;
       re = pcre_compile(regexstr,0, &error, &err_offset,NULL);
       extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &error);
       if (extra == NULL)
           exit(EXIT_FAILURE);
       int jit = 0;
       int ret = pcre_fullinfo(re, extra, PCRE_INFO_JIT, &jit);
       if (ret != 0 || jit != 1)
           exit(EXIT_FAILURE);
       exit(EXIT_SUCCESS);
       ],
       [ pcre_jit_works=yes ], [:]
   )
   if test "x$pcre_jit_works" != "xyes"; then
       AC_MSG_RESULT(no)
       echo
       echo "   PCRE JIT support detection worked but testing it failed"
       echo "   something odd is going on, please file a bug report."
       echo
       exit 1
   else
       AC_MSG_RESULT(yes)
   fi
else
    AC_MSG_RESULT(no)
fi

#### End of PCRE ############################################################

# We don't want to use the Sagan_strstr assembly code if this is a 32 bit
# system.  We force SYSSTRSR="yes" when it is. 

# 32 bit linux. 

case "${host}" in
   # Linux | i386 | 32 bit 
   i386*-*-linux* | i686*-*-linux*)
   SYSSTRSTR="yes"
   ;;

   i386*-*-darwin* | i686*-*-darwin*)
   SYSSTRSTR="yes" 
   ;;

esac



if test "$SYSSTRSTR" = "yes"; then
	AC_MSG_RESULT([using build in strstr()...])
	AC_DEFINE(WITH_SYSSTRSTR, 1, With system strstr)
	fi

if test "$SYSLOG" = "yes"; then
	AC_MSG_RESULT([------- Syslog support is enabled -------])
	AC_CHECK_HEADER([syslog.h])
	AC_DEFINE(WITH_SYSLOG, 1, With Syslog)
	fi

if test "$REDIS" = "yes"; then
       AC_MSG_RESULT([------- Redis support is enabled -------])
       AC_CHECK_HEADER([hiredis/hiredis.h])
       AC_CHECK_LIB(hiredis, main,,AC_MSG_ERROR(The Hiredis (Redis) library cannot be found.
If you're not interested in Redis support use the --disable-redis flag.))
       fi

if test "$GEOIP" = "yes"; then
       AC_MSG_RESULT([------- Maxmind GeoIP support is enabled -------])
       AC_CHECK_HEADER([maxminddb.h])
       AC_CHECK_LIB(maxminddb, main,,AC_MSG_ERROR(The Maxmind GeoIP library cannot be found.
If you're not interested in GeoIP support use the --disable-geoip flag.))
       fi

if test "$ESMTP" = "yes"; then
       AC_MSG_RESULT([------- libesmtp support is enabled -------])
       AC_CHECK_HEADER([libesmtp.h])
       AC_CHECK_LIB(esmtp, main,,AC_MSG_ERROR(The libesmtp library cannot be found.
If you're not interested in libesmtp support use the --disable-esmtp flag.))
       fi


if test "$FASTJSON" = "yes"; then
	AC_MSG_RESULT([------- libfastjson support is enabled -------])
	PKG_CHECK_MODULES(LIBFASTJSON, libfastjson >= 0.0.0)
	AC_CHECK_LIB(fastjson, main,,AC_MSG_ERROR(The libfastjson library cannot be found.
This library can be located at https://github.com/rsyslog/libfastjson. ))
	fi

if test "$LOGNORM" = "yes"; then
       AC_MSG_RESULT([------- liblognorm support is enabled -------])
       PKG_CHECK_MODULES(LIBESTR, libestr >= 0.0.0)
       PKG_CHECK_MODULES(LIBLOGNORM, lognorm >= 1.0.0)
       PKG_CHECK_MODULES(LIBFASTJSON, libfastjson >= 0.0.0)
       AC_CHECK_HEADER([liblognorm.h])
       AC_CHECK_HEADER([libestr.h])
       AC_CHECK_LIB(fastjson, main,,AC_MSG_ERROR(The libfastjson library cannot be found.
This library is used by liblognorm for log correlation.  Please see:
https://wiki.quadrantsec.com/bin/view/Main/LibLogNorm. To disable this feature
use the --disable-lognorm flag. 
This library can be located at https://github.com/rsyslog/libfastjson. ))
       AC_CHECK_LIB(estr, main,,AC_MSG_ERROR(The libestr library cannot be found.
This library is important for log correlation. Please see:
https://wiki.quadrantsec.com/bin/view/Main/LibLogNorm. To disable this feature
use the --disable-lognorm flag. ))
      AC_CHECK_LIB(lognorm, main,,AC_MSG_ERROR(The liblognorm library cannot be found.
This library is important for log correlation. Please see:
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

if test "$BLUEDOT" = "yes"; then
        AC_MSG_RESULT([------- Quadrant "Bluedot" is enabled -------])
        AC_DEFINE(WITH_BLUEDOT, 1, With Bluedot)
	PKG_CHECK_MODULES(LIBFASTJSON, libfastjson >= 0.0.0)
        fi

test "x$prefix" = x. || test "x$prefix" = xNONE && prefix=/usr/local
AC_DEFINE_UNQUOTED(CONFIG_FILE_PATH, "`eval echo "${sysconfdir}/sagan.yaml"`", [Sagan configuration file]) 

AC_DEFINE_UNQUOTED(PACKAGE_NAME, "sagan" )
AC_DEFINE_UNQUOTED(PACKAGE_STRING, "Sagan $VERSION")
AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "cclark@quadrantsec.com" )
AC_DEFINE_UNQUOTED(PACKAGE_TARNAME, "sagan" )
AC_DEFINE_UNQUOTED(PACKAGE_VERSION, "$VERSION" )

AC_CONFIG_FILES([ \
Makefile \
src/Makefile \
tools/Makefile])


# AC_OUTPUT(Makefile)
AC_OUTPUT

AC_MSG_RESULT([])
AC_MSG_RESULT([  ,-._,-.    Sagan has been configured!])
AC_MSG_RESULT([  \/)"(\/ ])
AC_MSG_RESULT([   (_o_)     Champ Clark III & The Quadrant InfoSec Team [[quadrantsec.com]]])
AC_MSG_RESULT([   /   \/)   Copyright (C) 2009-2020 Quadrant Information Security, et al.])
AC_MSG_RESULT([  (|| ||) ])
AC_MSG_RESULT([   oo-oo  ]) 
AC_MSG_RESULT([])


