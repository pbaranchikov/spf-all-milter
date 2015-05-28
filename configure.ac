AC_INIT([Spf +all regection milter], [0.0.1])
AM_INIT_AUTOMAKE()
AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CC_C_O

CFLAGS="${CFLAGS} -Wall -Werror -lresolv"

AC_HEADER_STDC
AC_CHECK_HEADERS([resolv.h])

AM_CONDITIONAL(VZVR, test x$with_vzvr == xyes)
AM_CONDITIONAL(RAMDISK, test x$with_ramdisk == xyes)

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
