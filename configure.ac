AC_INIT(stt, 0.9.9g)
AC_CONFIG_SRCDIR(testtool.c)
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
AC_CANONICAL_HOST

case $host_os in
linux*)
    CFLAGS="$CFLAGS -DLINUX -D_GNU_SOURCE"
    ;;
darwin*)
    CFLAGS="$CFLAGS -DDARWIN -D__APPLE_USE_RFC_2292"
    ;;
freebsd*)
    CFLAGS="$CFLAGS -DFREEBSD"
    ;;
esac

AC_CHECK_HEADERS()
AC_CHECK_MEMBER(struct sockaddr_in.sin_len,
                AC_DEFINE(HAVE_SIN_LEN, 1, [Define this if struct sockaddr_in has a  sin_len field.]),,
                [#ifdef HAVE_SYS_TYPES_H
                 #include <sys/types.h>
                 #endif
                 #include <netinet/in.h>])

AC_CHECK_MEMBER(struct sockaddr_in6.sin6_len,
                AC_DEFINE(HAVE_SIN6_LEN, 1, [Define this if struct sockaddr_in6 has a  sin6_len field.]),,
                [#ifdef HAVE_SYS_TYPES_H
                 #include <sys/types.h>
                 #endif
                 #include <netinet/in.h>])

PKG_CHECK_MODULES([GUILE], [guile-2.2])

AC_OUTPUT(Makefile)
