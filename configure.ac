dnl Process this file with autoconf to produce a configure script.
AC_INIT([pen],[0.21.1])
AC_CONFIG_SRCDIR([pen.c])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_ISC_POSIX

dnl Checks for libraries.
AC_CHECK_LIB(socket, main)
AC_CHECK_LIB(nsl, main)
dnl Next line is for Solaris
AC_CHECK_LIB(resolv, inet_aton)

dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_MAJOR

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

if test "$GCC" = "yes"; then
	CFLAGS="-Wall $CFLAGS"
fi

dnl Checks for library functions.
dnl AC_CHECK_FUNC(inet_aton, AC_DEFINE(HAVE_INET_ATON, 1, [#undef HAVE_INET_ATON]))
AC_CHECK_FUNC(getaddrinfo, AC_DEFINE(HAVE_GETADDRINFO, 1, [#undef HAVE_GETADDRINFO]))


dnl Check things for pen

AC_ARG_ENABLE(profiling,
	[  --enable-profiling      enable profiling],
	[ if test "$withval" != "no"; then
		CFLAGS="$CFLAGS -pg"
	fi ])
AC_ARG_WITH(daemon,
	[  --with-daemon           use daemon() if available],
	[ if test "$withval" != "no"; then
		AC_CHECK_FUNC(daemon,
			AC_DEFINE([HAVE_DAEMON], 1, [#undef HAVE_DAEMON]))
	fi ])
AC_ARG_WITH(poll,
	[  --with-poll             use poll() if available],
	[ if test "$withval" != "no"; then
		AC_CHECK_FUNC(poll,
			AC_DEFINE([HAVE_POLL], 1, [#undef HAVE_POLL]))
	fi ])
AC_ARG_WITH(kqueue,
	[  --with-kqueue           use kqueue() if available],
	[ if test "$withval" != "no"; then
		AC_CHECK_FUNC(kqueue,
			AC_DEFINE([HAVE_KQUEUE], 1, [#undef HAVE_KQUEUE]))
	fi ])
AC_ARG_WITH(fd_setsize,
	[  --with-fd_setsize=N     set FD_SETSIZE to N (see INSTALL)],
	[ if test "$withval" != "no"; then
		AC_DEFINE_UNQUOTED([FD_SETSIZE], $withval, [#undef FD_SETSIZE])
	fi ])
AC_ARG_WITH(ssl,
	[  --with-ssl=DIR          use SSL (default /usr/local/ssl)],
	[ case "$withval" in
	yes )
		TRY_SSL=/usr/local/ssl
		;;
	no )
		;;
	* )
		TRY_SSL="$withval"
		;;
	esac
	if test ! -z "$TRY_SSL"; then
		LDFLAGS="$LDFLAGS -L$TRY_SSL/lib"
		LIBS="-lssl -lcrypto $LIBS"
		CFLAGS="$CFLAGS -I$TRY_SSL/include"
		AC_DEFINE([HAVE_SSL], 1, [#undef HAVE_SSL])
	fi ])
AC_ARG_WITH(geoip,
	[  --with-geoip            use libgeoip],
	[ if test "$withval" != "no"; then
		LIBS="-lGeoIP $LIBS"
		AC_DEFINE([HAVE_GEOIP], 1, [#undef HAVE_GEOIP])
	fi ])

docdir='${prefix}/doc/pen'
AC_ARG_WITH(docdir,
	[  --with-docdir=DIR       install docs in DIR [[PREFIX/doc/pen]]],
	[ if test "$withval" != "yes" && test "$withval" != "no"; then
		docdir=$withval
	fi ])
AC_SUBST(docdir)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

