dnl Process this file with autoconf to produce a configure script.
AC_INIT([pen],[0.35.0])
AC_CONFIG_SRCDIR([pen.c])
AC_CONFIG_HEADERS(config.h)
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
AC_CHECK_FUNC(accept4, AC_DEFINE(HAVE_ACCEPT4, 1, [#undef HAVE_ACCEPT4]))

dnl Check things for pen

AC_CHECK_HEADERS([sys/select.h])

AC_ARG_ENABLE(profiling,
	[  --enable-profiling      enable profiling],
	[ if test "$withval" != "no"; then
		CFLAGS="$CFLAGS -pg"
	fi ])

AC_ARG_ENABLE(debugging, AS_HELP_STRING([--enable-debugging], [enable debugging messages]))
AS_IF([test "$enable_debugging" != "no"], [CFLAGS="$CFLAGS -DDEBUGGING"])

AC_ARG_WITH(daemon,
	[  --with-daemon           use daemon() if available],
	[ if test "$withval" != "no"; then
		AC_CHECK_FUNC(daemon,
			AC_DEFINE([HAVE_DAEMON], 1, [#undef HAVE_DAEMON]))
	fi ])

AC_ARG_WITH(poll, AS_HELP_STRING([--with-poll], [use poll() if available]))
AS_IF([test "$with_poll" != "no"],
	AC_CHECK_FUNC(poll,
		AC_DEFINE([HAVE_POLL], 1, [#undef HAVE_POLL])))

AC_ARG_WITH(epoll, AS_HELP_STRING([--with-epoll], [use epoll if available]))
AS_IF([test "$with_epoll" != "no"],
	AC_CHECK_FUNC(epoll_create1,
		AC_DEFINE([HAVE_EPOLL], 1, [#undef HAVE_EPOLL])))

AC_ARG_WITH(kqueue, AS_HELP_STRING([--with-kqueue], [use kqueue() if available]))
AS_IF([test "$with_kqueue" != "no"],
	AC_CHECK_FUNC(kqueue,
		AC_DEFINE([HAVE_KQUEUE], 1, [#undef HAVE_KQUEUE])))

AC_ARG_WITH(fd_setsize,
	[  --with-fd_setsize=N     set FD_SETSIZE to N (see INSTALL)],
	[ if test "$withval" != "no"; then
		AC_DEFINE_UNQUOTED([FD_SETSIZE], $withval, [#undef FD_SETSIZE])
	fi ])

AC_ARG_WITH(ssl, AS_HELP_STRING([--with-ssl], [use SSL (default /usr/local/ssl)]))
AS_IF([test "$with_ssl" != "no"],
	AC_CHECK_LIB(crypto, main)
	AC_CHECK_LIB(ssl, main))

dnl Some people think the EC stuff is patented and needs to be stripped out
AC_CHECK_FUNC(EC_KEY_new_by_curve_name,
	AC_DEFINE([HAVE_EC_KEY], 1, [#undef HAVE_EC_KEY]))

AC_ARG_WITH(geoip, AS_HELP_STRING([--with-geoip], [use libgeoip]))
AS_IF([test "$with_geoip" != "no"],
	AC_CHECK_LIB([GeoIP], [GeoIP_country_code_by_addr]))

AC_ARG_WITH(dsr, AS_HELP_STRING([--with-dsr], [enable direct server return]))
AS_IF([test "$with_dsr" != "no"],
	[ AC_CHECK_HEADERS([linux/if_packet.h])
	AC_CHECK_HEADERS([net/netmap_user.h])])

docdir='${prefix}/doc/pen'
AC_ARG_WITH(docdir,
	[  --with-docdir=DIR       install docs in DIR [[PREFIX/doc/pen]]],
	[ if test "$withval" != "yes" && test "$withval" != "no"; then
		docdir=$withval
	fi ])
AC_SUBST(docdir)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

