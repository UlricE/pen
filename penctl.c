/*
   Copyright (C) 2000-2015  Ulric Eriksson <ulric@siag.nu>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA.
*/

#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
//#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

#include "config.h"

static void error(char *fmt, ...)
{
	char b[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	fprintf(stderr, "%s\n", b);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static void alarm_handler(int dummy)
{
	;
}

static void usage(void)
{
	printf("usage: penctl host:port command\n");
	exit(0);
}

static int open_unix_socket(char *path)
{
	int n, fd;
	struct sockaddr_un serv_addr;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) error("error opening socket");
	memset(&serv_addr, 0, sizeof serv_addr);
	serv_addr.sun_family = AF_UNIX;
	snprintf(serv_addr.sun_path, sizeof serv_addr.sun_path, "%s", path);
	n = connect(fd, (struct sockaddr *)&serv_addr, sizeof serv_addr);
	if (n == -1) {
		error("error connecting to server");
	}
	return fd;
}

static int open_socket(char *addr, char *port)
{
	int fd = -1;
	struct addrinfo *ai;
	struct addrinfo hints;
	struct addrinfo *runp;
	int n;
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;
	n = getaddrinfo(addr, port, &hints, &ai);
	if (n != 0) {
		error("getaddrinfo: %s", gai_strerror(n));
	}
	runp = ai;
	/* only using first result; should try all */
	fd = socket(runp->ai_family, runp->ai_socktype, runp->ai_protocol);

	if (fd < 0) error("error opening socket");
	signal(SIGALRM, alarm_handler);
	n = connect(fd, runp->ai_addr, runp->ai_addrlen);
	alarm(0);
	if (n == -1) {
		error("error connecting to server");
	}
	return fd;
}

int main(int argc, char **argv)
{
	int i, fd, n;
	char b[1024], *p;

	if (argc < 3) {
		usage();
	}

	if (strchr(argv[1], '/')) {
		fd = open_unix_socket(argv[1]);
	} else {
		n = 1+strlen(argv[1]);	/* one for \0 */
		if (n > sizeof b) error("Overlong arg '%s'", argv[1]);
		snprintf(b, sizeof b, "%s", argv[1]);
		/* We need the *last* : to allow such arguments as ::1:10080
		   if pen's control port is ipv6 localhost:10080 */
		p = strrchr(b, ':');
		if (p == NULL) error("no port given");

		*p++ = '\0';

		fd = open_socket(b, p);
	}

	n = 0;
	for (i = 2; argv[i]; i++) {
		for (p = argv[i]; *p; p++) {
			if (n >= (sizeof b)-1) error("Overlong argument list");
			b[n++] = *p;
		}
		b[n++] = ' ';
	}
	if (n >= (sizeof b)-1) error("Overlong argument list");
	b[--n] = '\n';	/* replace last ' ' */
	b[++n] = '\0';	/* terminate string */

	n = write(fd, b, strlen(b));
	if (n == -1) error("error writing to socket");
	for (;;) {
		n = read(fd, b, sizeof b);
		if (n == 0) break;
		if (n == -1) error("error reading from socket");
		n = write(1, b, n);
		if (n == -1) error("error writing to stdout");
	}
	close(fd);

	return 0;
}
