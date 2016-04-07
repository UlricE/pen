/*
   Copyright (C) 2002-2015  Ulric Eriksson <ulric@siag.nu>

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>
#include <pwd.h>
#include <errno.h>
#include <ctype.h>
#include "diag.h"
#include "settings.h"

#define PEN_MAX 1000	/* make that at least 1000 for prod */

/* This structure is statically allocated, which is wasteful but saves us
   from frequest memory allocation.
*/
static struct penlog {
	struct in_addr addr;
	char client[100];
	char request[100];
} *penlog;

static int pen_n = 0;		/* next slot in buffer */

static int unbuffer = 0;
static char *logfile = NULL;
static FILE *logfp;
static char *pidfile = NULL;
static int loopflag = 1;
static int do_restart_log = 0;
static int pen_max = PEN_MAX;
static char *user = NULL, *jail = NULL;

static struct sigaction hupaction, termaction;

static void restart_log(int dummy)
{
	do_restart_log = 1;
	sigaction(SIGHUP, &hupaction, NULL);
}

static void quit(int dummy)
{
	loopflag = 0;
}

static void store_web(char *b, int n, struct in_addr addr)
{
	char request[1024];
	char *p, *q;
	int i, m;

	b[n] = '\0';
	if (debuglevel > 1) debug("store_web(%s, %d)", b, n);
	p = strchr(b, '"');
	if (p == NULL) {
		debug("bogus web line %s", b);
		return;
	}
	p++;
	q = strchr(p, '"');
	if (q == NULL) {
		debug("bogus line %s", b);
		return;
	}
	memcpy(request, p, q-p);
	request[q-p] = '\0';
	if (q-p < 100) m = q-p;
	else m = 100;
	i = pen_n-1;
	if (i < 0) i = pen_max-1;
	while (i != pen_n) {
		if (penlog[i].request[0] &&
		    addr.s_addr == penlog[i].addr.s_addr &&
		    !strncmp(request, penlog[i].request, m)) {
			break;
		}
		i--;
		if (i < 0) i = pen_max-1;
	}

	if (i == pen_n) {	/* no match */
		fwrite(b, 1, n, logfp);
	} else {
		fputs(penlog[i].client, logfp);
		p = strchr(b, ' ');
		if (p == NULL) {
			if (debuglevel) debug("Ugly");
			return;
		}
		fwrite(p, 1, n-(p-b), logfp);
	}
}

static void store_pen(char *b, int n)
{
	char client[100], server[100], request[100];
#ifdef HAVE_INET_ATON
	struct in_addr addr;
#else
	struct hostent *hp;
#endif

	b[n] = '\0';
	if (sscanf(b, "+ %99[^ ] %99[^ ] %99[^\n]",
		   client, server, request) != 3) {
		debug("discarding bogus pen line %s", b);
		return;
	}
	if (debuglevel > 1)
		debug("store_pen(%i: %s, %s, %s)",pen_n, client, server, request);

#ifdef HAVE_INET_ATON
	if (inet_aton(server, &addr) == 0) {
		debug("bogus address %s", server);
		return;
	}
	penlog[pen_n].addr = addr;
#else
	hp = gethostbyname(server);
	memcpy(&penlog[pen_n].addr, hp->h_addr, hp->h_length);
#endif


	strncpy(penlog[pen_n].client, client, 100);
	strncpy(penlog[pen_n].request, request, 100);
	pen_n++;
	if (pen_n >= pen_max) pen_n = 0;
}

static void usage(void)
{
	printf("Usage:\n"
	       "  penlogd [options] port\n"
	       "\n"
	       "  -d        debugging on\n"
	       "  -f        stay in foreground\n"
	       "  -j dir    run in chroot\n"
	       "  -l file   write log to file\n"
	       "  -b        unbuffer output (Testing Only!)\n"
	       "  -n N      number of pen log entries to cache [1000]\n"
	       "  -p file   write pid to file\n"
	       "  -u user   run as alternative user\n");
	exit(0);
}

static void background(void)
{
#ifdef HAVE_DAEMON
	daemon(0, 0);
#else
	int childpid;
	if ((childpid = fork()) < 0) {
		error("Can't fork");
	} else {
		if (childpid > 0) exit(0);	/* parent */
	}
	setsid();
	signal(SIGCHLD, SIG_IGN);
#endif
}

static int options(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "j:l:n:p:u:dfb")) != -1) {
		switch (c) {
		case 'd':
			debuglevel++;
			break;
		case 'b':
			unbuffer = 1;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'j':
			jail = optarg;
			break;
		case 'l':
			logfile = optarg;
			break;
		case 'n':
			pen_max = atoi(optarg);
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
		}
	}

	return optind;
}

int main(int argc, char **argv)
{
	struct passwd *pwd = NULL;
	struct sockaddr_in a;
	socklen_t len;
	int ld, p;
	char b[1024];

	int n = options(argc, argv);
	argc -= n;
	argv += n;

	if (argc < 1 || (p = atoi(argv[0])) == 0) {
		usage();
		exit(0);
	}

	penlog = malloc(pen_max * sizeof *penlog);
	if (!penlog) error("Can't allocate penlog");

	if (!foreground) background();

	if (user) {
		if (debuglevel) debug("Run as user %s", user);
		pwd = getpwnam(user);
		if (pwd == NULL) error("Can't getpwnam(%s)", user);
	}
	if (jail) {
		if (debuglevel) debug("Run in %s", jail);
		if (chroot(jail) == -1) error("Can't chroot(%s)", jail);
	}
	if (pwd) {
		if (setuid(pwd->pw_uid) == -1)
			error("Can't setuid(%d)", (int)pwd->pw_uid);
	}
	if (logfile) {
		if (debuglevel) debug("Logging to %s", logfile);
		logfp = fopen(logfile, "a");
		if (!logfp) error("Can't open logfile %s", logfile);
		if (unbuffer) setvbuf(logfp, (char *)NULL, _IOLBF, 0);
	} else {
		if (debuglevel) debug("Logging to stdout");
		logfp = stdout;
	}
	if (pidfile) {
		FILE *pidfp = fopen(pidfile, "w");
		if (debuglevel) {
			debug("Writing pid %d to %s",
				(int)getpid(), pidfile);
		}
		if (!pidfp) error("Can't create pidfile %s", pidfile);
		fprintf(pidfp, "%d", (int)getpid());
		fclose(pidfp);
	}

	if ((ld = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		error("Problem creating socket");
	}

	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_ANY);
	a.sin_port = htons(p);

	if (bind(ld, (struct sockaddr *) &a, sizeof(a)) < 0) {
		error("Problem binding");
	}

	len = sizeof a;
	if (getsockname(ld, (struct sockaddr *) &a, &len) < 0) {
		error("Error getsockname");
	}

	hupaction.sa_handler = restart_log;
	sigemptyset(&hupaction.sa_mask);
	hupaction.sa_flags = 0;
	sigaction(SIGHUP, &hupaction, NULL);
	termaction.sa_handler = quit;
	sigemptyset(&termaction.sa_mask);
	termaction.sa_flags = 0;
	sigaction(SIGTERM, &termaction, NULL);

	loopflag = 1;

	if (debuglevel) debug("Enter main loop\n");

	while (loopflag) {
		if (do_restart_log) {
			if (debuglevel) debug("Reopen log file %s", logfile);
			if (logfp != stdout) {
				fclose(logfp);
				logfp = fopen(logfile, "a");
				if (!logfp) error("Can't open %s", logfile);
				if (unbuffer) setvbuf(logfp, (char *)NULL, _IOLBF, 0);
			}
			do_restart_log = 0;
		}
		n = recvfrom(ld, b, sizeof b, 0, (struct sockaddr *) &a, &len);

		if (n < 0) {
			if (errno != EINTR)
				debug("Error receiving data: %s", strerror(errno));
			continue;
		}
		b[n] = 0;
		if (b[0] == '+') {
			store_pen(b, n);
		} else {
			store_web(b, n, a.sin_addr);
		}
	}

	if (debuglevel) debug("Exit main loop");

	if (logfp) fclose(logfp);
	if (pidfile) unlink(pidfile);
	return 0;
}
