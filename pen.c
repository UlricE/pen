/*
   Copyright (C) 2000-2016  Ulric Eriksson <ulric@siag.nu>

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
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <assert.h>
#ifndef WINDOWS
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <pwd.h>
#endif
#include <signal.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "ssl.h"

#include "pen.h"
#include "acl.h"
#include "client.h"
#include "conn.h"
#include "diag.h"
#include "dlist.h"
#include "dsr.h"
#include "event.h"
#include "idlers.h"
#include "memory.h"
#include "netconv.h"
#include "pen_epoll.h"
#include "pen_kqueue.h"
#include "pen_poll.h"
#include "pen_select.h"
#include "server.h"
#include "settings.h"
#include "windows.h"

#define BUFFER_MAX 	(32*1024)

#define KEEP_MAX	100	/* how much to keep from the URI */

#define DUMMY_MSG "Ulric was here."

static int dummy = 0;		/* use pen as a test target */
time_t now;
static int tcp_nodelay = 0;
static int listen_queue = CONNECTIONS_MAX;

static int asciidump;
static int loopflag;
static int exit_enabled = 0;

static int hupcounter = 0;

#ifndef WINDOWS
static int stats_flag = 0;
static int restart_log_flag = 0;
#endif
static int http = 0;

static char *cfgfile = NULL;
static char *logfile = NULL;
static FILE *logfp = NULL;
static struct sockaddr_in logserver;
static int logsock = -1;
static char *pidfile = NULL;
static FILE *pidfp = NULL;
static char *webfile = NULL;
static char listenport[1000];
static int port;
static int peek = 0;

static int control_acl;
static char *ctrlport = NULL;
int listenfd = -1;
static int ctrlfd = -1;
static char *jail = NULL;
static char *user = NULL;

static char *dsr_if, *dsr_ip;

struct sockaddr_storage *source = NULL;

#ifdef WINDOWS
/* because Windows scribbles over errno in an uncalled-for manner */
static int saved_errno;
#define SAVE_ERRNO (saved_errno = socket_errno)
#define USE_ERRNO (saved_errno)

#else	/* not windows */
#define WOULD_BLOCK(err) (err == EAGAIN || err == EWOULDBLOCK)

#ifndef HAVE_ACCEPT4
static void make_nonblocking(int fd)
{
	int fl;
	DEBUG(2, "make_nonblocking(%d)", fd);
	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		error("Can't fcntl, errno = %d", errno);
	if (fl & O_NONBLOCK) {
		DEBUG(3, "fd %d is already nonblocking", fd);
	} else {
		DEBUG(4, "fd %d is not nonblocking", fd);
		if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) == -1) {
			error("Can't fcntl, errno = %d", errno);
		}
	}
}
#endif

#define SAVE_ERRNO
#define USE_ERRNO (socket_errno)

#endif

/* enable/disable with "tcp_nodelay/no tcp_nodelay" */
static void tcp_nodelay_on(int s)
{
#ifdef TCP_NODELAY
	int one = 1;
	int n = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (void *)&one, sizeof one);
	DEBUG(2, "setsockopt(%d, %d, %d, %p, %d) returns %d",
		s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one, n);
#else
	debug("You don't have TCP_NODELAY");
#endif
}

/* save a few syscalls for modern Linux and BSD */
int socket_nb(int domain, int type, int protocol)
{
#ifdef SOCK_NONBLOCK
	int s = socket(domain, type|SOCK_NONBLOCK, protocol);
	SAVE_ERRNO;
	DEBUG(2, "socket returns %d, socket_errno=%d", s, USE_ERRNO);
	if (s == -1) error("Error opening socket: %s", strerror(USE_ERRNO));
#else
	int s = socket(domain, type, protocol);
	SAVE_ERRNO;
	DEBUG(2, "socket returns %d, socket_errno=%d", s, USE_ERRNO);
	if (s == -1) error("Error opening socket: %s", strerror(USE_ERRNO));
	make_nonblocking(s);
#endif
	if (tcp_nodelay) tcp_nodelay_on(s);
	return s;
}

/* and a few more */
extern int accept4(int, struct sockaddr *, socklen_t *, int);

static int accept_nb(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
#ifdef HAVE_ACCEPT4
	return accept4(sockfd, addr, addrlen, SOCK_NONBLOCK);
#else
	int s = accept(sockfd, addr, addrlen);
	if (s != -1) make_nonblocking(sockfd);
	return s;
#endif
	if (tcp_nodelay) tcp_nodelay_on(sockfd);
}

#ifndef WINDOWS
static struct sigaction alrmaction, hupaction, termaction, usr1action, usr2action;
#endif

static int pen_strncasecmp(const char *p, const char *q, size_t n)
{
	size_t i = 0;
	int c = 0;

	while ((i < n) && !(c = toupper((unsigned char)*p)-toupper((unsigned char)*q)) && *p) {
		p++;
		q++;
		i++;
	}
	return c;
}

static char *pen_strcasestr(const char *haystack, const char *needle)
{
	char *p = (char *)haystack;
	int n = strlen(needle);

	while (*p) {
		if (!pen_strncasecmp(p, needle, n)) return p;
		p++;
	}
	return NULL;
}

static int webstats(void)
{
	FILE *fp;
	int i;
	time_t now;
	struct tm *nowtm;
	char nowstr[80];

	if (webfile == NULL) {
		debug("Don't know where to write web stats; see -w option");
		return 0;
	}
	fp = fopen(webfile, "w");
	if (fp == NULL) {
		debug("Can't write to %s", webfile);
		return 0;
	}
	now=time(NULL);
	nowtm = localtime(&now);
	strftime(nowstr, sizeof(nowstr), "%Y-%m-%d %H:%M:%S", nowtm);
	fprintf(fp,
		"<html>\n"
		"<head>\n"
		"<title>Pen status page</title>\n"
		"</head>\n"
		"<body bgcolor=\"#ffffff\">"
		"<h1>Pen status page</h1>\n");
	fprintf(fp,
		"Time %s, %d servers, %d current<p>\n",
		nowstr, nservers, current);
	fprintf(fp,
		"<table bgcolor=\"#c0c0c0\">\n"
		"<tr>\n"
		"<td bgcolor=\"#80f080\">server</td>\n"
		"<td bgcolor=\"#80f080\">address</td>\n"
		"<td bgcolor=\"#80f080\">status</td>\n"
		"<td bgcolor=\"#80f080\">port</td>\n"
		"<td bgcolor=\"#80f080\">connections</td>\n"
		"<td bgcolor=\"#80f080\">max soft</td>\n"
		"<td bgcolor=\"#80f080\">max hard</td>\n"
		"<td bgcolor=\"#80f080\">sent</td>\n"
		"<td bgcolor=\"#80f080\">received</td>\n"
		"<td bgcolor=\"#80f080\">weight</td>\n"
		"<td bgcolor=\"#80f080\">prio</td>\n"
		"</tr>\n");
	for (i = 0; i < nservers; i++) {
		fprintf(fp,
			"<tr>\n"
			"<td>%d</td>\n"
			"<td>%s</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%" PRIu64 "</td>\n"
			"<td>%" PRIu64 "</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"</tr>\n",
			i, pen_ntoa(&servers[i].addr),
			servers[i].status, pen_getport(&servers[i].addr),
			servers[i].c, servers[i].maxc, servers[i].hard,
			servers[i].sx, servers[i].rx,
			servers[i].weight, servers[i].prio);
	}
	fprintf(fp, "</table>\n");

	fprintf(fp, "<h2>Active clients</h2>");
	fprintf(fp, "Max number of clients: %d<p>", clients_max);
	fprintf(fp,
		"<table bgcolor=\"#c0c0c0\">\n"
		"<tr>\n"
		"<td bgcolor=\"#80f080\">client</td>\n"
		"<td bgcolor=\"#80f080\">address</td>\n"
		"<td bgcolor=\"#80f080\">age(secs)</td>\n"
		"<td bgcolor=\"#80f080\">last server</td>\n"
		"<td bgcolor=\"#80f080\">connects</td>\n"
		"<td bgcolor=\"#80f080\">sent</td>\n"
		"<td bgcolor=\"#80f080\">received</td>\n"
		"</tr>\n");
	for (i = 0; i < clients_max; i++) {
		if (clients[i].last == 0) continue;
		fprintf(fp,
			"<tr>\n"
			"<td>%d</td>\n"
			"<td>%s</td>\n"
			"<td>%ld</td>\n"
			"<td>%d</td>\n"
			"<td>%ld</td>\n"
			"<td>%" PRIu64 "</td>\n"
			"<td>%" PRIu64 "</td>\n"
			"</tr>\n",
			i, pen_ntoa(&clients[i].addr),
			(long)(now-clients[i].last), clients[i].server, clients[i].connects,
			clients[i].csx, clients[i].crx);
	}
	fprintf(fp, "</table>\n");

	fprintf(fp, "<h2>Active connections</h2>");
	fprintf(fp, "Number of connections: %d max, %d used, %d last<p>",
		connections_max, connections_used, connections_last);
	fprintf(fp,
		"<table bgcolor=\"#c0c0c0\">\n"
		"<tr>\n"
		"<td bgcolor=\"#80f080\">connection</td>\n"
		"<td bgcolor=\"#80f080\">downfd</td>\n"
		"<td bgcolor=\"#80f080\">upfd</td>\n"
		"<td bgcolor=\"#80f080\">pending data down</td>\n"
		"<td bgcolor=\"#80f080\">pending data up</td>\n"
		"<td bgcolor=\"#80f080\">client</td>\n"
		"<td bgcolor=\"#80f080\">server</td>\n"
		"</tr>\n");
	for (i = 0; i < connections_max; i++) {
		if (conns[i].downfd == -1) continue;
		fprintf(fp,
			"<tr>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"<td>%d</td>\n"
			"</tr>\n",
			i, conns[i].downfd, conns[i].upfd,
			conns[i].downn, conns[i].upn,
			conns[i].client, conns[i].server);
	}
	fprintf(fp, "</table>\n");
	fprintf(fp,
		"</body>\n"
		"</html>\n");
	fclose(fp);
	return 1;
}

#ifndef WINDOWS
static void textstats(void)
{
	int i;
	time_t now;
	struct tm *nowtm;
	char nowstr[80];

	now=time(NULL);
	nowtm = localtime(&now);
	strftime(nowstr, sizeof(nowstr), "%Y-%m-%d %H:%M:%S", nowtm);

	debug("Time %s, %d servers, %d current",
		nowstr, nservers, current);
	for (i = 0; i < nservers; i++) {
		debug("Server %d status:\n"
			"address %s\n"
			"%d\n"
			"port %d\n"
			"%d connections (%d soft, %d hard)\n"
			"%llu sent, %llu received\n",
			i, pen_ntoa(&servers[i].addr),
			servers[i].status, pen_getport(&servers[i].addr),
			servers[i].c, servers[i].maxc, servers[i].hard,
			servers[i].sx, servers[i].rx);
	}
	debug("Max number of clients: %d", clients_max);
	debug("Active clients:");
	for (i = 0; i < clients_max; i++) {
		if (clients[i].last == 0) continue;
		debug("Client %d status:\n"
			"address %s\n"
			"last used %ld\n"
			"last server %d\n",
			"connects  %ld\n",
			"sent  %llu\n",
			"received  %llu\n",
			i, pen_ntoa(&clients[i].addr),
			(long)(now-clients[i].last), clients[i].server, clients[i].connects,
			clients[i].csx, clients[i].crx);
	}
	debug("Max number of connections: %d", connections_max);
	debug("Active connections:");
	for (i = 0; i < connections_max; i++) {
		if (conns[i].downfd == -1) continue;
		debug("Connection %d status:\n"
			"downfd = %d, upfd = %d\n"
			"pending data %d down, %d up\n"
			"client %d, server %d\n",
			i, conns[i].downfd, conns[i].upfd,
			conns[i].downn, conns[i].upn,
			conns[i].client, conns[i].server);
	}
}

static void stats(int dummy)
{
	DEBUG(1, "Caught USR1, will save stats");
	stats_flag=1;
	sigaction(SIGUSR1, &usr1action, NULL);
}

static void restart_log(int dummy)
{
	DEBUG(1, "Caught HUP, will read cfg");
	restart_log_flag=1;
	sigaction(SIGHUP, &hupaction, NULL);
}
#endif

static void quit(int dummy)
{
	DEBUG(1, "Quitting\nRead configuration %d times", hupcounter);
	loopflag = 0;
}

#ifndef WINDOWS
static void die(int dummy)
{
	abort();
}
#endif

static void dump(unsigned char *p, int n)
{
	int i;

	fprintf(stderr, "%d: ", n);
	for (i = 0; i < n; i++) {
		if (asciidump) {
			fprintf(stderr, "%c",
				(isprint(p[i])||isspace(p[i]))?p[i]:'.');
		} else {
			fprintf(stderr, "%02x ", (int)p[i]);
		}
	}
	fprintf(stderr, "\n");
}

/* Log format is:

   + client_ip server_ip request
*/
static void netlog(int fd, int i, unsigned char *r, int n)
{
	int j, k;
	char b[1024];
	DEBUG(2, "netlog(%d, %d, %p, %d)", fd, i, r, n);
	strncpy(b, "+ ", sizeof b);
	k = 2;
	strncpy(b+k, pen_ntoa(&clients[conns[i].client].addr), (sizeof b)-k);
	k += strlen(b+k);
	b[k++] = ' ';
	strncpy(b+k, pen_ntoa(&servers[conns[i].server].addr), (sizeof b)-k);
	k += strlen(b+k);
	b[k++] = ' ';

	/* We have already used k bytes from b. This means that we want
	   no more than (sizeof b-(k+1)) bytes from r. The +1 is for the
	   trailing newline.
	*/
	j = sizeof b-(k+1);
	if (n > j) n = j;
	for (j = 0; j < n && r[j] != '\r' && r[j] != '\n'; j++) {
		b[k++] = r[j];
	}
	b[k++] = '\n';
	sendto(fd, b, k, 0, (struct sockaddr *)&logserver, sizeof logserver);
}

/* Log format is:

    client_ip timestamp server_ip request
*/
static void log_request(FILE *fp, int i, unsigned char *b, int n)
{
	int j;
	if (n > KEEP_MAX) n = KEEP_MAX;
	fprintf(fp, "%s ", pen_ntoa(&clients[conns[i].client].addr));
	fprintf(fp, "%ld ", (long)now);
	fprintf(fp, "%s ", pen_ntoa(&servers[conns[i].server].addr));
	for (j = 0; j < n && b[j] != '\r' && b[j] != '\n'; j++) {
		fprintf(fp, "%c", isascii(b[j])?b[j]:'.');
	}
	fprintf(fp, "\n");
}

static int rewrite_request(int i, int n, char *b)
{
	char *q;
	char p[BUFFER_MAX];
	int pl;

	b[n] = '\0';

	DEBUG(2, "rewrite_request(%d, %d, %s)", i, n, b);

	if (pen_strncasecmp(b, "GET ", 4) &&
	    pen_strncasecmp(b, "POST ", 5) &&
	    pen_strncasecmp(b, "HEAD ", 5)) {
		return n;	/* You can't touch this */
	}
	DEBUG(2, "Looking for CRLFCRLF");
	q = strstr(b, "\r\n\r\n");
	/* Steve Hall <steveh@intrapower.com.au> tells me that
	   apparently some clients send \n\n instead */
	if (!q) {
		DEBUG(2, "Looking for LFLF");
		q = strstr(b, "\n\n");
	}
	if (!q) return n;		/* not a header */

	/* Look for existing X-Forwarded-For */
	DEBUG(2, "Looking for X-Forwarded-For");
	if (!pen_strcasestr(b, "\nX-Forwarded-For:"))
	{
		DEBUG(2, "Adding X-Forwarded-For");
		/* Didn't find one, add our own */
		snprintf(p, sizeof p, "\r\nX-Forwarded-For: %s",
			pen_ntoa(&clients[conns[i].client].addr));
		pl=strlen(p);
		if (n+pl > BUFFER_MAX) return n;
		memmove(q+pl, q, b+n-q);
		memmove(q, p, pl);
		n += pl;
	}
	b[n] = '\0';
	if (!pen_strcasestr(b, "\nX-Forwarded-Proto:")){
		DEBUG(2, "Adding X-Forwarded-Proto");
		/* Didn't find one, add our own */
		#ifdef HAVE_LIBSSL
		snprintf(p, sizeof p, "\r\nX-Forwarded-Proto: %s",
			(conns[i].ssl)?"https":"http");
		#else
		snprintf(p, sizeof p, "\r\nX-Forwarded-Proto: %s","http");
		#endif  /* HAVE_LIBSSL */
		pl=strlen(p);
		if (n+pl > BUFFER_MAX) return n;
		memmove(q+pl, q, b+n-q);
		memmove(q, p, pl);
		n += pl;
	}
	return n;
}

static void change_events(int i)
{
	int up_events = 0, down_events = 0;
	int state = conns[i].state;
	if (state & CS_IN_PROGRESS) {
		DEBUG(2, "waiting for connect() to complete");
		up_events |= EVENT_WRITE;
	} else if (state & CS_CONNECTED) {
		/* we are never interested in additional udp data from the client */
		if (!udp) {
			if (conns[i].upn == 0) {
				if (!(state & CS_CLOSED_DOWN)) {
					DEBUG(2, "interested in reading from downstream socket %d of connection %d", conns[i].downfd, i);
					down_events |= EVENT_READ;
				}
			} else {
				DEBUG(2, "interested in writing %d bytes to upstream socket %d of connection %d", conns[i].upn, conns[i].upfd, i);
				up_events |= EVENT_WRITE;
			}
		}

		/* tcp and udp processing upstream is handled the same here */
		if (conns[i].downn == 0) {
			if (!(state & CS_CLOSED_UP)) {
				DEBUG(2, "interested in reading from upstream socket %d of connection %d", conns[i].upfd, i);
				up_events |= EVENT_READ;
			}
		} else {
			DEBUG(2, "interested in writing %d bytes to downstream socket %d of connection %d", conns[i].downn, conns[i].downfd, i);
			down_events |= EVENT_WRITE;
		}
	}
	/* We know that if down_events == up_events == 0, the connection
	   will be closed. Not doing anything here shaves off two syscalls.
	*/
	if (down_events || up_events) {
		if (conns[i].downfd != -1) event_arm(conns[i].downfd, down_events);
		if (conns[i].upfd != -1) event_arm(conns[i].upfd, up_events);
	}
}

static int my_recv(int fd, void *buf, size_t len, int flags)
{
	return recvfrom(fd, buf, len, flags, NULL, 0);
}

static int my_send(int fd, const void *buf, size_t len, int flags)
{
	if (fd == -1) return len;	/* idler */
	return sendto(fd, buf, len, flags, NULL, 0);
}

static void add_dummy_reply(int conn)
{
	char msg[1024];
	DEBUG(2, "add_dummy_reply(%d)", conn);
	snprintf(msg, sizeof msg,
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/html\r\n\r\n%s",
		(int)strlen(DUMMY_MSG), DUMMY_MSG);
	conns[conn].downn = strlen(msg);
	conns[conn].downbptr = conns[conn].downb = pen_malloc(conns[conn].downn);
	memcpy(conns[conn].downb, msg, conns[conn].downn);
	change_events(conn);
}

static int copy_up(int i)
{
	int n, rc, err = 0;
	int from = conns[i].downfd;
	int to = conns[i].upfd;
	int serverindex = conns[i].server;

	unsigned char b[BUFFER_MAX];

#ifdef HAVE_LIBSSL
	SSL *ssl = conns[i].ssl;

	if (ssl) {
		rc = SSL_read(ssl, b, BUFFER_MAX);
		DEBUG(2, "SSL_read returns %d\n", rc);
		if (rc < 0) {
			err = SSL_get_error(ssl, rc);
			DEBUG(2, "SSL_read returns %d (SSL error %d)\n", rc, err);
			if (err == SSL_ERROR_WANT_READ ||
			    err == SSL_ERROR_WANT_WRITE) {
				return 0;
			}
		}
	} else {
		rc = my_recv(from, b, BUFFER_MAX, 0);
		err = socket_errno;
	}
#else

	rc = my_recv(from, b, BUFFER_MAX, 0);
	err = socket_errno;

#endif  /* HAVE_LIBSSL */

	DEBUG(2, "copy_up: recv(%d, %p, %d, 0) returns %d, errno = %d, socket_errno = %d", \
		from, b, BUFFER_MAX, rc, errno, socket_errno);

	if (rc == 0) {	/* orderly shutdown */
		DEBUG(2, "orderly shutdown of socket downfd=%d", from);
		conns[i].state |= CS_CLOSED_DOWN;

		/* no need to bother with any of this
		   if the connection will be closed anyway
		*/
		if (closing_time(i)) return -1;

		change_events(i);	/* so we stop reading from downfd */
		if (!(conns[i].state & CS_CLOSED_UP)) {
			/* proceed telling upfd about the close */
			n = shutdown(to, SHUT_WR);
			if (n == -1) {
				err = socket_errno;
				DEBUG(2, "shutdown(upfd=%d, SHUT_WR) returns %d, socket_errno=%d", to, n, err);
				if (err != ENOTCONN) conns[i].state |= CS_CLOSED;	/* because of the error */
			}
		}
		return -1;	/* the connection was successfully half-closed, wait for upstream to act */
	} else if (rc == -1) {
		if (WOULD_BLOCK(err)) return 0;
		conns[i].state |= CS_CLOSED;	/* because of the error */
		return -1;
	} else {
		if (http) {
			rc = rewrite_request(i, rc, (char *)b);
		}

		if (debuglevel > 2) dump(b, rc);

		if (logfp) {
			log_request(logfp, i, b, rc);
			if (debuglevel > 2) log_request(stderr, i, b, rc);
		}
		if (logsock != -1) {
			netlog(logsock, i, b, rc);
		}

		n = my_send(to, b, rc, 0);	/* no ssl here */
		conns[i].state &= ~CS_HALFDEAD;
		SAVE_ERRNO;

		DEBUG(2, "copy_up: send(%d, %p, %d, 0) returns %d, socket_errno = %d",
			to, b, rc, n, USE_ERRNO);
		if (n == -1) {
			if (!WOULD_BLOCK(USE_ERRNO)) {
				conns[i].state |= CS_CLOSED;
				return -1;
			}
			n = 0;
		}
		if (n != rc) {
			DEBUG(2, "copy_up saving %d bytes in up buffer", rc-n);
			conns[i].upn = rc-n;	/* remaining to be copied */
			conns[i].upbptr = conns[i].upb = pen_malloc(rc-n);
			memcpy(conns[i].upb, b+n, rc-n);
			change_events(i);
		}
#if 0
These could be simplified, no? Just store them in conn and update
servers and clients from close_conn.
#endif
		servers[serverindex].sx += rc;	/* That's not right? Should be n */
		clients[conns[i].client].crx += rc;
		conns[i].crx += rc;	/* rewritten bytes read from client */
		conns[i].ssx += n;	/* actual bytes written to server */

		if (dummy) add_dummy_reply(i);
	}
	return 0;
}

/* this function may have to deal with udp */
static int copy_down(int i)
{
	int n, rc, err = 0;
	int from = conns[i].upfd;
	int to = conns[i].downfd;
	int serverindex = conns[i].server;
#ifdef HAVE_LIBSSL
	SSL *ssl = conns[i].ssl;
#endif

	unsigned char b[BUFFER_MAX];

	/* we called connect from add_client, so this works for udp and tcp */
	rc = my_recv(from, b, BUFFER_MAX, 0);	/* no ssl here */

	DEBUG(2, "copy_down: recv(%d, %p, %d, %d) returns %d", from, b, BUFFER_MAX, 0, rc);
	if (debuglevel > 2) dump(b, rc);

	if (rc == 0) {
		DEBUG(2, "orderly shutdown of socket %d", from);
		conns[i].state |= CS_CLOSED_UP;

		/* no need to bother with any of this
		   if the connection will be closed anyway
		*/
		if (closing_time(i)) return -1;

		change_events(i);	/* so we stop reading from upfd */
		if (!(conns[i].state & CS_CLOSED_DOWN)) {
			n = shutdown(to, SHUT_WR);
			if (n == -1) {
				err = socket_errno;
				DEBUG(2, "shutdown(downfd=%d, SHUT_WR) returns %d, socket_errno=%d", to, n, err);
				if (err != ENOTCONN) conns[i].state |= CS_CLOSED;	/* because of the error */
			}
		}
		return -1;
	} else if (rc == -1) {
		DEBUG(2, "socket_errno = %d", socket_errno);
		conns[i].state |= CS_CLOSED;	/* because of the error */
		return -1;
	} else {
		int n;

		if (udp) {
			n = send(to, (void *)b, rc, 0);
			conns[i].state = CS_CONNECTED;
			return 0;
		}

#ifdef HAVE_LIBSSL
		if (ssl) {
			/* We can't SSL_write here, because the auto buffer we're using now
			   won't be around if we need to retry the write.
			   Therefore don't write anything here but let flush_down do it. */
			n = 0;
		} else {
			n = my_send(to, b, rc, 0);
			err = socket_errno;
			DEBUG(2, "copy_down: send(%d, %p, %d, %d) returns %d", to, b, rc, 0, n);
		}
#else
		n = my_send(to, b, rc, 0);
		err = socket_errno;
		DEBUG(2, "copy_down: send(%d, %p, %d, %d) returns %d", to, b, rc, 0, n);
#endif

		if (n == -1) {
			DEBUG(2, "errno = %d, socket_errno = %d", errno, socket_errno);
			if (!WOULD_BLOCK(err)) {
				conns[i].state |= CS_CLOSED;
				return -1;
			}
			n = 0;
		}
		if (n != rc) {
			DEBUG(2, "copy_down saving %d bytes in down buffer", rc-n);
			conns[i].downn = rc-n;
			conns[i].downbptr = conns[i].downb = pen_malloc(rc-n);
			memcpy(conns[i].downb, b+n, rc-n);
			change_events(i);
		}
		servers[serverindex].rx += rc;
		clients[conns[i].client].csx += n;
		conns[i].srx += rc;
		conns[i].csx += n;
	}
	return 0;
}

#ifndef WINDOWS
static void alarm_handler(int dummy)
{
	DEBUG(2, "alarm_handler(%d)", dummy);
}
#endif


static void usage(void)
{
	printf("usage:\n"
	       "  pen [-C addr:port] [-X] [-b sec] [-c N] [-e host[:port]] \\\n"
	       "	  [-t sec] [-x N] [-w dir] [-UHPWadfhrs] \\\n"
	       "          [-o option] \\\n"
#ifdef HAVE_LIBSSL
	       "	  [-E certfile] [-K keyfile] \\\n"
	       "	  [-G cacertfile] [-A cacertdir] \\\n"
	       "	  [-Z] [-R] [-L protocol] \\\n"
#endif
	       "	  [host:]port h1[:p1[:maxc1[:hard1[:weight1[:prio1]]]]] [h2[:p2[:maxc2[:hard2[:weight2[:prio2]]]]]] ...\n"
	       "\n"
	       "  -B host:port abuse server for naughty clients\n"
	       "  -C port   control port\n"
	       "  -T sec    tracking time in seconds (0 = forever) [%d]\n"
	       "  -H	add X-Forwarded-For header in http requests\n"
	       "  -U	use udp protocol support\n"
	       "  -N	use hash for initial server selection without save server\n"
	       "  -O option	use option in penctl format\n"
	       "  -P	use poll() rather than select()\n"
	       "  -Q    use kqueue to manage events (BSD)\n"
	       "  -W    use weight for server selection\n"
	       "  -X	enable 'exit' command for control port\n"
	       "  -a	debugging dumps in ascii format\n"
	       "  -b sec    blacklist time in seconds [%d]\n"
	       "  -c N      max number of clients [%d]\n"
	       "  -d	debugging on (repeat -d for more)\n"
	       "  -e host:port emergency server of last resort\n"
	       "  -f	stay in foregound\n"
	       "  -h	use hash for initial server selection\n"
	       "  -j dir    run in chroot\n"
	       "  -F file   name of configuration file\n"
	       "  -l file   logging on\n"
	       "  -r	bypass client tracking in server selection\n"
	       "  -s	stubborn selection, i.e. don't fail over\n"
	       "  -t sec    connect timeout in seconds [%d]\n"
	       "  -u user   run as alternative user\n"
	       "  -p file   write pid to file\n"
	       "  -x N      max number of simultaneous connections [%d]\n"
	       "  -w file   save statistics in HTML format in a file\n"
	       "  -o option use option in penctl format\n"
#ifdef HAVE_LIBSSL
	       "  -E certfile   use the given certificate in PEM format\n"
	       "  -K keyfile    use the given key in PEM format (may be contained in cert)\n"
	       "  -G cacertfile file containing the CA's certificate\n"
	       "  -A cacertdir  directory containing CA certificates in hashed format\n"
	       "  -Z	    use SSL compatibility mode\n"
	       "  -R	    require valid peer certificate\n"
	       "  -L protocol   ssl23 (default), ssl2, ssl3 or tls1\n"
#endif
	       "\n"
	       "example:\n"
	       "  pen smtp mailhost1:smtp mailhost2:25 mailhost3\n"
	       "\n",
	       TRACKING_TIME, BLACKLIST_TIME, CLIENTS_MAX, TIMEOUT, CONNECTIONS_MAX);

	exit(0);
}

#ifndef WINDOWS
static void background(void)
{
#ifdef HAVE_DAEMON
	daemon(0, 0);
#else
	int childpid;
	if ((childpid = fork()) < 0) {
		error("Can't fork");
	} else {
		if (childpid > 0) {
			exit(0);	/* parent */
		}
	}	
	int devnull_fd = open("/dev/null", O_RDWR);
	dup2(devnull_fd,0); /* stdin */
	dup2(devnull_fd,1); /* stdout */
	dup2(devnull_fd,2); /* stderr */
	setsid();
	signal(SIGCHLD, SIG_IGN);
#endif
}
#endif

static void init(int argc, char **argv)
{
	int i;
	int server;
	int proto;

	DEBUG(2, "init(%d, %p); port = %d", argc, argv, port);

	debug("Before: conns = %p, connections_max = %d, clients = %p, clients_max = %d",
		conns, connections_max, clients, clients_max);
	if (connections_max == 0) expand_conntable(CONNECTIONS_MAX);
	if (clients_max == 0) expand_clienttable(CLIENTS_MAX);
	debug("After: conns = %p, connections_max = %d, clients = %p, clients_max = %d",
		conns, connections_max, clients, clients_max);

	current = 0;

	server = 0;

	if (udp) proto = SOCK_DGRAM;
	else proto = SOCK_STREAM;

	for (i = 1; i < argc; i++) {
		DEBUG(2, "server[%d] = %s", server, argv[i]);
		expand_servertable(server+1);
		servers[server].status = 0;
		servers[server].c = 0;	/* connections... */
		setaddress(server, argv[i], port, proto);
		servers[server].sx = 0;
		servers[server].rx = 0;
		server++;
	}

	if (e_server) {
		DEBUG(2, "Emergency server = %s", e_server);
		expand_servertable(EMERGENCY_SERVER+1);
		emerg_server = EMERGENCY_SERVER;
		servers[EMERGENCY_SERVER].status = 0;
		servers[EMERGENCY_SERVER].c = 0;	/* connections... */
		setaddress(EMERGENCY_SERVER, e_server, port, proto);
		servers[EMERGENCY_SERVER].sx = 0;
		servers[EMERGENCY_SERVER].rx = 0;
		server++;
	}

	if (a_server) {
		DEBUG(2, "Abuse server = %s", a_server);
		expand_servertable(ABUSE_SERVER+1);
		abuse_server = ABUSE_SERVER;
		servers[ABUSE_SERVER].status = 0;
		servers[ABUSE_SERVER].c = 0;	/* connections... */
		setaddress(ABUSE_SERVER, a_server, port, proto);
		servers[ABUSE_SERVER].sx = 0;
		servers[ABUSE_SERVER].rx = 0;
		server++;
	}

	for (i = 0; i < clients_max; i++) {
		clients[i].last = 0;
		memset(&clients[i].addr, 0, sizeof(clients[i].addr));
		clients[i].server = 0;
		clients[i].connects = 0;
		clients[i].csx = 0;
		clients[i].crx = 0;
	}

	if (debuglevel) {
		debug("%s starting", PACKAGE_STRING);
		debug("servers:");
		for (i = 0; i < nservers; i++) {
			debug("%2d %s:%d:%d:%d:%d:%d", i,
				pen_ntoa(&servers[i].addr), pen_getport(&servers[i].addr),
				servers[i].maxc, servers[i].hard,
				servers[i].weight, servers[i].prio);
		}
	}
}

static void open_log(char *logfile)
{
	if (logfp) {
		fclose(logfp);
		logfp = NULL;
	}
	if (logsock >= 0) {
		close(logsock);
		logsock = -1;
	}
	if (logfile) {
		char *p = strchr(logfile, ':');
		if (p && logfile[0] != '/') {	/* log to net */
			struct hostent *hp;
			DEBUG(2, "net log to %s", logfile);
			*p++ = '\0';
			logsock = socket_nb(PF_INET, SOCK_DGRAM, 0);
			logserver.sin_family = AF_INET;
			hp = gethostbyname(logfile);
			if (hp == NULL) error("Bogus host %s", logfile);
			memcpy(&logserver.sin_addr.s_addr,
				hp->h_addr, hp->h_length);
			logserver.sin_port = htons(atoi(p));
		} else {	/* log to file */
			DEBUG(2, "file log to %s", logfile);
			logfp = fopen(logfile, "a");
			if (!logfp) error("Can't open logfile %s", logfile);
		}
	}
}

#ifndef WINDOWS
static int open_unix_listener(char *a)
{
	int n, listenfd;
	struct sockaddr_un serv_addr;

	remove(a);
	memset(&serv_addr, 0, sizeof serv_addr);
	serv_addr.sun_family = AF_UNIX;
	snprintf(serv_addr.sun_path, sizeof serv_addr.sun_path, "%s", a);
	listenfd = socket_nb(AF_UNIX, SOCK_STREAM, 0);
	if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof serv_addr) != 0) {
		error("can't bind local address");
	}
	n = listen(listenfd, listen_queue);
	if (n == -1) {
		DEBUG(2, "listen(%d, %d) returns -1, errno = %d, socket_errno = %d",
			listenfd, listen_queue, errno, socket_errno);
	}
	return listenfd;
}
#endif

static int open_listener(char *a, int proto)
{
	int listenfd;
	struct sockaddr_storage ss;

	char b[1024], *p;
	int one = 1;
	int optval = 1;

	DEBUG(2, "open_listener(%s)", a);

#ifndef WINDOWS
	/* Handle Unix domain sockets separately */
	if (strchr(a, '/')) return open_unix_listener(a);
#endif

	memset(&ss, 0, sizeof ss);
	p = strrchr(a, ':');	/* look for : separating address from port */
	if (p) {
		/* found one, extract parts */
		if ((p-a) >= sizeof b) {
			error("Address %s too long", a);
			return -1;
		}
		strncpy(b, a, p-a);
		b[p-a] = '\0';
		port = getport(p+1, proto);
	} else {
		strncpy(b, "0.0.0.0", sizeof b);
		port = getport(a, proto);
	}
	if (port < 1 || port > 65535) {
		debug("Port %d out of range", port);
		return -1;
	}

	if (!pen_aton(b, &ss)) {
		debug("Can't convert address '%s'", b);
		return -1;
	}
	pen_setport(&ss, port);

	listenfd = socket_nb(ss.ss_family, proto, 0);
	DEBUG(2, "local address=[%s:%d]", b, port);

	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof one);
	setsockopt(listenfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval, sizeof optval);
#ifdef SO_REUSEPORT
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, (void *)&one, sizeof one);
#endif

	if (bind(listenfd, (struct sockaddr *)&ss, pen_ss_size(&ss)) < 0) {
		error("can't bind local address");
	}

	listen(listenfd, listen_queue);
	return listenfd;
}

static void read_cfg(char *);

static void write_cfg(char *p)
{
	int i;
	struct tm *nowtm;
	char nowstr[80];
	FILE *fp = fopen(p, "w");
	if (!fp) {
		debug("Can't open file '%s'", p);
		return;
	}
	nowtm = localtime(&now);
	strftime(nowstr, sizeof(nowstr), "%Y-%m-%d %H:%M:%S", nowtm);
	fprintf(fp, "# Generated by pen %s\n", nowstr);
	fprintf(fp, "# pen");
	if (udp) fprintf(fp, " -U");
	if (foreground) fprintf(fp, " -f");
	if (exit_enabled) fprintf(fp, " -X");
	if (clients_max != CLIENTS_MAX)
		fprintf(fp, " -c %d", clients_max);
	if (e_server) fprintf(fp, " -e %s", e_server);
	if (a_server) fprintf(fp, " -B %s", a_server);
	if (jail) fprintf(fp, " -j '%s'", jail);
	if (pidfile) fprintf(fp, " -p '%s'", pidfile);
	if (user) fprintf(fp, " -u '%s'", user);
	if (connections_max != CONNECTIONS_MAX)
		fprintf(fp, " -x %d", connections_max);
	fprintf(fp, " -F '%s' -C %s %s\n", p, ctrlport, listenport);
	save_acls(fp);
	if (asciidump) fprintf(fp, "ascii\n");
	else fprintf(fp, "no ascii\n");
	fprintf(fp, "blacklist %d\n", blacklist_time);
	fprintf(fp, "client_acl %d\n", client_acl);
	fprintf(fp, "control_acl %d\n", control_acl);
	fprintf(fp, "debug %d\n", debuglevel);
	if (server_alg & ALG_HASH) fprintf(fp, "hash\n");
	else fprintf(fp, "no hash\n");
	if (http) fprintf(fp, "http\n");
	else fprintf(fp, "no http\n");
	if (logfile) fprintf(fp, "log %s\n", logfile);
	else fprintf(fp, "no log\n");
	if (server_alg & ALG_ROUNDROBIN) fprintf(fp, "roundrobin\n");
	else fprintf(fp, "no roundrobin\n");
	for (i = 0; i < nservers; i++) {
		fprintf(fp,
			"server %d acl %d address %s port %d max %d hard %d",
			i, servers[i].acl,
			pen_ntoa(&servers[i].addr), pen_getport(&servers[i].addr),
			servers[i].maxc, servers[i].hard);
		if (server_alg & ALG_WEIGHT) fprintf(fp, " weight %d", servers[i].weight);
		if (server_alg & ALG_PRIO) fprintf(fp, " prio %d", servers[i].prio);
		fprintf(fp, "\n");
	}
	if (server_alg & ALG_STUBBORN) fprintf(fp, "stubborn\n");
	else fprintf(fp, "no stubborn\n");
	if (tcp_fastclose == CS_CLOSED) {
		fprintf(fp, "tcp_fastclose both\n");
	} else if (tcp_fastclose == CS_CLOSED_UP) {
		fprintf(fp, "tcp_fastclose up\n");
	} else if (tcp_fastclose == CS_CLOSED_DOWN) {
		fprintf(fp, "tcp_fastclose down\n");
	} else {
		fprintf(fp, "tcp_fastclose off\n");
	}
	if (tcp_nodelay) {
		fprintf(fp, "tcp_nodelay\n");
	} else {
		fprintf(fp, "no tcp_nodelay\n");
	}
	fprintf(fp, "timeout %d\n", timeout);
	fprintf(fp, "tracking %d\n", tracking_time);
	if (webfile) fprintf(fp, "web_stats %s\n", webfile);
	else fprintf(fp, "no web_stats\n");
	if (server_alg & ALG_WEIGHT) fprintf(fp, "weight\n");
	else fprintf(fp, "no weight\n");
	if (server_alg & ALG_PRIO) fprintf(fp, "prio\n");
	else fprintf(fp, "no prio\n");
	fclose(fp);
}

static void do_cmd(char *b, void (*output)(void *, char *, ...), void *op)
{
	char *p, *q;
	int n;
	FILE *fp;

	p = strchr(b, '\r');
	if (p) *p = '\0';
	p = strchr(b, '\n');
	if (p) *p = '\0';
	DEBUG(2, "do_cmd(%s, %p, %p)", b, output, op);
	p = strtok(b, " ");
	if (p == NULL) return;
	if (!strcmp(p, "abort_on_error")) {
		abort_on_error = 1;
	} else if (!strcmp(p, "acl")) {
		char *no, *pd, *ip, *ma;
		/* acl N permit|deny ipaddr [mask] */
		if ((no = strtok(NULL, " ")) &&
		    (pd = strtok(NULL, " ")) &&
		    (ip = strtok(NULL, " "))) {
			int a = atoi(no);
			int permit;
			if (!strcmp(pd, "permit")) permit = 1;
			else if (!strcmp(pd, "deny")) permit = 0;
			else {
				debug("acl: expected permit|deny");
				return;
			}
			if (!strcmp(ip, "country")) {
				char *country = strtok(NULL, " ");
				if (!country) {
					debug("acl: expected country");
					return;
				}
				add_acl_geo(a, country, permit);
			} else if (strchr(ip, ':')) {
				unsigned char ipaddr[INET6_ADDRSTRLEN];
				ma = strchr(ip, '/');
				if (ma) {
					*ma++ = '\0';
				} else {
					ma = "128";
				}
				struct sockaddr_storage ss;
				struct sockaddr_in6 *si6;
				if (pen_aton(ip, &ss) != 1) {
					debug("acl: can't convert address %s", ip);
					return;
				}
				if (ss.ss_family != AF_INET6) {
					debug("acl: %s is not an ipv6 address", ip);
					return;
				}
				si6 = (struct sockaddr_in6 *)&ss;
				memcpy(ipaddr, &si6->sin6_addr, sizeof ipaddr);
				add_acl_ipv6(a, ipaddr, atoi(ma), permit);
			} else {
				struct in_addr ipaddr, mask;
				ma = strtok(NULL, " ");
				if (!ma) ma = "255.255.255.255";
				if (!inet_aton(ip, &ipaddr)) {
					debug("acl: bogus address '%s'\n", ip);
					return;
				}
				if (!inet_aton(ma, &mask)) {
					debug("acl: bogus mask '%s'\n", ma);
					return;
				}
				add_acl_ipv4(a, ipaddr.s_addr, mask.s_addr, permit);
			}
		}
	} else if (!strcmp(p, "ascii")) {
		asciidump = 1;
	} else if (!strcmp(p, "blacklist")) {
		p = strtok(NULL, " ");
		if (p) blacklist_time = atoi(p);
		output(op, "%d\n", blacklist_time);
	} else if (!strcmp(p, "client_acl")) {
		p = strtok(NULL, " ");
		if (p) client_acl = atoi(p);
		if (client_acl < 0 || client_acl >= ACLS_MAX)
			client_acl = 0;
		output(op, "%d\n", client_acl);
	} else if (!strcmp(p, "clients_max")) {
		p = strtok(NULL, " ");
		if (p) expand_clienttable(atoi(p));
		output(op, "%d\n", clients_max);
	} else if (!strcmp(p, "close")) {
		p = strtok(NULL, " ");
		int conn = p ? atoi(p) : 0;
		if (conn < 0 || conn >= connections_max) {
			output(op, "Connection %d out of range\n", conn);
		} else {
			output(op, "Forcibly closing connection %d\n", conn);
			close_conn(conn);
		}
	} else if (!strcmp(p, "connection")) {
		p = strtok(NULL, " ");
		int conn = p ? atoi(p) : 0;
		if (conn < 0 || conn >= connections_max) {
			output(op, "Connection %d out of range\n", conn);
		} else {
			output(op, "Connection %d:\n", conn);
			output(op, "state = %d\n", conns[conn].state);
			output(op, "downfd = %d, upfd = %d\n",
				conns[conn].downfd, conns[conn].upfd);
			output(op, "client = %d, server = %d\n",
				conns[conn].client, conns[conn].server);
			output(op, "pend = %d\n", conns[conn].pend);
		}
	} else if (!strcmp(p, "conn_max")) {
		p = strtok(NULL, " ");
		if (p) expand_conntable(atoi(p));
		output(op, "%d\n", connections_max);
	} else if (!strcmp(p, "control")) {
		output(op, "%s\n", ctrlport);
	} else if (!strcmp(p, "control_acl")) {
		p = strtok(NULL, " ");
		if (p) control_acl = atoi(p);
		if (control_acl < 0 || control_acl >= ACLS_MAX)
			control_acl = 0;
		output(op, "%d\n", control_acl);
	} else if (!strcmp(p, "debug")) {
		p = strtok(NULL, " ");
		if (p) debuglevel = atoi(p);
		output(op, "%d\n", debuglevel);
	} else if (!strcmp(p, "dsr_if")) {
		p = strtok(NULL, " ");
		if (p) {
			free(dsr_if);
			dsr_if = pen_strdup(p);
		}
	} else if (!strcmp(p, "dsr_ip")) {
		p = strtok(NULL, " ");
		if (p) {
			free(dsr_ip);
			dsr_ip = pen_strdup(p);
		}
	} else if (!strcmp(p, "dummy")) {
		dummy = 1;
	} else if (!strcmp(p, "epoll")) {
		event_init = epoll_init;
	} else if (!strcmp(p, "exit")) {
		if (exit_enabled) {
			quit(0);
		} else {
			output(op, "Exit is not enabled; restart with -X flag\n");
		}
	} else if (!strcmp(p, "hash")) {
		server_alg |= ALG_HASH;
	} else if (!strcmp(p, "http")) {
		http = 1;
	} else if (!strcmp(p, "idle_timeout")) {
		p = strtok(NULL, " ");
		if (p) idle_timeout = atoi(p);
		if (idle_timeout < 0) idle_timeout = 0;
		output(op, "Idle timeout: %d seconds\n", idle_timeout);
	} else if (!strcmp(p, "idlers")) {
		p = strtok(NULL, " ");
		if (p) idlers_wanted = atoi(p);
		output(op, "Idlers: %d/%d\n", idlers, idlers_wanted);
	} else if (!strcmp(p, "include")) {
		p = strtok(NULL, " ");
		if (p) {
			read_cfg(p);
		} else {
			debug("Usage: include filename");
		}
	} else if (!strcmp(p, "keepalive")) {
		keepalive = 1;
	} else if (!strcmp(p, "kqueue")) {
		event_init = kqueue_init;
	} else if (!strcmp(p, "listen")) {
		p = strtok(NULL, " ");
		if (p) {
			snprintf(listenport, sizeof listenport, "%s", p);
			if (listenfd != -1) {
				n = close(listenfd);
				DEBUG(2, "close(listenfd=%d) returns %d", listenfd, n);
			}
			listenfd = open_listener(p, udp ? SOCK_DGRAM : SOCK_STREAM);
			/* we may need to defer this if we haven't called event_init yet */
			if (event_add) event_add(listenfd, EVENT_READ);
			DEBUG(2, "new listenfd = %d", listenfd);
		}
		output(op, "%s\n", listenport);
	} else if (!strcmp(p, "log")) {
		p = strtok(NULL, " ");
		if (p) {
			free(logfile);
			logfile = pen_strdup(p);
			open_log(logfile);
		}
		if (logfile) {
			output(op, "%s\n", logfile);
		}
	} else if (!strcmp(p, "mode")) {
		output(op, "%shash %sroundrobin %sstubborn %sweight %sprio\n",
			(server_alg & ALG_HASH)?"":"no ",
			(server_alg & ALG_ROUNDROBIN)?"":"no ",
			(server_alg & ALG_STUBBORN)?"":"no ",
			(server_alg & ALG_WEIGHT)?"":"no ",
			(server_alg & ALG_PRIO)?"":"no ");
	} else if (!strcmp(p, "no")) {
		p = strtok(NULL, " ");
		if (p == NULL) return;
		if (!strcmp(p, "abort_on_error")) {
			abort_on_error = 0;
		} else if (!strcmp(p, "acl")) {
			int a;
			p = strtok(NULL, " ");
			a = atoi(p);
			del_acl(a);
		} else if (!strcmp(p, "ascii")) {
			asciidump = 0;
		} else if (!strcmp(p, "dummy")) {
			dummy = 0;
		} else if (!strcmp(p, "hash")) {
			server_alg &= ~ALG_HASH;
		} else if (!strcmp(p, "http")) {
			http = 0;
		} else if (!strcmp(p, "keepalive")) {
			keepalive = 0;
		} else if (!strcmp(p, "log")) {
			logfile = NULL;
			if (logfp) fclose(logfp);
			logfp = NULL;
		} else if (!strcmp(p, "peek")) {
			peek = 0;
		} else if (!strcmp(p, "prio")) {
			server_alg &= ~ALG_PRIO;
		} else if (!strcmp(p, "roundrobin")) {
			server_alg &= ~ALG_ROUNDROBIN;
		} else if (!strcmp(p, "stubborn")) {
			server_alg &= ~ALG_STUBBORN;
		} else if (!strcmp(p, "tcp_nodelay")) {
			tcp_nodelay = 0;
		} else if (!strcmp(p, "transparent")) {
			transparent = 0;
		} else if (!strcmp(p, "web_stats")) {
			webfile = NULL;
		} else if (!strcmp(p, "weight")) {
			server_alg &= ~ALG_WEIGHT;
		}
	} else if (!strcmp(p, "peek")) {
		peek = 1;
	} else if (!strcmp(p, "pending_max")) {
		p = strtok(NULL, " ");
		if (p) pending_max = atoi(p);
		if (pending_max <= 0) pending_max = 1;
	} else if (!strcmp(p, "pid")) {
		output(op, "%ld\n", (long)getpid());
	} else if (!strcmp(p, "poll")) {
		event_init = poll_init;
	} else if (!strcmp(p, "prio")) {
		server_alg |= ALG_PRIO;
	} else if (!strcmp(p, "recent")) {
		time_t when = now;
		p = strtok(NULL, " ");
		if (p) when -= atoi(p);
		else when -= 300;
		for (n = 0; n < clients_max; n++) {
			if (clients[n].last < when) continue;
			output(op, "%s connects %ld sx %lld rx %lld\n",
				pen_ntoa(&clients[n].addr),
				clients[n].connects,
				clients[n].csx, clients[n].crx);
		}
	} else if (!strcmp(p, "roundrobin")) {
		server_alg |= ALG_ROUNDROBIN;
	} else if (!strcmp(p, "select")) {
		event_init = select_init;
	} else if (!strcmp(p, "server")) {
		p = strtok(NULL, " ");
		if (p == NULL) return;
		n = atoi(p);
		if (n < 0) return;
		expand_servertable(n+1);
		while ((p = strtok(NULL, " ")) && (q = strtok(NULL, " "))) {
			if (!strcmp(p, "acl")) {
				servers[n].acl = atoi(q);
			} else if (!strcmp(p, "address")) {
				int result;
				debug("do_cmd: server %d address %s", n, q);
				result = pen_aton(q, &servers[n].addr);
				DEBUG(1, "pen_aton returns %d\n" \
					"address family = %d", \
					n, servers[n].addr.ss_family);
				if (debuglevel > 1) pen_dumpaddr(&servers[n].addr);
				if (result != 1) return;
			} else if (!strcmp(p, "port")) {
				pen_setport(&servers[n].addr, atoi(q));
			} else if (!strcmp(p, "max")) {
				servers[n].maxc = atoi(q);
			} else if (!strcmp(p, "hard")) {
				servers[n].hard = atoi(q);
			} else if (!strcmp(p, "blacklist")) {
				servers[n].status = now+atoi(q)-blacklist_time;
			} else if (!strcmp(p, "weight")) {
				servers[n].weight = atoi(q);
			} else if (!strcmp(p, "prio")) {
				servers[n].prio = atoi(q);
			}
		}
	} else if (!strcmp(p, "servers")) {
		for (n = 0; n < nservers; n++) {
			output(op,
				"%d addr %s port %d conn %d max %d hard %d weight %d prio %d sx %llu rx %llu\n",
				n, pen_ntoa(&servers[n].addr), pen_getport(&servers[n].addr),
				servers[n].c, servers[n].maxc, servers[n].hard,
				servers[n].weight, servers[n].prio,
				servers[n].sx, servers[n].rx);
		}
	} else if (!strcmp(p, "socket")) {
		p = strtok(NULL, " ");
		int fd = p ? atoi(p) : 0;
		int conn = fd2conn_get(fd);
		output(op, "Socket %d belongs to connection %d\n", fd, conn);
	} else if (!strcmp(p, "source")) {
		p = strtok(NULL, " ");
		if (!source) source = pen_malloc(sizeof *source);
		if (pen_aton(p, source) == 0) {
			debug("pen_aton(%d, source) returns 0", p);
			output(op, "unable to set source address to '%s'", p);
			free(source);
			source = NULL;
		}
	} else if (!strcmp(p, "status")) {
		if (webstats()) {
			fp = fopen(webfile, "r");
			if (fp == NULL) {
				output(op, "Can't read webstats\n");
				return;
			}
			while (fgets(b, sizeof b, fp)) {
				output(op, "%s", b);
			}
			fclose(fp);
		} else {
			output(op, "Unable to create webstats\n");
		}
#ifdef HAVE_LIBSSL
	} else if (!strcmp(p, "ssl_ciphers")) {
		p = strtok(NULL, " ");
		if (ssl_ciphers) {
			free(ssl_ciphers);
			ssl_ciphers = NULL;
		}
		if (p) ssl_ciphers = pen_strdup(p);
	} else if (!strcmp(p, "ssl_client_renegotiation_interval")) {
		p = strtok(NULL, " ");
		ssl_client_renegotiation_interval = atoi(p);
	} else if (!strcmp(p, "ssl_ocsp_response")) {
		p = strtok(NULL, " ");
		if (ocsp_resp_file) {
			free(ocsp_resp_file);
		}
		ocsp_resp_file = pen_strdup(p);
	} else if (!strcmp(p, "ssl_option")) {
		p = strtok(NULL, " ");
		if (p == NULL) {
			debug("Missing option");
		} else if (!strcmp(p, "no_sslv2")) {
			ssl_options |= SSL_OP_NO_SSLv2;
		} else if (!strcmp(p, "no_sslv3")) {
			ssl_options |= SSL_OP_NO_SSLv3;
		} else if (!strcmp(p, "no_tlsv1")) {
			ssl_options |= SSL_OP_NO_TLSv1;
#ifdef SSL_OP_NO_TLSv1_1
		} else if (!strcmp(p, "no_tlsv1.1")) {
			ssl_options |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
		} else if (!strcmp(p, "no_tlsv1.2")) {
			ssl_options |= SSL_OP_NO_TLSv1_2;
#endif
		} else if (!strcmp(p, "cipher_server_preference")) {
			ssl_options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
		}
	} else if (!strcmp(p, "ssl_sni_path")) {
		p = strtok(NULL, " ");
		if (p == NULL) {
			debug("Missing ssl_sni_path");
		} else {
			if (ssl_sni_path) free(ssl_sni_path);
			ssl_sni_path = pen_strdup(p);
		}
#endif	/* HAVE_SSL */
	} else if (!strcmp(p, "stubborn")) {
		server_alg |= ALG_STUBBORN;
	} else if (!strcmp(p, "tcp_fastclose")) {
		p = strtok(NULL, " ");
		if (!p) {
			output(op, "do_cmd: ignoring tcp_fastclose without argument\n");
			return;
		}
		if (!strcmp(p, "both")) {
			tcp_fastclose = CS_CLOSED;
		} else if (!strcmp(p, "up")) {
			tcp_fastclose = CS_CLOSED_UP;
		} else if (!strcmp(p, "down")) {
			tcp_fastclose = CS_CLOSED_DOWN;
		} else {
			tcp_fastclose = 0;
		}
	} else if (!strcmp(p, "tarpit_acl")) {
		p = strtok(NULL, " ");
		if (p) tarpit_acl = atoi(p);
		if (tarpit_acl < -1 || tarpit_acl >= ACLS_MAX)
			tarpit_acl = 0;
		output(op, "tarpit_acl = %d", tarpit_acl);
	} else if (!strcmp(p, "tcp_nodelay")) {
		tcp_nodelay = 1;
	} else if (!strcmp(p, "timeout")) {
		p = strtok(NULL, " ");
		if (p) timeout = atoi(p);
		output(op, "%d\n", timeout);
	} else if (!strcmp(p, "tracking")) {
		p = strtok(NULL, " ");
		if (p) tracking_time = atoi(p);
		output(op, "%d\n", tracking_time);
	} else if (!strcmp(p, "transparent")) {
		transparent = 1;
	} else if (!strcmp(p, "web_stats")) {
		p = strtok(NULL, " ");
		if (p) {
			free(webfile);
			webfile = pen_strdup(p);
		}
		if (webfile) {
			output(op, "%s\n", webfile);
		}
	} else if (!strcmp(p, "weight")) {
		server_alg |= ALG_WEIGHT;
	} else if (!strcmp(p, "write")) {
		p = strtok(NULL, " ");
		if (!p) p = cfgfile;
		if (p) {
			write_cfg(p);
		} else {
			debug("write: no file");
		}
	} else {
		if (p[0] != '#')
			output(op, "do_cmd: ignoring command starting with '%s'\n", p);
	}
}

static void output_net(void *op, char *fmt, ...)
{
	int *fp = op;
	int n;
	char b[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	n = send(*fp, b, strlen(b), 0);
	if (n == -1) {
		debug("output_net: write failed");
	}
	va_end(ap);
}

static void output_file(void *op, char *fmt, ...)
{
	FILE *fp = op;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
}

static void do_ctrl(int downfd, struct sockaddr_storage *cli_addr)
{
	char b[4096];
	int n, max_b = sizeof b;

	if (!match_acl(control_acl, cli_addr)) {
		debug("do_ctrl: not from there");
	} else {
		n = my_recv(downfd, b, max_b-1, 0);
		if (n != -1) {
			b[n] = '\0';
			do_cmd(b, output_net, &downfd);
		}
	}
	close(downfd);
}

static void read_cfg(char *cf)
{
	FILE *fp;
	char b[4096];

	DEBUG(1, "read_cfg(%s)", cf);
	hupcounter++;
	if (cf == NULL) return;

	fp = fopen(cf, "r");
	if (fp == NULL) {
		debug("Can't read config file '%s'\n", cf);
		return;
	}
	while (fgets(b, sizeof b, fp)) {
		do_cmd(b, output_file, stdout);
	}
	fclose(fp);
}

static void add_client(int downfd, struct sockaddr_storage *cli_addr)
{
	int rc = 0;
	unsigned char b[BUFFER_MAX];
	int client = -1;
	int conn = -1;

#ifdef HAVE_LIBSSL
	SSL *ssl = NULL;

	/* check the ssl stuff before picking servers */
	if (ssl_context) {
		ssl = SSL_new(ssl_context);
		if (ssl == NULL) {
			int err = ERR_get_error();
			debug("SSL: error allocating handle: %s",
				ERR_error_string(err, NULL));
			return;
		}
		SSL_set_fd(ssl, downfd);
		SSL_set_accept_state(ssl);
	}
#endif

	/* we don't know the client address for udp until we read the message */
	if (udp) {
		int n, one = 1;
		socklen_t len = sizeof *cli_addr;
		struct sockaddr_storage listenaddr;
		socklen_t listenlen = sizeof listenaddr;
		rc = recvfrom(listenfd, (void *)b, sizeof b, 0, (struct sockaddr *)cli_addr, &len);
		DEBUG(2, "add_client: received %d bytes from client", rc);
		if (rc < 0) {
			if (errno != EINTR)
				debug("Error receiving data");
			return;
		}
	/* we need a downfd for udp as well */
		downfd = socket_nb(cli_addr->ss_family, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
		if (downfd == -1) {
			debug("Can't create downfd");
			return;
		}
#ifdef SO_REUSEPORT
		setsockopt(downfd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
		n = getsockname(listenfd, (struct sockaddr *)&listenaddr, &listenlen);
		if (n != 0) {
			debug("getsockname returns %d, errno = %d", n, errno);
			close(downfd);
			return;
		}
		if (listenlen > sizeof listenaddr) {
			debug("getsockaddr returns address that is too large for the buffer");
			close(downfd);
			return;
		}
		n = bind(downfd, (struct sockaddr *)&listenaddr, listenlen);
		if (n != 0) {
			debug("bind returns %d, errno = %d", n, errno);
			close(downfd);
			return;
		}
		n = connect(downfd, (struct sockaddr *)cli_addr, pen_ss_size(cli_addr));
		if (n != 0) {
			debug("connect (downfd = %d) returns %d, errno = %d", downfd, n, errno);
			close(downfd);
			return;
		}
	}

	client = store_client(cli_addr);	// no server yet
	DEBUG(2, "store_client returns %d", client);

#ifdef HAVE_LIBSSL
	conn = store_conn(downfd, ssl, client);
	conns[conn].reneg = 0;	/* never */
	if (ssl) {
		SSL_set_app_data(ssl, &conns[conn]);
	}
#else
	conn = store_conn(downfd, client);
#endif
	DEBUG(2, "store_conn returns %d", conn);

	if (dummy) {	/* don't bother with a server */
		conns[conn].initial = -1;
		conns[conn].upfd = -1;
		conns[conn].state = CS_CONNECTED|CS_CLOSED_UP;
		if (!udp) event_add(conns[conn].downfd, EVENT_READ);
		return;
	}

	if (peek) {	/* we'll choose a server later */
		DEBUG(2, "We'll choose a server later");
		conns[conn].initial = -1;
		conns[conn].upfd = -1;
		conns[conn].state = CS_WAIT_PEEK;
		event_add(conns[conn].downfd, EVENT_READ);
		return;
	}

	conns[conn].initial = conns[conn].server = initial_server(conn);
	if (conns[conn].initial == -1) {
		DEBUG(1, "No initial server found, giving up");
		close_conn(conn);
		return;
	}
	if (!try_server(conns[conn].initial, conn)) {
		/* try_server rejected the client, try another */
		if (!failover_server(conn)) {
			DEBUG(1, "No failover server found, giving up");
			//close_conn(conn);
			return;
		}
	}

	if (udp && rc > 0) {	/* pass on the message */
		/* we are "connected" and don't need sendto */
		rc = send(conns[conn].upfd, (void *)b, rc, 0);
		conns[conn].state &= ~CS_HALFDEAD;
		DEBUG(2, "add_client: wrote %d bytes to socket %d", rc, conns[conn].upfd);
	}
}

static int flush_down(int i)
{
	int n, err = 0;

#ifdef HAVE_LIBSSL
	SSL *ssl = conns[i].ssl;

	if (ssl) {
		int m = conns[i].downn;
		if (m > 16000) m = 16000;
		n = SSL_write(ssl, conns[i].downbptr, m);
		DEBUG(2, "SSL_write returns %d\n", n);
		if (n < 0) {
			int err = SSL_get_error(ssl, n);
			DEBUG(1, "SSL_write returns %d (SSL error %d)", n, err);
			if (err == SSL_ERROR_WANT_READ ||
			    err == SSL_ERROR_WANT_WRITE) {
				return 0;
			}
		}
	} else {
		n = my_send(conns[i].downfd, conns[i].downbptr, conns[i].downn, 0);
		err = socket_errno;
	}
#else
	struct sockaddr name;
	size_t size = sizeof(struct sockaddr);

	if (!udp) {
		n = my_send(conns[i].downfd, conns[i].downbptr, conns[i].downn, 0);
	} else {
		n = sendto(conns[i].downfd, (void *)conns[i].downbptr, conns[i].downn, 0,
			(struct sockaddr *) &name, size);
		conns[i].state &= ~CS_HALFDEAD;
	}
	err = socket_errno;
#endif  /* HAVE_LIBSSL */

	DEBUG(2, "flush_down(%d): send(%d, %p, %d, 0) returns %d, errno = %d, socket_errno = %d", \
		i, conns[i].downfd, conns[i].downbptr, conns[i].downn, n, errno, socket_errno);
	if (n == -1) {
		if (!WOULD_BLOCK(err)) {
			conns[i].state |= CS_CLOSED;
			return -1;
		}
		n = 0;
	}
	if (n > 0) {
		conns[i].downn -= n;
		if (conns[i].downn == 0) {
			free(conns[i].downb);
			if (dummy) {
				conns[i].state |= CS_CLOSED;
				return -1;
			}
			else change_events(i);
		} else {
			conns[i].downbptr += n;
		}
		clients[conns[i].client].csx += n;
		conns[i].csx += n;
	}
	return n;
}

/* This only talks upstream and does not need ssl */
static int flush_up(int i)
{
	int n, err = 0;

       struct sockaddr name;
       size_t size = sizeof(struct sockaddr);

	if (!udp) {
		n = my_send(conns[i].upfd, conns[i].upbptr, conns[i].upn, 0);
	} else {
		n = sendto(conns[i].upfd, (void *)conns[i].upbptr, conns[i].upn, 0,
			(struct sockaddr *) &name, size);
		conns[i].state &= ~CS_HALFDEAD;
	}
	err = socket_errno;

	DEBUG(2, "flush_up(%d): send(%d, %p, %d, 0) returns %d, errno = %d, socket_errno = %d", \
		i, conns[i].upfd, conns[i].upbptr, conns[i].upn, n, errno, socket_errno);
	if (n == -1) {
		if (!WOULD_BLOCK(err)) {
			conns[i].state |= CS_CLOSED;
			return -1;
		}
		n = 0;
	}
	if (n > 0) {
		conns[i].upn -= n;
		if (conns[i].upn == 0) {
			free(conns[i].upb);
			change_events(i);
		} else {
			conns[i].upbptr += n;
		}
		conns[i].ssx += n;
	}
	return n;
}

#ifndef WINDOWS
static void setup_signals(void)
{
	usr1action.sa_handler = stats;
	sigemptyset(&usr1action.sa_mask);
	usr1action.sa_flags = 0;
	sigaction(SIGUSR1, &usr1action, NULL);

	usr2action.sa_handler = die;
	sigemptyset(&usr2action.sa_mask);
	usr2action.sa_flags = 0;
	sigaction(SIGUSR2, &usr2action, NULL);

	hupaction.sa_handler = restart_log;
	sigemptyset(&hupaction.sa_mask);
	hupaction.sa_flags = 0;
	sigaction(SIGHUP, &hupaction, NULL);

	termaction.sa_handler = quit;
	sigemptyset(&termaction.sa_mask);
	termaction.sa_flags = 0;
	sigaction(SIGTERM, &termaction, NULL);

	alrmaction.sa_handler = alarm_handler;
	sigemptyset(&alrmaction.sa_mask);
	alrmaction.sa_flags = 0;
	signal(SIGPIPE, SIG_IGN);
}

static void check_signals(void)
{
	if (stats_flag) {
		if (webfile) webstats();
		else textstats();
		stats_flag=0;
	}
	if (restart_log_flag) {
		if (logfp) {
			fclose(logfp);
			logfp = fopen(logfile, "a");
			if (!logfp) 
				error("Can't open logfile %s", logfile);
		}
		read_cfg(cfgfile);
		restart_log_flag=0;
	}
}
#else
static void setup_signals(void)
{
	;
}

static void check_signals(void)
{
	;
}
#endif

static void check_listen_socket(void)
{
	struct sockaddr_storage cli_addr;
	socklen_t clilen = sizeof cli_addr;
	int i, downfd;
	DEBUG(2, "check_listen_socket()");
	if (dsr_if) {
		/* special case for dsr */
		dsr_frame(listenfd);
	} else if (udp) {
		/* special case for udp */
		downfd = 0;
		add_client(downfd, &cli_addr);
	} else {
	/* process tcp connection(s) */
		for (i = 0; i < multi_accept; i++) {
			if (connections_used >= connections_max) break;
			if (pending_queue >= pending_max) break;
			downfd = accept_nb(listenfd,
				(struct sockaddr *)&cli_addr, &clilen);
			if (downfd < 0) {
				if (debuglevel && errno != EAGAIN) {
					debug("accept: %s", strerror(errno));
				}
				break;
			}
			if (clilen == 0) {
				DEBUG(1, "clilen: %s", strerror(errno));
				break;
			}
			add_client(downfd, &cli_addr);
		}
		DEBUG(2, "accepted %d connections", i);
	}
}

static void check_control_socket(void)
{
	struct sockaddr_storage cli_addr;
	socklen_t clilen = sizeof cli_addr;
	int downfd = accept(ctrlfd, (struct sockaddr *) &cli_addr, &clilen);
	DEBUG(2, "check_control_socket()");
	if (downfd < 0) {
		DEBUG(1, "accept: %s", strerror(errno));
		return;
	}
	if (clilen == 0) {
		DEBUG(1, "clilen: %s", strerror(errno));
		return;
	}
	do_ctrl(downfd, &cli_addr);
}

static void check_if_connected(int i)
{
	int result;
	socklen_t length = sizeof result;
	DEBUG(2, "Something happened to connection %d", i);
	if (getsockopt(conns[i].upfd, SOL_SOCKET, SO_ERROR, (void *)&result, &length) < 0) {
		debug("Can't getsockopt: %s", strerror(errno));
		close_conn(i);
		return;
	}
	if (result != 0) {
		debug("Connect failed: %s", strerror(result));
		debug("blacklisting server %d because of connect failure", conns[i].server);
		blacklist_server(conns[i].server);
		if (failover_server(i) == 0) {
			//close_conn(i);
		}
		return;
	}
	DEBUG(2, "Connection %d completed", i);
	if (conns[i].state & CS_IN_PROGRESS) {
		pending_list = dlist_remove(conns[i].pend);
		pending_queue--;
	}
	conns[i].state = CS_CONNECTED;
	conns[i].t = now;
	if (conns[i].downfd == -1) {
		/* idler */
		conns[i].state |= CS_CLOSED_DOWN;
	} else {
		event_add(conns[i].downfd, EVENT_READ);
	}
	event_arm(conns[i].upfd, EVENT_READ);
	servers[conns[i].server].c++;
}

static void check_if_timeout(int i)
{
	DEBUG(2, "check_if_timeout(%d, %d)\n" \
		"conns[%d].t = %d\n" \
		"now-conns[%d].t = %d", \
		(int)now, i, i, conns[i].t, i, now-conns[i].t);
	if (now-conns[i].t >= timeout) {
		DEBUG(2, "Connection %d timed out", i);
		debug("blacklisting server %d because of connect timeout", conns[i].server);
		blacklist_server(conns[i].server);
		if (failover_server(i) == 0) {
			//close_conn(i);
		}
	} else {
		DEBUG(2, "Keep waiting...");
	}
}

static int try_copy_up(int i)
{
	DEBUG(2, "want to read from downstream socket %d of connection %d", conns[i].downfd, i);
	if (copy_up(i) < 0) {
		//close_conn(i);
		return 0;
	}
	return 1;
}

static int try_copy_down(int i)
{
	DEBUG(2, "want to read from upstream socket %d of connection %d", conns[i].upfd, i);
	if (copy_down(i) < 0) {
		//close_conn(i);
		return 0;
	}
	return 1;
}

static int try_flush_down(int i)
{
	DEBUG(2, "want to write to downstream socket %d of connection %d", conns[i].downfd, i);
	if (flush_down(i) < 0) {
		//close_conn(i);
		return 0;
	}
	return 1;
}

static int try_flush_up(int i)
{
	DEBUG(2, "want to write to upstream socket %d of connection %d", conns[i].upfd, i);
	if (flush_up(i) < 0) {
		//close_conn(i);
		return 0;
	}
	return 1;
}

static void arm_listenfd(void)
{
	static int can_accept = 0;

	if (udp) {
		event_arm(listenfd, EVENT_READ);
	} else if (can_accept) {
		if (connections_used >= connections_max) {
			event_arm(listenfd, 0);
			can_accept = 0;
		}
	} else {
		if (connections_used < connections_max) {
			event_arm(listenfd, EVENT_READ);
			can_accept = 1;
		}
	}
}

static int handle_events(int *pending_close)
{
	int fd, conn, events;
	int npc = 0;

        for (fd = event_fd(&events); fd != -1; fd = event_fd(&events)) {
		int closing = 0;
		DEBUG(2, "event_fd returns fd=%d, events=%d", fd, events);
		if (events == 0) continue;
                if (fd == listenfd) {
                        if (events & EVENT_READ) {
                                check_listen_socket();
                        }
                        continue;
                }
                if (fd == ctrlfd) {
                        if (events & EVENT_READ) {
                                check_control_socket();
                        }
                        continue;
                }
                conn = fd2conn_get(fd);
		DEBUG(3, "fd = %d => conn = %d", fd, conn);
		if (conn == -1) continue;

		if (events & EVENT_ERR) {
			DEBUG(2, "Error on fd %d, connection %d", fd, conn);
			conns[conn].state |= CS_CLOSED;
		} else if (conns[conn].state & CS_IN_PROGRESS) {
                        if (fd == conns[conn].upfd && events & EVENT_WRITE) {
                                check_if_connected(conn);
                        }
                } else {
			conns[conn].t = now;
                	if (fd == conns[conn].downfd) {
                        	if (events & EVENT_READ) {
                                	if (!try_copy_up(conn)) closing = 1;
                        	}
                        	if (events & EVENT_WRITE) {
                                	if (!try_flush_down(conn)) closing = 1;
                        	}
                	} else {        /* down */
                        	if (events & EVENT_READ) {
                                	if (!try_copy_down(conn)) closing = 1;
                        	}
                        	if (events & EVENT_WRITE) {
                                	if (!try_flush_up(conn)) closing = 1;
                        	}
                	}
		}
		if ((conns[conn].state & CS_CLOSED) == CS_CLOSED) {
			DEBUG(2, "Connection %d was closed", conn);
			closing = 1;
		}

		if (closing) {
			pending_close[npc++] = conn;
		}
        }
	return npc;
}

static void pending_and_closing(int *pending_close, int npc)
{
	int j, p, start, npe;

	if (pending_list != -1) {
		npe = npc;
		p = start = pending_list;
		do {
			int conn = dlist_value(p);
			if (conns[conn].state & CS_IN_PROGRESS) {
				pending_close[npe++] = conn;
			}
			p = dlist_next(p);
		} while (p != start);
		for (j = npc; j < npe; j++) {
			check_if_timeout(pending_close[j]);
		}
	}
        for (j = 0; j < npc; j++) {
		int conn = pending_close[j];
                if (closing_time(conn)) {
			close_conn(conn);
		}
        }
	if (idlers > idlers_wanted) {
		close_idlers(idlers-idlers_wanted);
	}
	while (idlers < idlers_wanted) {
		if (!add_idler()) break;
	}
}

static void check_idle_timeout(void)
{
	static int conn = 0;
	int i, n;

	if (idle_timeout == 0) return;
	n = connections_max/idle_timeout;

	DEBUG(2, "check_idle_timeout(): conn=%d, n=%d", conn, n);
	for (i = 0; i < n; i++) {
		if (conns[conn].state == CS_CONNECTED &&
		    now-conns[conn].t >= idle_timeout) {
			DEBUG(2, "Connection %d idle for %d seconds, closing",
				conn, now-conns[conn].t);
			close_conn(conn);
		}
		conn = (conn+1)%connections_max;
	}
}

void mainloop(void)
{
        int npc;
        int *pending_close;
	event_init();
	event_add(listenfd, EVENT_READ);
	dlist_init(connections_max);
	if (ctrlfd != -1) event_add(ctrlfd, EVENT_READ);
        setup_signals();
        loopflag = 1;
        pending_close = pen_malloc(connections_max * sizeof *pending_close);
	DEBUG(2, "mainloop()");
        while (loopflag) {
                check_signals();
		if (dsr_if) dsr_arp(listenfd);
		arm_listenfd();
                event_wait();
                now = time(NULL);
		DEBUG(2, "After event_wait()");
		npc = handle_events(pending_close);
		pending_and_closing(pending_close, npc);
		check_idle_timeout();
        }
}

static int options(int argc, char **argv)
{
	int c;
	char b[1024];

#ifdef HAVE_LIBSSL
	char *opt = "B:C:F:O:S:T:b:c:e:i:j:l:m:o:p:q:t:u:w:x:DHNPQWXUadfhnrsE:K:G:A:ZRL:";
#else
	char *opt = "B:C:F:O:S:T:b:c:e:i:j:l:m:o:p:q:t:u:w:x:DHNPQWXUadfhnrs";
#endif

	while ((c = getopt(argc, argv, opt)) != -1) {
		switch (c) {
		case 'B':
			a_server = optarg;
			break;
		case 'C':
			ctrlport = optarg;
			break;
		case 'D':
			fprintf(stderr, "Pen 0.26.0 removed the delayed forward feature,\n"
					"making the -D option obsolete\n");
			break;
		case 'F':
			cfgfile = optarg;
			break;
		case 'H':
			http = 1;
			break;
		case 'O':
			do_cmd(optarg, output_file, stdout);
			break;
		case 'Q':
			fprintf(stderr, "Since Pen 0.26.0, kqueue is already the default on supported systems,\n"
					"making the -Q option obsolete\n");
			break;
		case 'P':
			event_init = poll_init;
			break;
		case 'S':
			fprintf(stderr, "As of 0.28.1 the server table is expanded dynamically,\n"
					"making the -S option obsolete\n");
			break;
		case 'T':
			tracking_time = atoi(optarg);
			break;
		case 'U':
			udp = 1;
			break;
		case 'W':
			server_alg |= ALG_WEIGHT;
			break;
		case 'X':
	    		exit_enabled = 1;
	    		break;
		case 'a':
			asciidump = 1;
			break;
		case 'b':
			blacklist_time = atoi(optarg);
			break;
		case 'c':
			expand_clienttable(atoi(optarg));
			break;
		case 'd':
			debuglevel++;
			break;
		case 'e':
			e_server = optarg;
			break;
		case 'f':
			foreground = 1;
			break;
		case 'h':
			server_alg |= ALG_HASH;
			break;
		case 'i':
#ifdef WINDOWS
			install_service(optarg);
#else
			fprintf(stderr, "Windows only\n");
#endif
			exit(0);
		case 'j':
			jail = optarg;
			break;
		case 'l':
			logfile = pen_strdup(optarg);
			break;
		case 'm':
			multi_accept = atoi(optarg);
			if (multi_accept < 1) {
				fprintf(stderr, "multi_accept bumped to 1\n");
				multi_accept = 1;
			}
			break;
		case 'n':
			fprintf(stderr, "Pen 0.26.0 and up uses only nonblocking sockets,\n"
					"making the -n option obsolete\n");
			break;
		case 'o':
			snprintf(b, sizeof b, "%s", optarg);
			do_cmd(optarg, output_file, stdout);
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'q':
			listen_queue = atoi(optarg);
			if (listen_queue < 50) {
				fprintf(stderr, "listen_queue bumped to 50\n");
				listen_queue = 50;
			}
			break;
		case 'r':
			server_alg |= ALG_ROUNDROBIN;
			break;
		case 's':
			server_alg |= ALG_STUBBORN;
			break;
		case 't':
			timeout = atoi(optarg);
			if (timeout < 1) {
				usage();
			}
			break;
		case 'u':
#ifdef WINDOWS
			delete_service(optarg);
			exit(0);
#else
			user = optarg;
#endif
			break;
		case 'x':
			expand_conntable(atoi(optarg));
			break;
		case 'w':
			webfile = pen_strdup(optarg);
			break;
#ifdef HAVE_LIBSSL
		case 'E':
			certfile = optarg;
			break;
		case 'K':
			keyfile = optarg;
			break;
		case 'G':
			cacert_file = optarg;
			break;
		case 'A':
			cacert_dir = optarg;
			break;
		case 'Z':
			ssl_compat = 1;
			break;
		case 'R':
			require_peer_cert = 1;
			break;
		case 'L':
			if (strcmp(optarg, "ssl23") == 0)
				ssl_protocol = SRV_SSL_V23;
			else if (strcmp(optarg, "ssl2") == 0)
				ssl_protocol = SRV_SSL_V2;
			else if (strcmp(optarg, "ssl3") == 0)
				ssl_protocol = SRV_SSL_V3;
			else if (strcmp(optarg, "tls1") == 0)
				ssl_protocol = SRV_SSL_TLS1;
			else {
				fprintf(stderr, "protocol version %s not known\n", optarg);
				exit(1);
			}
			break;
#endif  /* HAVE_LIBSSL */
		case '?':
		default:
			usage();
		}
	}

	return optind;
}

int main(int argc, char **argv)
{
	int i, n;

	acl_init();

	n = options(argc, argv);
	argc -= n;
	argv += n;

	now = time(NULL);
#ifdef WINDOWS
	start_winsock();
#endif

	read_cfg(cfgfile);

#ifndef WINDOWS
	if (listenfd == -1 && argc < 1) {
		usage();
	}

	struct rlimit r;
	getrlimit(RLIMIT_CORE, &r);
	r.rlim_cur = r.rlim_max;
	setrlimit(RLIMIT_CORE, &r);

	signal(SIGCHLD, SIG_IGN);

	if (!foreground) {
		background();
	}
#endif

	/* we must open listeners before dropping privileges */
	/* Control port */
	if (ctrlport) {
		if (getuid() == 0 && user == NULL) {
			debug("Won't open control port running as root; use -u to run as different user");
		} else {
			ctrlfd = open_listener(ctrlport, SOCK_STREAM);
		}
	}


	/* Balancing port */
	if (listenfd == -1) {
		snprintf(listenport, sizeof listenport, "%s", argv[0]);
		/* Direct server return */
		if (dsr_if) {
			listenfd = dsr_init(dsr_if, listenport);
			if (listenfd == -1) {
				error("Can't initialize direct server return");
			}
		} else {
			listenfd = open_listener(listenport, udp ? SOCK_DGRAM : SOCK_STREAM);
		}
	}
	init(argc, argv);

#ifdef HAVE_LIBSSL
	if (certfile) {
		ssl_init();
	}
#endif

#ifndef WINDOWS
	/* we must look up user id before chrooting */
	struct passwd *pwd = NULL;
	if (user) {
		DEBUG(1, "Run as user %s", user);
		pwd = getpwnam(user);
		if (pwd == NULL) error("Can't getpwnam(%s)", user);
	}

	/* we must chroot before dropping privileges */
	if (jail) {
		DEBUG(1, "Run in %s", jail);
		if (chroot(jail) == -1) error("Can't chroot(%s)", jail);
	}

	/* ready to defang ourselves */
	if (pwd) {
		if (setgid(pwd->pw_gid) == -1)
			error("Can't setgid(%d)", (int)pwd->pw_gid);
		if (setuid(pwd->pw_uid) == -1)
			error("Can't setuid(%d)", (int)pwd->pw_uid);
	}
#endif

	open_log(logfile);
	if (pidfile) {
		pidfp = fopen(pidfile, "w");
		if (!pidfp) {
			error("Can't create pidfile %s", pidfile);
			exit(1);
		}
		fprintf(pidfp, "%d", (int)getpid());
		fclose(pidfp);
	}

#ifdef WINDOWS
	if (!foreground) {
		char cfgdir[1024], *p, dirsep = '\\';
		GetModuleFileName(NULL, cfgdir, sizeof cfgdir);
		cfgdir[sizeof cfgdir - 1] = '\0';
		p = strrchr(cfgdir, dirsep);
		if (p) *p = '\0';
		chdir(cfgdir);
		read_cfg("pen.cfg");
		service_main(0, NULL);
	} else {
		mainloop();
	}
#else
	mainloop();
#endif

	DEBUG(1, "Exiting, cleaning up...");
	if (logfp) fclose(logfp);
	for (i = 0; i < connections_max; i++) {
		if (conns[i].downfd != -1) close_conn(i);
	}
	close(listenfd);
	if (pidfile) {
		unlink(pidfile);
	}
	return 0;
}
