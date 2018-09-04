#include "config.h"
#include <stdlib.h>
#include <string.h>
#ifndef WINDOWS
#include <sys/socket.h>
#endif
#include <unistd.h>
#include "conn.h"
#include "client.h"
#include "diag.h"
#include "dlist.h"
#include "event.h"
#include "idlers.h"
#include "memory.h"
#include "pen.h"
#include "server.h"
#include "settings.h"

int idle_timeout = 0;	/* never time out */
int pending_list = -1;	/* pending connections */
int pending_queue = 0;	/* number of pending connections */
int pending_max = 100;	/* max number of pending connections */
connection *conns;
int connections_max = 0;
int connections_used = 0;
int connections_last = 0;
int tracking_time = TRACKING_TIME;
static int fd2conn_max = 0;
static int *fd2conn;

/* store_conn does fd2conn_set(fd, conn) */
/* close_conn does fd2conn_set(fd, -1) */
void fd2conn_set(int fd, int conn)
{
	DEBUG(3, "fd2conn_set(fd=%d, conn=%d)", fd, conn);
	if (fd < 0) error("fd2conn_set(fd = %d, conn = %d)", fd, conn);
	if (fd >= fd2conn_max) {
		int i, new_max = fd+10000;
		DEBUG(2, "expanding fd2conn to %d bytes", new_max);
		fd2conn = pen_realloc(fd2conn, new_max * sizeof *fd2conn);
		for (i = fd2conn_max; i < new_max; i++) fd2conn[i] = -1;
		fd2conn_max = new_max;
	}
	fd2conn[fd] = conn;
}

int fd2conn_get(int fd)
{
	if (fd < 0 || fd >= fd2conn_max) return -1;
	return fd2conn[fd];
}

int closing_time(int conn)
{
	int closed = conns[conn].state & CS_CLOSED;

	if (closed == CS_CLOSED) return 1;
	if (conns[conn].downn + conns[conn].upn == 0) {
		return closed & tcp_fastclose;
	}
	return 0;
}

#ifdef HAVE_LIBSSL
int store_conn(int downfd, SSL *ssl, int client)
#else
int store_conn(int downfd, int client)
#endif
{
	int i;

	i = connections_last;
	do {
		if ((conns[i].state == CS_UNUSED) || (conns[i].state & CS_HALFDEAD)) break;
		if (udp) conns[i].state |= CS_HALFDEAD;
		i++;
		if (i >= connections_max) i = 0;
	} while (i != connections_last);

	/* For TCP, we have either CS_UNUSED or something we can't use */
	/* For UDP, we have either CS_UNUSED or CS_HALFDEAD */
	if (conns[i].state & CS_HALFDEAD) {
		DEBUG(2, "Recycling halfdead connection %d", i);
		close_conn(i);
	}
	/* And now UDP is guaranteed to be CS_UNUSED */

	if (conns[i].state == CS_UNUSED) {
		connections_last = i;
		connections_used++;
		DEBUG(2, "incrementing connections_used to %d for connection %d",
			connections_used, i);
		conns[i].upfd = -1;
		conns[i].downfd = downfd;
		if (downfd != -1) fd2conn_set(downfd, i);
#ifdef HAVE_LIBSSL
		conns[i].ssl = ssl;
#endif
		conns[i].client = client;
		conns[i].initial = NO_SERVER;
		conns[i].server = NO_SERVER;
		conns[i].srx = conns[i].ssx = 0;
		conns[i].crx = conns[i].csx = 0;
	} else {
		i = -1;
		if (debuglevel)
			debug("Connection table full (%d slots), can't store connection.\n"
			      "Try restarting with -x %d",
			      connections_max, 2*connections_max);
		if (downfd != -1) close(downfd);
	}
	DEBUG(2, "store_conn: conn = %d, downfd = %d, connections_used = %d", \
		i, downfd, connections_used);
	return i;
}

int idler(int conn)
{
	return (conns[conn].state & CS_CONNECTED) && (conns[conn].client == -1);
}

void close_conn(int i)
{
	int index = conns[i].server;

	/* unfinished connections have server == NO_SERVER */
	if (index != NO_SERVER) {
		servers[index].c -= 1;
		if (servers[index].c < 0) servers[index].c = 0;
	}

	if (conns[i].upfd != -1 && conns[i].upfd != listenfd) {
		event_delete(conns[i].upfd);
		close(conns[i].upfd);
		fd2conn_set(conns[i].upfd, -1);
	}
#ifdef HAVE_LIBSSL
	if (conns[i].ssl) {
		int n = SSL_shutdown(conns[i].ssl);
		DEBUG(3, "First SSL_shutdown(%d) returns %d", conns[i].ssl, n);
		if (n == 0) {
			n = SSL_shutdown(conns[i].ssl);
			DEBUG(3, "Second SSL_shutdown(%d) returns %d", conns[i].ssl, n);
		}
		if (n == -1) {
			n = SSL_get_error(conns[i].ssl, n);
			DEBUG(3, "%s", ERR_error_string(SSL_get_error(conns[i].ssl, n), NULL));
			ERR_print_errors_fp(stderr);
		}
		SSL_free(conns[i].ssl);
		conns[i].ssl = 0;
	}
#endif
	if (conns[i].downfd != -1 && conns[i].downfd != listenfd) {
		event_delete(conns[i].downfd);
		close(conns[i].downfd);
		fd2conn_set(conns[i].downfd, -1);
	}
	if (idler(i)) idlers--;
	conns[i].upfd = conns[i].downfd = -1;
	if (conns[i].downn) {
		free(conns[i].downb);
		conns[i].downn=0;
	}
	if (conns[i].upn) {
		free(conns[i].upb);
		conns[i].upn=0;
	}
	connections_used--;
	DEBUG(2, "decrementing connections_used to %d for connection %d",
		connections_used, i);
	if (connections_used < 0) {
		debug("connections_used = %d. Resetting.", connections_used);
		connections_used = 0;
	}
	if (conns[i].state & CS_IN_PROGRESS) {
		pending_list = dlist_remove(conns[i].pend);
		pending_queue--;
	}
	conns[i].state = CS_UNUSED;
	DEBUG(2, "close_conn: Closing connection %d to server %d; connections_used = %d\n" \
		"\tRead %ld from client, wrote %ld to server\n" \
		"\tRead %ld from server, wrote %ld to client", \
		i, index, connections_used, \
		conns[i].crx, conns[i].ssx, \
		conns[i].srx, conns[i].csx);
	DEBUG(3, "Aggregate for server %d: sx=%d, rx=%d",
		conns[i].server, servers[conns[i].server].sx, servers[conns[i].server].rx);
}

void expand_conntable(size_t size)
{
	int i;
	DEBUG(1, "expand_conntable(%d)", size);
	if (size < connections_max) return;	/* nothing to do */
	conns = pen_realloc(conns, size*sizeof *conns);
	memset(&conns[connections_max], 0, (size-connections_max)*sizeof *conns);
	for (i = connections_max; i < size; i++) {
		conns[i].upfd = conns[i].downfd = -1;
	}
	connections_max = size;
}

