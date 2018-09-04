#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#ifndef WINDOWS
#include <netinet/in.h>
#endif
#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "acl.h"
#include "client.h"
#include "conn.h"
#include "diag.h"
#include "dlist.h"
#include "event.h"
#include "memory.h"
#include "netconv.h"
#include "pen.h"
#include "server.h"
#include "settings.h"
#include "windows.h"

#ifndef WINDOWS
#define CONNECT_IN_PROGRESS (EINPROGRESS)
#endif

int nservers = 0;
server *servers = NULL;

int current;		/* current server */
int emerg_server = NO_SERVER;	/* server of last resort */
static int emergency = 0;	/* are we using the emergency server? */
int abuse_server = NO_SERVER;	/* server for naughty clients */
int blacklist_time = BLACKLIST_TIME;
int server_alg;
char *e_server = NULL;
char *a_server = NULL;

static int pen_hash(struct sockaddr_storage *a)
{
	struct sockaddr_in *si;
	struct sockaddr_in6 *si6;
	unsigned char *u;
	int hash;

	switch (a->ss_family) {
	case AF_INET:
		si = (struct sockaddr_in *)a;
		if (server_alg & ALG_ROUNDROBIN) {
			hash = (si->sin_addr.s_addr ^ si->sin_port) % (nservers?nservers:1);
		} else {
			hash = si->sin_addr.s_addr % (nservers?nservers:1);
		}

		DEBUG(2, "Hash: %d", hash);

		return hash;

	case AF_INET6:
		si6 = (struct sockaddr_in6 *)a;
		u = (unsigned char *)(&si6->sin6_addr);
		return u[15] % (nservers?nservers:1);
	default:
		return 0;
	}
}

/* Introduce the new format "[address]:port:maxc:hard:weight:prio"
   in addition to the old one.
*/
void setaddress(int server, char *s, int dp, int proto)
{
	char address[1024], pno[100];
	int n;
	char *format;
	int port;

	if (s[0] == '[') {
		format = "[%999[^]]]:%99[^:]:%d:%d:%d:%d";
	} else {
		format = "%999[^:]:%99[^:]:%d:%d:%d:%d";
	}
	n = sscanf(s, format, address, pno,
		&servers[server].maxc, &servers[server].hard,
		&servers[server].weight, &servers[server].prio);

	if (n > 1) port = getport(pno, proto);
	else port = dp;
	if (n < 3) servers[server].maxc = 0;
	if (n < 4) servers[server].hard = 0;
	if (n < 5) servers[server].weight = 0;
	if (n < 6) servers[server].prio = 0;

	DEBUG(2, "n = %d, address = %s, pno = %d, maxc1 = %d, hard = %d, weight = %d, prio = %d, proto = %d ", \
		n, address, port, servers[server].maxc, \
		servers[server].hard, servers[server].weight, \
		servers[server].prio, proto);

	if (pen_aton(address, &servers[server].addr) == 0) {
		error("unknown or invalid address [%s]", address);
	}
	memset(servers[server].hwaddr, 0, 6);
	pen_setport(&servers[server].addr, port);
}

void blacklist_server(int server)
{
	servers[server].status = now;
}

int unused_server_slot(int i)
{
	struct sockaddr_storage *a = &servers[i].addr;
	if (a->ss_family == AF_INET) {
		struct sockaddr_in *si = (struct sockaddr_in *)a;
		if (si->sin_addr.s_addr == 0) return i;
	}
	return 0;
}

int server_is_blacklisted(int i)
{
	return (now-servers[i].status < blacklist_time);
}

int server_is_unavailable(int i)
{
	return unused_server_slot(i) || server_is_blacklisted(i);
}

static int server_by_weight(void)
{
	int best_server = NO_SERVER;
	int best_load = -1;
	int i, load;

	DEBUG(2, "server_by_weight()");
	for (i = 0; i < nservers; i++) {
		if (server_is_unavailable(i)) continue;
		if (servers[i].weight == 0) continue;
		load = (WEIGHT_FACTOR*servers[i].c)/servers[i].weight;
		if (best_server == NO_SERVER || load < best_load) {
			DEBUG(2, "Server %d has load %d", i, load);
			best_load = load;
			best_server = i;
		}
	}
	DEBUG(2, "Least loaded server = %d", best_server);
	return best_server;
}

static int server_by_prio(void)
{
	int best_server = NO_SERVER;
	int best_prio = -1;
	int i, prio;

	DEBUG(2, "server_by_prio()");
	for (i = 0; i < nservers; i++) {
		if (server_is_unavailable(i)) continue;
		prio = servers[i].prio;
		if (best_server == NO_SERVER || prio < best_prio) {
			DEBUG(2, "Server %d has prio %d", i, prio);
			best_prio = prio;
			best_server = i;
		}
	}
	DEBUG(2, "Best prio server = %d", best_server);
	return best_server;
}

int server_by_roundrobin(void)
{
	static int last_server = 0;
	int i = last_server;

	if (nservers == 0) return NO_SERVER;
	do {
		i = (i+1) % (nservers?nservers:1);
		DEBUG(3, "server_by_roundrobin considering server %d", i);
		if (!server_is_unavailable(i)) return (last_server = i);
		DEBUG(3, "server %d is unavailable, try next one", i);
	} while (i != last_server);
	return NO_SERVER;
}

/* Suggest a server for the initial field of the connection.
   Return NO_SERVER if none available.
*/
int initial_server(int conn)
{
	int pd = match_acl(client_acl, &clients[conns[conn].client].addr);
	if (!pd) {
		DEBUG(1, "initial_server: denied by acl");
		return abuse_server;
		/* returning abuse_server is correct even if it is not set
		   because it defaults to NO_SERVER */
	}
	if (!(server_alg & ALG_ROUNDROBIN)) {
		// Load balancing with memory == No roundrobin
		int server = clients[conns[conn].client].server;
		/* server may be NO_SERVER if this is a new client */
		if (server != NO_SERVER && server != emerg_server && server != abuse_server) {
			DEBUG(2, "Will try previous server %d for client %d", server, conns[conn].client);
			return server;
		}
	}
	if (server_alg & ALG_PRIO) return server_by_prio();
	if (server_alg & ALG_WEIGHT) return server_by_weight();
	if (server_alg & ALG_HASH) return pen_hash(&clients[conns[conn].client].addr);
	return server_by_roundrobin();
}

/* Returns 1 if a failover server candidate is available.
   Close connection and return 0 if none was found.
*/
int failover_server(int conn)
{
	int server = conns[conn].server;
	DEBUG(2, "failover_server(%d): server = %d", conn, server);
	if (server_alg & ALG_STUBBORN) {
		DEBUG(2, "Won't failover because we are stubborn");
		close_conn(conn);
		return 0;
	}
	if (server == ABUSE_SERVER) {
		DEBUG(2, "Won't failover from abuse server (%d)", abuse_server);
		close_conn(conn);
		return 0;
	}
	if (server == EMERGENCY_SERVER) {
		DEBUG(2, "Already using emergency server (%d), won't fail over", emerg_server);
		close_conn(conn);
		return 0;
	}
	if (conns[conn].upfd != -1) {
		if (conns[conn].state & CS_IN_PROGRESS) {
			pending_list = dlist_remove(conns[conn].pend);
			pending_queue--;
		}

		close(conns[conn].upfd);
		conns[conn].upfd = -1;
	}
	/* there needs to be at least two regular servers in order to fail over to something else */
	/* and if we couldn't find a candidate for initial_server, we're not going to find one now */
	if (nservers > 1 && server != NO_SERVER) {
		DEBUG(2, "Trying to find failover server. server = %d, initial = %d, nservers = %d", server, conns[conn].initial, nservers);
		do {
			server = (server+1) % nservers;
			DEBUG(2, "Intend to try server %d", server);
			if (try_server(server, conn)) return 1;
		} while (server != conns[conn].initial);
	}
	DEBUG(1, "using emergency server, remember to reset flag");
	emergency = 1;
	if (try_server(emerg_server, conn)) return 1;
	close_conn(conn);
	return 0;
}

/* Using os-specific, similar but incompatible techniques, attempt to be transparent by
   setting our local upstream address to the client's address */
static void spoof_bind(int server, int conn, int upfd)
{
#if defined(IP_TRANSPARENT)	/* Linux */
#define SOL_TRANSPARENCY SOL_IP
#define PEN_TRANSPARENCY IP_TRANSPARENT
#elif defined(SO_BINDANY)	/* OpenBSD */
#define SOL_TRANSPARENCY SOL_SOCKET
#define PEN_TRANSPARENCY SO_BINDANY
#elif defined(IP_BINDANY)	/* FreeBSD */
#define SOL_TRANSPARENCY IPPROTO_IP
#define PEN_TRANSPARENCY IP_BINDANY
#else
#undef PEN_TRANSPARENCY
#endif

#ifdef PEN_TRANSPARENCY
	int client = conns[conn].client;
	int n;
	int one = 1;
	struct sockaddr_storage *sss = &servers[server].addr;
	struct sockaddr_storage *css = &clients[client].addr;
	struct sockaddr_in *caddr, addr;
	DEBUG(1, "spoof_bind(server = %d, conn = %d, upfd = %d)", server, conn, upfd);
	DEBUG(1, "client = %d", client);
	if (sss->ss_family != AF_INET || css->ss_family != AF_INET) {
		DEBUG(1, "server family = %d", sss->ss_family);
		DEBUG(1, "client family = %d", css->ss_family);
		debug("No transparency for incompatible families");
		return;
	}
	n = setsockopt(upfd, SOL_TRANSPARENCY, PEN_TRANSPARENCY, &one, sizeof one);
	if (n == -1) {
		DEBUG(1, "upfd = %d", upfd);
		debug("setsockopt: %s", strerror(errno));
		return;
	}
	caddr = (struct sockaddr_in *)css;
	addr.sin_family = caddr->sin_family;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = caddr->sin_addr.s_addr;
	n = bind(upfd, (struct sockaddr *)&addr, sizeof addr);
	if (n == -1) {
		DEBUG(1, "upfd = %d", upfd);
		debug("bind: %s", strerror(errno));
		return;
	}
#else
	debug("You are trying to be transparent, but it is not supported");
#endif
}

/* Initiate connection to server 'index' and populate upfd field in connection */
/* return 1 for (potential) success, 0 for failure */
int try_server(int index, int conn)
{
	int upfd;
	int client = conns[conn].client;
	int n = 0, err;
	int optval = 1;
	struct sockaddr_storage *addr = &servers[index].addr;
	/* The idea is that a client should be able to connect again to the same server
	   even if the server is close to its configured connection limit */
	int sticky = ((client != -1) && (index == clients[client].server));

	if (index == NO_SERVER) {
		DEBUG(2, "Won't try to connect to NO_SERVER");
		return 0;	/* out of bounds */
	}
	DEBUG(2, "Trying server %d for connection %d at time %d", index, conn, now);
	if (pen_getport(addr) == 0) {
		DEBUG(1, "No port for you!");
		return 0;
	}
	if (now-servers[index].status < blacklist_time) {
		DEBUG(1, "Server %d is blacklisted", index);
		return 0;
	}
	if (servers[index].maxc != 0 &&
	    (servers[index].c >= servers[index].maxc) &&
	    (sticky == 0 || servers[index].c >= servers[index].hard)) {
		DEBUG(1, "Server %d is overloaded: sticky=%d, maxc=%d, hard=%d", \
				index, sticky, servers[index].maxc, servers[index].hard);
		return 0;
	}
	if ((client != -1) && !match_acl(servers[index].acl, &(clients[client].addr))) {
		DEBUG(1, "try_server: denied by acl");
		return 0;
	}
	upfd = socket_nb(addr->ss_family, udp ? SOCK_DGRAM : SOCK_STREAM, 0);

	if (keepalive) {
		setsockopt(upfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&optval, sizeof optval);
	}

	if (debuglevel > 1) {
		debug("Connecting to %s", pen_ntoa(addr));
		pen_dumpaddr(addr);
	}
	conns[conn].t = now;

	if (source) {
		/* specify local address for upstream connection */
		int n = bind(upfd, (struct sockaddr *)source, pen_ss_size(source));
		if (n == -1) {
			debug("bind: %s", strerror(errno));
		}
	} else if (transparent) {
		/* use originating client's address for upstream connection */
		spoof_bind(index, conn, upfd);
	}

	n = connect(upfd, (struct sockaddr *)addr, pen_ss_size(addr));
	err = socket_errno;
	DEBUG(2, "connect (upfd = %d) returns %d, errno = %d, socket_errno = %d",
		upfd, n, errno, err);
	/* A new complication is that we don't know yet if the connect will succeed. */
	if (n == 0) {		/* connection completed */
		conns[conn].state = CS_CONNECTED;
		if (conns[conn].downfd == -1) {
			/* idler */
			conns[conn].state |= CS_CLOSED_DOWN;
		}
		event_add(upfd, EVENT_READ);
		event_add(conns[conn].downfd, EVENT_READ);
		servers[index].c++;
		if (servers[index].status) {
			servers[index].status = 0;
			DEBUG(1, "Server %d ok", index);
		}
		DEBUG(2, "Successful connect to server %d\n" \
			"conns[%d].client = %d\n" \
			"conns[%d].server = %d", \
			index, conn, conns[conn].client, conn, conns[conn].server);
	} else if (err == CONNECT_IN_PROGRESS) {	/* may potentially succeed */
		conns[conn].state = CS_IN_PROGRESS;
		pending_list = dlist_insert(pending_list, conn);
		conns[conn].pend = pending_list;
		pending_queue++;
		event_add(upfd, EVENT_WRITE);
		DEBUG(2, "Pending connect to server %d\n" \
			"conns[%d].client = %d\n" \
			"conns[%d].server = %d", \
			index, conn, conns[conn].client, conn, conns[conn].server);
	} else {		/* failed definitely */
		if (servers[index].status == 0) {
			debug("Server %d failed, retry in %d sec: %d",
				index, blacklist_time, socket_errno);
		}
		debug("blacklisting server %d because connect error %d", index, err);
		blacklist_server(index);
		close(upfd);
		return 0;
	}
	conns[conn].server = index;
	DEBUG(2, "Setting server %d for client %d", index, client);
	clients[client].server = index;
	current = index;
	conns[conn].upfd = upfd;
	fd2conn_set(upfd, conn);
	return 1;
}

/* we want size server slots plus two for abuse and emergency */
void expand_servertable(int size)
{
	static server *server_storage = NULL;
	static int real_size = 0;
	int new_size = size+2;	/* for emergency and abuse servers */
	if (new_size <= real_size) return;	/* nothing to expand here */
	server_storage = pen_realloc(server_storage, new_size*sizeof *server_storage);
	memset(&server_storage[real_size], 0, (new_size-real_size)*sizeof server_storage[0]);
	servers = &server_storage[2];	/* making server[0] the first regular server */
	real_size = new_size;
	if (size > nservers) nservers = size;
}

