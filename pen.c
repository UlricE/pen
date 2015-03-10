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

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SRV_SSL_V23 0
#define SRV_SSL_V2 1
#define SRV_SSL_V3 2
#define SRV_SSL_TLS1 3

static char ssl_compat;
static char require_peer_cert;
static char ssl_protocol;
static char *certfile;
static char *keyfile;
static char *cacert_dir;
static char *cacert_file;
static SSL_CTX *ssl_context = NULL;
#endif  /* HAVE_LIBSSL */

#ifdef HAVE_LIBGEOIP
#include <GeoIP.h>
GeoIP *geoip4, *geoip6;
#endif

#include "pen.h"
#include "dlist.h"

#define ACE_IPV4 (1)
#define ACE_IPV6 (2)
#define ACE_GEO (3)

#define BUFFER_MAX 	(32*1024)

#define CLIENTS_MAX	2048	/* max clients */
#define SERVERS_MAX	16	/* max servers */
#define ACLS_MAX	10	/* max acls */
#define CONNECTIONS_MAX	256	/* max simultaneous connections */
#define TIMEOUT		3	/* default timeout for non reachable hosts */
#define BLACKLIST_TIME	30	/* how long to shun a server that is down */
#define TRACKING_TIME	0	/* how long a client is remembered */
#define KEEP_MAX	100	/* how much to keep from the URI */
#define WEIGHT_FACTOR	256	/* to make weight kick in earlier */

/* Connection states, as used in struct conn */
#define CS_UNUSED	(0)	/* not connected, unused slot */
#define CS_IN_PROGRESS	(1)	/* connection in progress */
#define CS_CONNECTED	(2)	/* successfully connected */
#define CS_CLOSED_UP	(4)	/* we read eof from upfd */
#define CS_CLOSED_DOWN	(8)	/* we read eof from downfd */
#define CS_CLOSED	(CS_CLOSED_UP | CS_CLOSED_DOWN)

typedef struct {
	int state;		/* as per above */
	time_t t;		/* time of connection attempt */
	int downfd, upfd;
	unsigned char *downb, *downbptr, *upb, *upbptr;
	int downn, upn;		/* pending bytes */
	unsigned long ssx, srx;	/* server total sent, received */
	unsigned long csx, crx;	/* client total sent, received */
	int client;		/* client index */
	int initial;		/* first server tried */
	int server;		/* server index */
	int pend;		/* node in pending_list */
#ifdef HAVE_LIBSSL
	SSL *ssl;
#endif
} connection;

typedef struct {
	int status;		/* last failed connection attempt */
	int acl;		/* which clients can use this server */
	struct sockaddr_storage addr;
	int c;			/* connections */
	int weight;		/* default 1 */
	int prio;
	int maxc;		/* max connections, soft limit */
	int hard;		/* max connections, hard limit */
	unsigned long long sx, rx;	/* bytes sent, received */
} server;

typedef struct {
	time_t last;		/* last time this client made a connection */
	struct sockaddr_storage addr;
	int server;		/* server used last time */
	long connects;
	long long csx, crx;
} client;

typedef struct {
	unsigned int ip, mask;
} ace_ipv4;

typedef struct {
	struct in6_addr ip;
	unsigned char len;
} ace_ipv6;

typedef struct {
	char country[2];
} ace_geo;

typedef struct {
	unsigned char class;
	unsigned char permit;
	union {
		ace_ipv4 ipv4;
		ace_ipv6 ipv6;
		ace_geo geo;
	} ace;
} acl;

void (*event_add)(int, int);
void (*event_arm)(int, int);
void (*event_delete)(int);
void (*event_wait)(void);
int (*event_fd)(int *);
#if defined HAVE_KQUEUE
void (*event_init)(void) = kqueue_init;
#elif defined HAVE_EPOLL
void (*event_init)(void) = epoll_init;
#elif defined HAVE_POLL
void (*event_init)(void) = poll_init;
#else
void (*event_init)(void) = select_init;
#endif

#define DUMMY_MSG "Ulric was here."

static int idle_timeout = 0;	/* never time out */
static int abort_on_error = 0;
static int dummy = 0;		/* use pen as a test target */
static int idlers = 0, idlers_wanted = 0;
static time_t now;
static int tcp_nodelay = 0;
static int tcp_fastclose = 0;
static int pending_list = -1;	/* pending connections */
static int listen_queue = 100;
static int multi_accept = 100;
static int nservers;		/* number of servers */
static int current;		/* current server */
static int nacls[ACLS_MAX];
static client *clients;
static server *servers;
static acl *acls[ACLS_MAX];
static int emerg_server = -1;	/* server of last resort */
static int emergency = 0;	/* are we using the emergency server? */
static int abuse_server = -1;	/* server for naughty clients */
static connection *conns;

int debuglevel;
static int asciidump;
static int foreground;
static int loopflag;
static int exit_enabled = 0;
static int keepalive = 0;

static int hupcounter = 0;
static int clients_max = CLIENTS_MAX;
static int servers_max = SERVERS_MAX;
int connections_max = CONNECTIONS_MAX;
static int connections_used = 0;
static int connections_last = 0;
int timeout = TIMEOUT;
static int blacklist_time = BLACKLIST_TIME;
static int tracking_time = TRACKING_TIME;
static int roundrobin = 0;
static int weight = 0;
static int prio = 0;
static int hash = 0;
static int stubborn = 0;

static int stats_flag = 0;
static int restart_log_flag = 0;
static int http = 0;
static int client_acl, control_acl;
static int udp = 0;
static int protoid = SOCK_STREAM;

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

static char *ctrlport = NULL;
static int listenfd, ctrlfd = -1;
static char *e_server = NULL;
static char *a_server = NULL;
static char *jail = NULL;
static char *user = NULL;
static char *proto = "tcp";

static int fd2conn_max = 0;
static int *fd2conn;

static unsigned char mask_ipv6[129][16];

static void close_conn(int);

#ifdef WINDOWS
#define SHUT_WR SD_SEND		/* for shutdown */

#define LOG_CONS	0
#define LOG_USER	0
#define LOG_ERR		0
#define LOG_DEBUG	0

#define CONNECT_IN_PROGRESS (WSAEWOULDBLOCK)
#define WOULD_BLOCK(err) (err == WSAEWOULDBLOCK)

static FILE *syslogfp;

static void openlog(const char *ident, int option, int facility)
{
	syslogfp = fopen("syslog.txt", "a");
}

static void syslog(int priority, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	if (syslogfp) {
		vfprintf(syslogfp, format, ap);
	}
	va_end(ap);
}

static void closelog(void)
{
	fclose(syslogfp);
}

#define SIGHUP	0
#define SIGUSR1	0
#define SIGPIPE	0
#define SIGCHLD	0

typedef int sigset_t;
typedef int siginfo_t;

struct sigaction {
	void     (*sa_handler)(int);
	void     (*sa_sigaction)(int, siginfo_t *, void *);
	sigset_t   sa_mask;
	int        sa_flags;
	void     (*sa_restorer)(void);
};

static int sigaction(int signum, const struct sigaction *act,
		struct sigaction *oldact)
{
	return 0;
}

static int sigemptyset(sigset_t *set)
{
	return 0;
}

typedef int rlim_t;

struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

#define RLIMIT_CORE 0

static int getrlimit(int resource, struct rlimit *rlim)
{
	return 0;
}

static int setrlimit(int resource, const struct rlimit *rlim)
{
	return 0;
}

typedef int uid_t;
typedef int gid_t;

static uid_t getuid(void)
{
	return 0;
}

struct passwd {
	uid_t pw_uid;
	gid_t pw_gid;
};

static struct passwd *getpwnam(const char *name)
{
	static struct passwd p;
	p.pw_uid = 0;
	p.pw_gid = 0;
	return &p;
}

static int chroot(const char *path)
{
	return 0;
}

static int setgid(gid_t gid)
{
	return 0;
}

static int setuid(uid_t uid)
{
	return 0;
}

int inet_aton(const char *cp, struct in_addr *addr)
{
	addr->s_addr = inet_addr(cp);
	return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}

static void make_nonblocking(int fd)
{
	int i;
	u_long mode = 1;
	if ((i = ioctlsocket(fd, FIONBIO, &mode)) != NO_ERROR)
		error("Can't ioctlsocket, error = %d", i);
}

static WSADATA wsaData;
static int ws_started = 0;

static int start_winsock(void)
{
	int n;
	DEBUG(1, "start_winsock()");
	if (!ws_started) {
		n = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (n != NO_ERROR) {
			error("Error at WSAStartup() [%d]", WSAGetLastError());
		} else {
			DEBUG(2, "Winsock started");
			ws_started = 1;
		}
	}
	return ws_started;
}

void stop_winsock(void)
{
	WSACleanup();
	ws_started = 0;
}

/* because Windows scribbles over errno in an uncalled-for manner */
static int saved_errno;
#define SAVE_ERRNO (saved_errno = socket_errno)
#define USE_ERRNO (saved_errno)

#else	/* not windows */
#define CONNECT_IN_PROGRESS (EINPROGRESS)
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
	int n = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	DEBUG(2, "setsockopt(%d, %d, %d, %p, %d) returns %d",
		s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one, n);
#else
	debug("You don't have TCP_NODELAY");
#endif
}

/* save a few syscalls for modern Linux and BSD */
static int socket_nb(int domain, int type, int protocol)
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

static struct sigaction alrmaction, hupaction, termaction, usr1action, usr2action;

void debug(char *fmt, ...)
{
	time_t now;
	struct tm *nowtm;
	char nowstr[80];
	char b[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	now=time(NULL);
	nowtm = localtime(&now);
	strftime(nowstr, sizeof(nowstr), "%Y-%m-%d %H:%M:%S", nowtm);
	if (foreground) {
		fprintf(stderr, "%s: %s\n", nowstr, b);
	} else {
		openlog("pen", LOG_CONS, LOG_USER);
		syslog(LOG_DEBUG, "%s\n", b);
		closelog();
	}
	va_end(ap);
}

void error(char *fmt, ...)
{
	char b[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	fprintf(stderr, "%s\n", b);
	if (!foreground) {
		openlog("pen", LOG_CONS, LOG_USER);
		syslog(LOG_ERR, "%s\n", b);
		closelog();
	}
	va_end(ap);
	if (abort_on_error) abort();
	else exit(EXIT_FAILURE);
}

void *pen_malloc(size_t n)
{
	void *q = malloc(n);
	if (!q) error("Can't malloc %ld bytes", (long)n);
	return q;
}

static void *pen_calloc(size_t n, size_t s)
{
	void *q = calloc(n, s);
	if (!q) error("Can't calloc %ld bytes", (long)n*s);
	return q;
}

void *pen_realloc(void *p, size_t n)
{
	void *q = realloc(p, n);
	if (!q) error("Can't realloc %ld bytes", (long)n);
	return q;
}

static char *pen_strdup(char *p)
{
	size_t len = strlen(p);
	char *b = pen_malloc(len+1);
	memcpy(b, p, len);
	b[len] = '\0';
	return b;
}

static int pen_strncasecmp(const char *p, const char *q, size_t n)
{
	size_t i = 0;
	int c = 0;

	while ((i < n) && !(c = toupper(*p)-toupper(*q)) && *p) {
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

/* store_conn does fd2conn_set(fd, conn) */
/* close_conn does fd2conn_set(fd, -1) */
static void fd2conn_set(int fd, int conn)
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

static int fd2conn_get(int fd)
{
	if (fd < 0 || fd >= fd2conn_max) return -1;
	return fd2conn[fd];
}

static void init_mask(void)
{
	unsigned char m6[16];
	int i, j;

	memset(m6, 0, sizeof m6);
	for (i = 0; i < 129; i++) {
		for (j = 15; j >= 0; j--) {
			mask_ipv6[i][j] = m6[j];
			m6[j] >>= 1;
			if (j > 0) {
				m6[j] |= (m6[j-1] << 7);
			} else {
				m6[j] |= (1 << 7);
			}
		}
	}
}

static int pen_hash(struct sockaddr_storage *a)
{
	struct sockaddr_in *si;
	struct sockaddr_in6 *si6;
	unsigned char *u;

	switch (a->ss_family) {
	case AF_INET:
		si = (struct sockaddr_in *)a;
		return si->sin_addr.s_addr % nservers;
	case AF_INET6:
		si6 = (struct sockaddr_in6 *)a;
		u = (unsigned char *)(&si6->sin6_addr);
		return u[15] % nservers;
	default:
		return 0;
	}
}

/* Takes a struct sockaddr_storage and returns the port number in host order.
   For a Unix socket, the port number is 1.
*/
static int pen_getport(struct sockaddr_storage *a)
{
	struct sockaddr_in *si;
	struct sockaddr_in6 *si6;

	switch (a->ss_family) {
	case AF_UNIX:
		return 1;
	case AF_INET:
		si = (struct sockaddr_in *)a;
		return ntohs(si->sin_port);
	case AF_INET6:
		si6 = (struct sockaddr_in6 *)a;
		return ntohs(si6->sin6_port);
	default:
		debug("pen_getport: Unknown address family %d", a->ss_family);
	}
	return 0;
}

static int pen_setport(struct sockaddr_storage *a, int port)
{
	struct sockaddr_in *si;
	struct sockaddr_in6 *si6;

	switch (a->ss_family) {
	case AF_UNIX:
		/* No port for Unix domain sockets */
		return 1;
	case AF_INET:
		si = (struct sockaddr_in *)a;
		si->sin_port = htons(port);
		return 1;
	case AF_INET6:
		si6 = (struct sockaddr_in6 *)a;
		si6->sin6_port = htons(port);
		return 1;
	default:
		debug("pen_setport: Unknown address family %d", a->ss_family);
	}
	return 0;
}

/* Takes a struct sockaddr_storage and returns the name in a static buffer.
   The address can be a unix socket path or an ipv4 or ipv6 address.
*/
static char *pen_ntoa(struct sockaddr_storage *a)
{
	static char b[1024];
	struct sockaddr_in *si;
	struct sockaddr_in6 *si6;
#ifndef WINDOWS
	struct sockaddr_un *su;
#endif

	switch (a->ss_family) {
	case AF_INET:
		si = (struct sockaddr_in *)a;
		snprintf(b, sizeof b, "%s", inet_ntoa(si->sin_addr));
		break;
	case AF_INET6:
		si6 = (struct sockaddr_in6 *)a;
		if (inet_ntop(AF_INET6, &si6->sin6_addr, b, sizeof b) == NULL) {
			debug("pen_ntoa: can't convert address");
			strncpy(b, "(cannot convert address)", sizeof b);
		}
		break;
#ifndef WINDOWS
	case AF_UNIX:
		su = (struct sockaddr_un *)a;
		snprintf(b, sizeof b, "%s", su->sun_path);
		break;
#endif
	default:
		debug("pen_ntoa: unknown address family %d", a->ss_family);
		snprintf(b, sizeof b, "(unknown address family %d", a->ss_family);
	}
	return b;
}

static void pen_dumpaddr(struct sockaddr_storage *a)
{
	switch (a->ss_family) {
	case AF_INET:
		debug("Family: AF_INET");
		debug("Port: %d", pen_getport(a));
		debug("Address: %s", pen_ntoa(a));
		break;
	case AF_INET6:
		debug("Family: AF_INET6");
		debug("Port: %d", pen_getport(a));
		debug("Address: %s", pen_ntoa(a));
		break;
#ifndef WINDOWS
	case AF_UNIX:
		debug("Family: AF_UNIX");
		debug("Path: %s", pen_ntoa(a));
		break;
#endif
	default:
		debug("pen_dumpaddr: Unknown address family %d", a->ss_family);
	}
}

static int pen_ss_size(struct sockaddr_storage *ss)
{
	switch (ss->ss_family) {
#ifndef WINDOWS
	case AF_UNIX:
		return sizeof(struct sockaddr_un);
#endif
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		debug("pen_ss_size: unknown address family %d", ss->ss_family);
		return sizeof(struct sockaddr_storage);
	}
}

/* Takes a name and fills in a struct sockaddr_storage. The port is left alone.
   The address can be a unix socket path, a host name, an ipv4 address or an ipv6 address.
   Returns 0 for failure and 1 for success.
*/
static int pen_aton(char *name, struct sockaddr_storage *addr)
{
	struct sockaddr_in *si;
	struct sockaddr_in6 *si6;
#ifndef WINDOWS
	struct sockaddr_un *su;
#endif
	struct addrinfo *ai;
	struct addrinfo hints;
	int n, result;

	DEBUG(2, "pen_aton(%s, %p)", name, addr);
#ifndef WINDOWS
	/* Deal with Unix domain sockets first */
	if (strchr(name, '/')) {
		addr->ss_family = AF_UNIX;
		su = (struct sockaddr_un *)addr;
		snprintf(su->sun_path, sizeof su->sun_path, "%s", name);
		return 1;
	}
#endif
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;
	n = getaddrinfo(name, NULL, &hints, &ai);
	if (n != 0) {
		debug("getaddrinfo: %s", gai_strerror(n));
		return 0;
	}
	DEBUG(2, "family = %d\nsocktype = %d\nprotocol = %d\n" \
		"addrlen = %d\nsockaddr = %d\ncanonname = %s", \
		ai->ai_family, ai->ai_socktype, ai->ai_protocol, \
		(int)ai->ai_addrlen, ai->ai_addr, ai->ai_canonname);
	addr->ss_family = ai->ai_family;
	switch (ai->ai_family) {
	case AF_INET:
		si = (struct sockaddr_in *)addr;
		/* ai->ai_addr is a struct sockaddr * */
		/* (struct sockaddr_in *)ai->ai_addr is a struct sockaddr_in * */
		/* ((struct sockaddr_in *)ai->ai_addr)->sin_addr is a struct in_addr */
		si->sin_addr = ((struct sockaddr_in *)ai->ai_addr)->sin_addr;
		result = 1;
		break;
	case AF_INET6:
		si6 = (struct sockaddr_in6 *)addr;
		/* ai->ai_addr is a struct sockaddr * */
		/* (struct sockaddr_in6 *)ai->ai_addr is a struct sockaddr_in6 * */
		/* ((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr is a struct in6_addr */
		si6->sin6_addr = ((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
		result = 1;
		break;
	default:
		debug("Unknown family %d", ai->ai_family);
		result = 0;
		break;
	}
	freeaddrinfo(ai);
	return result;
}

#ifdef HAVE_LIBSSL
static int ssl_verify_cb(int ok, X509_STORE_CTX *ctx)
{
	char buffer[256];

	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),
			buffer, sizeof(buffer));
	if (ok) {
		debug("SSL: Certificate OK: %s", buffer);
	} else {
		switch (ctx->error) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
			debug("SSL: Cert error: CA not known: %s", buffer);
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
			debug("SSL: Cert error: Cert not yet valid: %s",
				buffer);
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			debug("SSL: Cert error: illegal \'not before\' field: %s",
				buffer);
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
			debug("SSL: Cert error: Cert expired: %s", buffer);
			break;
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			debug("SSL: Cert error: invalid \'not after\' field: %s",
				buffer);
			break;
		default:
			debug("SSL: Cert error: unknown error %d in %s",
				ctx->error, buffer);
			break;
		}
	}
	return ok;
}

static RSA *ssl_temp_rsa_cb(SSL *ssl, int export, int keylength)
{
	static RSA *rsa = NULL;

	if (rsa == NULL)
		rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
	return rsa;
}

static int ssl_init(void)
{
	int err;

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	switch (ssl_protocol) {
#if 0
	case SRV_SSL_V2:
		ssl_context = SSL_CTX_new(SSLv2_method());
		break;
#endif
	case SRV_SSL_V3:
		ssl_context = SSL_CTX_new(SSLv3_method());
		break;
	default:
	case SRV_SSL_V23:
		ssl_context = SSL_CTX_new(SSLv23_method());
		break;
	case SRV_SSL_TLS1:
		ssl_context = SSL_CTX_new(TLSv1_method());
		break;
	}
	if (ssl_context == NULL) {
		err = ERR_get_error();
		error("SSL: Error allocating context: %s",
			ERR_error_string(err, NULL));
	}
	if (ssl_compat) {
		SSL_CTX_set_options(ssl_context, SSL_OP_ALL);
	}
	if (certfile == NULL || *certfile == 0) {
		debug("SSL: No cert file specified in config file!");
		error("The server MUST have a certificate!");
	}
	if (keyfile == NULL || *keyfile == 0)
		keyfile = certfile;
	if (certfile != NULL && *certfile != 0) {
		if (!SSL_CTX_use_certificate_file(ssl_context, certfile,
						SSL_FILETYPE_PEM)) {
			err = ERR_get_error();
			error("SSL: error reading certificate from file %s: %s",
				certfile, ERR_error_string(err, NULL));
		}
		if (!SSL_CTX_use_PrivateKey_file(ssl_context, keyfile,
						SSL_FILETYPE_PEM)) {
			err = ERR_get_error();
			error("SSL: error reading private key from file %s: %s",
				keyfile, ERR_error_string(err, NULL));
		}
		if (!SSL_CTX_check_private_key(ssl_context)) {
			error("SSL: Private key does not match public key in cert!");
		}
	}
	if (cacert_dir != NULL && *cacert_dir == 0)
		cacert_dir = NULL;
	if (cacert_file != NULL && *cacert_file == 0)
		cacert_file = NULL;
	if (cacert_dir != NULL || cacert_file != NULL) {
		if (!SSL_CTX_load_verify_locations(ssl_context,
					cacert_file, cacert_dir)) {
			err = ERR_get_error();
			debug("SSL: Error error setting CA cert locations: %s",
				ERR_error_string(err, NULL));
			cacert_file = cacert_dir = NULL;
		}
	}
	if (cacert_dir == NULL && cacert_file == NULL) {  /* no verify locations loaded */
		debug("SSL: No verify locations, trying default");
		if (!SSL_CTX_set_default_verify_paths(ssl_context)) {
			err = ERR_get_error();
			debug("SSL: Error error setting default CA cert location: %s",
				ERR_error_string(err, NULL));
			debug("continuing anyway...");
		}
	}
	SSL_CTX_set_tmp_rsa_callback(ssl_context, ssl_temp_rsa_cb);
	if (require_peer_cert) {
		SSL_CTX_set_verify(ssl_context,
			SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			ssl_verify_cb);
	} else {
		SSL_CTX_set_verify(ssl_context,
			SSL_VERIFY_NONE,
			ssl_verify_cb);
	}

	SSL_CTX_set_client_CA_list(ssl_context,
			SSL_load_client_CA_file(certfile));

	/* permit large writes to be split up in several records */
	SSL_CTX_set_mode(ssl_context, SSL_MODE_ENABLE_PARTIAL_WRITE);

#if 1	/* testing */
	debug("SSL_CTX_get_session_cache_mode() returns %d",
		SSL_CTX_get_session_cache_mode(ssl_context));
	SSL_CTX_set_session_cache_mode(ssl_context, 0);
#endif

	return 0;
}

#endif  /* HAVE_LIBSSL */

/* allocate ace and fill in the generics */
static int add_acl(int a, unsigned char permit)
{
	int i;
	if (a < 0 || a >= ACLS_MAX) {
		debug("add_acl: %d outside (0,%d)", a, ACLS_MAX);
		return -1;
	}
	i = nacls[a]++;
	acls[a] = pen_realloc(acls[a], nacls[a]*sizeof(acl));
	acls[a][i].permit = permit;
	return i;
}

static void add_acl_ipv4(int a, unsigned int ip, unsigned int mask, unsigned char permit)
{
	int i = add_acl(a, permit);

	if (i == -1) return;

	DEBUG(2, "add_acl_ipv4(%d, %x, %x, %d)", a, ip, mask, permit);
	acls[a][i].class = ACE_IPV4;
	acls[a][i].ace.ipv4.ip = ip;
	acls[a][i].ace.ipv4.mask = mask;
}

static void add_acl_ipv6(int a, unsigned char *ipaddr, unsigned char len, unsigned char permit)
{
	int i = add_acl(a, permit);

	if (i == -1) return;

	DEBUG(2, "add_acl_ipv6(%d, %x, %d, %d)\n" \
		"%x:%x:%x:%x:%x:%x:%x:%x/%d", \
		a, ipaddr, len, permit, \
		256*ipaddr[0]+ipaddr[1], 256*ipaddr[2]+ipaddr[3], 256*ipaddr[4]+ipaddr[5], 256*ipaddr[6]+ipaddr[7], \
		256*ipaddr[8]+ipaddr[9], 256*ipaddr[10]+ipaddr[11], 256*ipaddr[12]+ipaddr[13], 256*ipaddr[14]+ipaddr[15],  len);
	acls[a][i].class = ACE_IPV6;
	memcpy(acls[a][i].ace.ipv6.ip.s6_addr, ipaddr, 16);
	acls[a][i].ace.ipv6.len = len;
}

static void add_acl_geo(int a, char *country, unsigned char permit)
{
	int i = add_acl(a, permit);

	if (i == -1) return;

	DEBUG(2, "add_acl_geo(%d, %s, %d", a, country, permit);
	acls[a][i].class = ACE_GEO;
	strncpy(acls[a][i].ace.geo.country, country, 2);
}

static void del_acl(int a)
{
	DEBUG(2, "del_acl(%d)", a);
	if (a < 0 || a >= ACLS_MAX) {
		debug("del_acl: %d outside (0,%d)", a, ACLS_MAX);
		return;
	}
	free(acls[a]);
	acls[a] = NULL;
	nacls[a] = 0;
}

#ifndef WINDOWS
static int match_acl_unix(int a, struct sockaddr_un *cli_addr)
{
	DEBUG(2, "Unix acl:s not implemented");
	return 1;
}
#endif

static int match_acl_ipv4(int a, struct sockaddr_in *cli_addr)
{
	unsigned int client = cli_addr->sin_addr.s_addr;
	int i;
	int permit = 0;
	acl *ap = acls[a];
#ifdef HAVE_LIBGEOIP
	const char *country = NULL;
	int geo_done = 0;
#endif
	DEBUG(2, "match_acl_ipv4(%d, %u)", a, client);
	for (i = 0; i < nacls[a]; i++) {
		permit = ap[i].permit;
		switch (ap[i].class) {
		case ACE_IPV4:
			if ((client & ap[i].ace.ipv4.mask) == ap[i].ace.ipv4.ip) {
				return permit;
			}
			break;
		case ACE_GEO:
#ifdef HAVE_LIBGEOIP
			if (geoip4 == NULL) break;
			if (!geo_done) {
				country = GeoIP_country_code_by_addr(geoip4,
						pen_ntoa((struct sockaddr_storage *)cli_addr));
				DEBUG(2, "Country = %s", country?country:"unknown");
				geo_done = 1;
			}
			if (country && !strncmp(country,
						ap[i].ace.geo.country, 2)) {
				return permit;
			}
#else
			debug("ACE_GEO: Not implemented");
#endif
			break;
		default:
			/* ignore other ACE classes (ipv6 et al) */
			break;
		}
	}
	return !permit;
}

/* The most straightforward way to get at the bytes of an ipv6 address
   is to take the pointer to the in6_addr and cast it to a pointer to
   unsigned char.
*/
static int match_acl_ipv6(int a, struct sockaddr_in6 *cli_addr)
{
	unsigned char *client = (unsigned char *)&(cli_addr->sin6_addr);
	unsigned char *ip;
	unsigned char *mask;
	int len;
	int i, j;
	int permit = 0;
	acl *ap = acls[a];
#ifdef HAVE_LIBGEOIP
	const char *country = NULL;
	int geo_done = 0;
#endif

	DEBUG(2, "match_acl_ipv6(%d, %u)", a, client);
	for (i = 0; i < nacls[a]; i++) {
		permit = ap[i].permit;
		switch (ap[i].class) {
		case ACE_IPV6:
			len = ap[i].ace.ipv6.len;
			ip = (unsigned char *)&(ap[i].ace.ipv6.ip);
			mask = mask_ipv6[len];

			DEBUG(2, "Matching %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x against %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x / %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", \
				client[0], client[1], client[2], client[3], \
				client[4], client[5], client[6], client[7], \
				client[8], client[9], client[10], client[11], \
				client[12], client[13], client[14], client[15], \
				ip[0], ip[1], ip[2], ip[3], \
				ip[4], ip[5], ip[6], ip[7], \
				ip[8], ip[9], ip[10], ip[11], \
				ip[12], ip[13], ip[14], ip[15], \
				mask[0], mask[1], mask[2], mask[3], \
				mask[4], mask[5], mask[6], mask[7], \
				mask[8], mask[9], mask[10], mask[11], \
				mask[12], mask[13], mask[14], mask[15]);

			for (j = 0; j < 16; j++) {
				if ((client[j] & mask[j]) != ip[j]) break;
			}
			if (j == 16) return permit;
			break;
		case ACE_GEO:
#ifdef HAVE_LIBGEOIP
			if (geoip6 == NULL) break;
			if (!geo_done) {
				country = GeoIP_country_code_by_addr_v6(geoip6,
						pen_ntoa((struct sockaddr_storage *)cli_addr));
				DEBUG(2, "Country = %s", country?country:"unknown");
				geo_done = 1;
			}
			if (country && !strncmp(country,
						ap[i].ace.geo.country, 2)) {
				return permit;
			}
#else
			debug("ACE_GEO: Not implemented");
#endif
			break;
		default:
			/* ignore other ACE classes (ipv4 et al) */
			break;
		}
	}
	return !permit;
}

static int match_acl(int a, struct sockaddr_storage *cli_addr)
{
	switch (cli_addr->ss_family) {
#ifndef WINDOWS
	case AF_UNIX:
		return match_acl_unix(a, (struct sockaddr_un *)cli_addr);
#endif
	case AF_INET:
		return match_acl_ipv4(a, (struct sockaddr_in *)cli_addr);
	case AF_INET6:
		return match_acl_ipv6(a, (struct sockaddr_in6 *)cli_addr);
	default:
		debug("match_acl: unknown address family %d", cli_addr->ss_family);
	}
	return 0;
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
			"<td>%llu</td>\n"
			"<td>%llu</td>\n"
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
			"<td>%lld</td>\n"
			"<td>%lld</td>\n"
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

static void quit(int dummy)
{
	DEBUG(1, "Quitting\nRead configuration %d times", hupcounter);
	loopflag = 0;
}

static void die(int dummy)
{
	abort();
}

/* Store client and return index */
static int store_client(struct sockaddr_storage *cli)
{
	int i;
	int empty = -1;		/* first empty slot */
	int oldest = -1;	/* in case we need to recycle */
	struct sockaddr_in *si;
	struct sockaddr_in6 *si6;
	int family = cli->ss_family;
	unsigned long ad = 0;
	void *ad6 = 0;

	if (family == AF_INET) {
		si = (struct sockaddr_in *)cli;
		ad = si->sin_addr.s_addr;
	} else if (family == AF_INET6) {
		si6 = (struct sockaddr_in6 *)cli;
		ad6 = &si6->sin6_addr;
	}

	for (i = 0; i < clients_max; i++) {
		/* look for client with same family and address */
		if (family == clients[i].addr.ss_family) {
			if (family == AF_UNIX) break;
			if (family == AF_INET) {
				si = (struct sockaddr_in *)&clients[i].addr;
				if (ad == si->sin_addr.s_addr) break;
			}
			if (family == AF_INET6) {
				si6 = (struct sockaddr_in6 *)&clients[i].addr;
				if (!memcmp(ad6, &si6->sin6_addr, sizeof *ad6)) break;
			}
		}

		/* recycle slots of client that haven't been used for some time */
		if (tracking_time > 0 && clients[i].last+tracking_time < now) {
			/* too old, recycle */
			clients[i].last = 0;
		}

		/* we already have an empty slot but keep looking for known client */
		if (empty != -1) continue;

		/* remember this empty slot in case we need it later */
		if (clients[i].last == 0) {
			empty = i;
			continue;
		}

		/* and if we can't find any reusable slot we'll reuse the oldest one */
		if (oldest == -1 || (clients[i].last < clients[oldest].last)) {
			oldest = i;
		}
	}

	/* reset statistics in case this is a "new" client */
	if (i == clients_max) {
		if (empty != -1) i = empty;
		else i = oldest;
		clients[i].connects = 0;
		clients[i].csx = 0;
		clients[i].crx = 0;
	}

	clients[i].last = now;
	clients[i].addr = *cli;
	clients[i].server = -1;
	clients[i].connects++;

	DEBUG(2, "Client %s has index %d", pen_ntoa(cli), i);

	return i;
}

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

/* return port number in host byte order */
static int getport(char *p, char *proto)
{
	struct servent *s = getservbyname(p, proto);
	if (s == NULL) {
		return atoi(p);
	} else {
		return ntohs(s->s_port);
	}
}

/* Introduce the new format "[address]:port:maxc:hard:weight:prio"
   in addition to the old one.
*/
static void setaddress(int server, char *s, int dp, char *proto)
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

	DEBUG(2, "n = %d, address = %s, pno = %d, maxc1 = %d, hard = %d, weight = %d, prio = %d, proto = %s ", \
		n, address, port, servers[server].maxc, \
		servers[server].hard, servers[server].weight, \
		servers[server].prio, proto);

	if (pen_aton(address, &servers[server].addr) == 0) {
		error("unknown or invalid address [%s]", address);
	}
	pen_setport(&servers[server].addr, port);
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
#if 0	/* how is that supposed to happen? */
	if (q >= b+n) return n;		/* outside of buffer */
#endif
	/* Look for existing X-Forwarded-For */
	DEBUG(2, "Looking for X-Forwarded-For");

	if (pen_strcasestr(b, "\nX-Forwarded-For:")) return n;

	DEBUG(2, "Adding X-Forwarded-For");
	/* Didn't find one, add our own */
	snprintf(p, sizeof p, "\r\nX-Forwarded-For: %s",
		pen_ntoa(&clients[conns[i].client].addr));
	pl=strlen(p);
	if (n+pl > BUFFER_MAX) return n;

	memmove(q+pl, q, b+n-q);
	memmove(q, p, pl);

	n += pl;
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

static int closing_time(int conn)
{
	int closed = conns[conn].state & CS_CLOSED;

	if (closed == CS_CLOSED) return 1;
	if (conns[conn].downn + conns[conn].upn == 0) {
		return closed & tcp_fastclose;
	}
	return 0;
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
			struct sockaddr_storage *ss = &clients[conns[i].client].addr;
			socklen_t sss = pen_ss_size(ss);
			DEBUG(2, "copy_down sending %d bytes to socket %d", rc, to);
			n = sendto(to, b, rc, 0, (struct sockaddr *)ss, sss);
			close_conn(i);
			return 0;
		}

#ifdef HAVE_LIBSSL
		if (ssl) {
			/* can't write more than 32000 bytes at a time */
			int ssl_rc;
			if (rc > 32000) ssl_rc = 32000;
			else ssl_rc = rc;
			n = SSL_write(ssl, b, ssl_rc);
			DEBUG(2, "SSL_write returns %d", n);
			if (n < 0) {
				err = SSL_get_error(ssl, n);
				if (debuglevel) debug("SSL error %d\n", err);
				if (err == SSL_ERROR_WANT_READ ||
				    err == SSL_ERROR_WANT_WRITE) {
					return 0;
				}
			}
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

static void alarm_handler(int dummy)
{
	DEBUG(2, "alarm_handler(%d)", dummy);
}

#ifdef HAVE_LIBSSL
static int store_conn(int downfd, SSL *ssl, int client)
#else
static int store_conn(int downfd, int client)
#endif
{
	int i;

	i = connections_last;
	do {
		if (conns[i].state == CS_UNUSED) break;
		i++;
		if (i >= connections_max) i = 0;
	} while (i != connections_last);

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
		conns[i].initial = -1;
		conns[i].server = -1;
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

static int idler(int conn)
{
	return (conns[conn].state & CS_CONNECTED) && (conns[conn].client == -1);
}

static void close_conn(int i)
{
	int index = conns[i].server;

	/* unfinished connections have server == -1 */
	if (index != -1) {
		servers[index].c -= 1;
		if (servers[index].c < 0) servers[index].c = 0;
	}

	if (conns[i].upfd != -1 && conns[i].upfd != listenfd) {
		event_delete(conns[i].upfd);
		close(conns[i].upfd);
		fd2conn_set(conns[i].upfd, -1);
	}
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
#ifdef HAVE_LIBSSL
	if (conns[i].ssl) {
		SSL_free(conns[i].ssl);
		conns[i].ssl = 0;
	}
#endif
	connections_used--;
	DEBUG(2, "decrementing connections_used to %d for connection %d",
		connections_used, i);
	if (connections_used < 0) {
		debug("connections_used = %d. Resetting.", connections_used);
		connections_used = 0;
	}
	if (conns[i].state == CS_IN_PROGRESS) {
		pending_list = dlist_remove(conns[i].pend);
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


static void usage(void)
{
	printf("usage:\n"
	       "  pen [-C addr:port] [-X] [-b sec] [-S N] [-c N] [-e host[:port]] \\\n"
	       "	  [-t sec] [-x N] [-w dir] [-HPWadfhrs] \\\n"
	       "          [-o option] \\\n"
	       "	  [-E certfile] [-K keyfile] \\\n"
	       "	  [-G cacertfile] [-A cacertdir] \\\n"
	       "	  [-Z] [-R] [-L protocol] \\\n"
	       "	  [host:]port h1[:p1[:maxc1[:hard1[:weight1[:prio1]]]]] [h2[:p2[:maxc2[:hard2[:weight2[:prio2]]]]]] ...\n"
	       "\n"
	       "  -B host:port abuse server for naughty clients\n"
	       "  -C port   control port\n"
	       "  -T sec    tracking time in seconds (0 = forever) [%d]\n"
	       "  -H	add X-Forwarded-For header in http requests\n"
	       "  -U	use udp protocol support\n"
	       "  -O    use epoll to manage events (Linux)\n"
	       "  -P	use poll() rather than select()\n"
	       "  -Q    use kqueue to manage events (BSD)\n"
	       "  -W    use weight for server selection\n"
	       "  -X	enable 'exit' command for control port\n"
	       "  -a	debugging dumps in ascii format\n"
	       "  -b sec    blacklist time in seconds [%d]\n"
	       "  -S N      max number of servers [%d]\n"
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
	       "  -E certfile   use the given certificate in PEM format\n"
	       "  -K keyfile    use the given key in PEM format (may be contained in cert)\n"
	       "  -G cacertfile file containing the CA's certificate\n"
	       "  -A cacertdir  directory containing CA certificates in hashed format\n"
	       "  -Z	    use SSL compatibility mode\n"
	       "  -R	    require valid peer certificate\n"
	       "  -L protocol   ssl23 (default), ssl2, ssl3 or tls1\n"
	       "\n"
	       "example:\n"
	       "  pen smtp mailhost1:smtp mailhost2:25 mailhost3\n"
	       "\n",
	       TRACKING_TIME, BLACKLIST_TIME, SERVERS_MAX, CLIENTS_MAX, TIMEOUT, CONNECTIONS_MAX);

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

	conns = pen_calloc(connections_max, sizeof *conns);
	clients = pen_calloc(clients_max, sizeof *clients);
	/* one extra server slot for the emergency server */
	/* and one for the abuse server */
	/* Check that servers_max is big enough for the command line */
	if ((argc-1) > servers_max) {
		debug("command line specifies %d servers, max is %d; attempting to compensate",
			argc-1, servers_max);
		servers_max = argc-1;
	}
	servers = pen_calloc(servers_max+2, sizeof *servers);

	nservers = 0;
	current = 0;

	server = 0;

	for (i = 1; i < argc; i++) {
		servers[server].status = 0;
		servers[server].c = 0;	/* connections... */
		setaddress(server, argv[i], port, proto);
		servers[server].sx = 0;
		servers[server].rx = 0;

		nservers++;
		server++;
	}
	while (nservers < servers_max) {
		servers[server].status = 0;
		servers[server].c = 0;	/* connections... */
		setaddress(server, "0.0.0.0", 0, proto);
		servers[server].sx = 0;
		servers[server].rx = 0;

		nservers++;
		server++;
	}
	if (e_server) {
		emerg_server = server;
		servers[server].status = 0;
		servers[server].c = 0;	/* connections... */
		setaddress(server, e_server, port, proto);
		servers[server].sx = 0;
		servers[server].rx = 0;
		server++;
	}

	if (a_server) {
		abuse_server = server;
		servers[server].status = 0;
		servers[server].c = 0;	/* connections... */
		setaddress(server, a_server, port, proto);
		servers[server].sx = 0;
		servers[server].rx = 0;
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
	for (i = 0; i < connections_max; i++) {
		conns[i].upfd = -1;
		conns[i].downfd = -1;
		conns[i].upn = 0;
		conns[i].downn = 0;
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

static void blacklist_server(int server)
{
	servers[server].status = now;
}

/* Initiate connection to server 'index' and populate upfd field in connection */
/* return 1 for (potential) success, 0 for failure */
static int try_server(int index, int conn)
{
	int upfd;
	int client = conns[conn].client;
	int n = 0, err;
	int optval = 1;
	struct sockaddr_storage *addr = &servers[index].addr;
	/* The idea is that a client should be able to connect again to the same server
	   even if the server is close to its configured connection limit */
	int sticky = ((client != -1) && (index == clients[client].server));

	DEBUG(2, "Trying server %d for connection %d at time %d", index, conn, now);
	if (index < 0) return 0;	/* out of bounds */
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
	upfd = socket_nb(addr->ss_family, protoid, 0);

	if (keepalive) {
		setsockopt(upfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof optval);
	}

	if (debuglevel > 1) {
		debug("Connecting to %s", pen_ntoa(addr));
		pen_dumpaddr(addr);
	}
	conns[conn].t = now;
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
		if (!udp) event_add(conns[conn].downfd, EVENT_READ);
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
		blacklist_server(index);
		close(upfd);
		return 0;
	}
	conns[conn].server = index;
	current = index;
	conns[conn].upfd = upfd;
	fd2conn_set(upfd, conn);
	return 1;
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

static int open_listener(char *a)
{
	int listenfd;
	struct sockaddr_storage ss;

	char b[1024], *p;
	int one = 1;
	int optval = 1;
#if 0
	int port;
#endif

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

	listenfd = socket_nb(ss.ss_family, protoid, 0);
	DEBUG(2, "local address=[%s:%d]", b, port);

	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof one);
	setsockopt(listenfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof optval);

	if (bind(listenfd, (struct sockaddr *)&ss, pen_ss_size(&ss)) < 0) {
		error("can't bind local address");
	}

	listen(listenfd, listen_queue);
	return listenfd;
}

static void read_cfg(char *);

static void write_cfg(char *p)
{
	int i, j;
	struct in_addr ip;
	char ip_str[INET6_ADDRSTRLEN];
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
	if (servers_max != SERVERS_MAX)
		fprintf(fp, " -S %d", servers_max);
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
	for (i = 0; i < ACLS_MAX; i++) {
		fprintf(fp, "no acl %d\n", i);
		for (j = 0; j < nacls[i]; j++) {
			fprintf(fp, "acl %d %s ", i,
				acls[i][j].permit?"permit":"deny");
			switch (acls[i][j].class) {
			case ACE_IPV4:
				memcpy(&ip, &acls[i][j].ace.ipv4.ip, 4);
				fprintf(fp, "%s ", inet_ntoa(ip));
				memcpy(&ip, &acls[i][j].ace.ipv4.mask, 4);
				fprintf(fp, "%s\n", inet_ntoa(ip));
				break;
			case ACE_IPV6:
				fprintf(fp, "%s/%d\n",
					inet_ntop(AF_INET6,
						&acls[i][j].ace.ipv6.ip,
						ip_str, sizeof ip_str),
					acls[i][j].ace.ipv6.len);
				break;
			case ACE_GEO:
				fprintf(fp, "country %c%c\n",
					acls[i][j].ace.geo.country[0],
					acls[i][j].ace.geo.country[1]);
				break;
			default:
				debug("Unknown ACE class %d (this is probably a bug)",
					acls[i][j].class);
			}
		}
	}
	if (asciidump) fprintf(fp, "ascii\n");
	else fprintf(fp, "no ascii\n");
	fprintf(fp, "blacklist %d\n", blacklist_time);
	fprintf(fp, "client_acl %d\n", client_acl);
	fprintf(fp, "control_acl %d\n", control_acl);
	fprintf(fp, "debug %d\n", debuglevel);
	if (hash) fprintf(fp, "hash\n");
	else fprintf(fp, "no hash\n");
	if (http) fprintf(fp, "http\n");
	else fprintf(fp, "no http\n");
	if (logfile) fprintf(fp, "log %s\n", logfile);
	else fprintf(fp, "no log\n");
	if (roundrobin) fprintf(fp, "roundrobin\n");
	else fprintf(fp, "no roundrobin\n");
	for (i = 0; i < nservers; i++) {
		fprintf(fp,
			"server %d acl %d address %s port %d max %d hard %d",
			i, servers[i].acl,
			pen_ntoa(&servers[i].addr), pen_getport(&servers[i].addr),
			servers[i].maxc, servers[i].hard);
		if (weight) fprintf(fp, " weight %d", servers[i].weight);
		if (prio) fprintf(fp, " prio %d", servers[i].prio);
		fprintf(fp, "\n");
	}
	if (stubborn) fprintf(fp, "stubborn\n");
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
	if (weight) fprintf(fp, "weight\n");
	else fprintf(fp, "no weight\n");
	if (prio) fprintf(fp, "prio\n");
	else fprintf(fp, "no prio\n");
	fclose(fp);
}

static void do_cmd(char *b, void (*output)(void *, char *, ...), void *op)
{
	char *p, *q;
	int n;
	FILE *fp;

	DEBUG(2, "do_cmd(%s, %p, %p)", b, output, op);
	p = strchr(b, '\r');
	if (p) *p = '\0';
	p = strchr(b, '\n');
	if (p) *p = '\0';
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
				if (inet_pton(AF_INET6, ip, ipaddr) != 1) {
					debug("acl: can't convert address %s", ip);
					return;
				}
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
		hash = 1;
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
			listenfd = open_listener(p);
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
			hash?"":"no ",
			roundrobin?"":"no ",
			stubborn?"":"no ",
			weight?"":"no ",
			prio?"":"no ");
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
			hash = 0;
		} else if (!strcmp(p, "http")) {
			http = 0;
		} else if (!strcmp(p, "keepalive")) {
			keepalive = 0;
		} else if (!strcmp(p, "log")) {
			logfile = NULL;
			if (logfp) fclose(logfp);
			logfp = NULL;
		} else if (!strcmp(p, "prio")) {
			prio = 0;
		} else if (!strcmp(p, "roundrobin")) {
			roundrobin = 0;
		} else if (!strcmp(p, "stubborn")) {
			stubborn = 0;
		} else if (!strcmp(p, "tcp_nodelay")) {
			tcp_nodelay = 0;
		} else if (!strcmp(p, "web_stats")) {
			webfile = NULL;
		} else if (!strcmp(p, "weight")) {
			weight = 0;
		}
	} else if (!strcmp(p, "pid")) {
		output(op, "%ld\n", (long)getpid());
	} else if (!strcmp(p, "poll")) {
		event_init = poll_init;
	} else if (!strcmp(p, "prio")) {
		prio = 1;
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
		roundrobin = 1;
	} else if (!strcmp(p, "select")) {
		event_init = select_init;
	} else if (!strcmp(p, "server")) {
		p = strtok(NULL, " ");
		if (p == NULL) return;
		n = atoi(p);
		if (n < 0 || n >= nservers) return;
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
	} else if (!strcmp(p, "stubborn")) {
		stubborn = 1;
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
		weight = 1;
	} else if (!strcmp(p, "write")) {
		p = strtok(NULL, " ");
		if (!p) p = cfgfile;
		if (p) {
			write_cfg(p);
		} else {
			debug("write: no file");
		}
	} else {
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

static int unused_server_slot(int i)
{
	struct sockaddr_storage *a = &servers[i].addr;
	if (a->ss_family == AF_INET) {
		struct sockaddr_in *si = (struct sockaddr_in *)a;
		if (si->sin_addr.s_addr == 0) return i;
	}
	return 0;
}

static int server_is_blacklisted(int i)
{
	return (now-servers[i].status < blacklist_time);
}

static int server_is_unavailable(int i)
{
	return unused_server_slot(i) || server_is_blacklisted(i);
}

static int server_by_weight(void)
{
	int best_server = -1;
	int best_load = -1;
	int i, load;

	DEBUG(2, "server_by_weight()");
	for (i = 0; i < nservers; i++) {
		if (server_is_unavailable(i)) continue;
		if (servers[i].weight == 0) continue;
		load = (WEIGHT_FACTOR*servers[i].c)/servers[i].weight;
		if (best_server == -1 || load < best_load) {
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
	int best_server = -1;
	int best_prio = -1;
	int i, prio;

	DEBUG(2, "server_by_prio()");
	for (i = 0; i < nservers; i++) {
		if (server_is_unavailable(i)) continue;
		prio = servers[i].prio;
		if (best_server == -1 || prio < best_prio) {
			DEBUG(2, "Server %d has prio %d", i, prio);
			best_prio = prio;
			best_server = i;
		}
	}
	DEBUG(2, "Best prio server = %d", best_server);
	return best_server;
}

static int server_by_roundrobin(void)
{
	static int last_server = 0;
	int i = last_server;

	do {
		i = (i+1) % nservers;
		DEBUG(3, "server_by_roundrobin considering server %d", i);
		if (!server_is_unavailable(i)) return (last_server = i);
		DEBUG(3, "server %d is unavailable, try next one", i);
	} while (i != last_server);
	return -1;
}

/* Suggest a server for the initial field of the connection.
   Return -1 if none available.
*/
static int initial_server(int conn)
{
	int pd = match_acl(client_acl, &clients[conns[conn].client].addr);
	if (!pd) {
		DEBUG(1, "initial_server: denied by acl");
		return abuse_server;
	}
	if (!roundrobin) {
		// Load balancing with memory == No roundrobin
		int server = clients[conns[conn].client].server;
		/* server may be -1 if this is a new client */
		if (server != -1 && server != emerg_server && server != abuse_server) {
			return server;
		}
	}
	if (prio) return server_by_prio();
	if (weight) return server_by_weight();
	if (hash) return pen_hash(&clients[conns[conn].client].addr);
	return server_by_roundrobin();
}

/* Returns 1 if a failover server candidate is available.
   Close connection and return 0 if none was found.
*/
static int failover_server(int conn)
{
	int server = conns[conn].server;
	DEBUG(2, "failover_server(%d)", conn);
	if (stubborn) {
		DEBUG(2, "Won't failover because we are stubborn");
		close_conn(conn);
		return 0;
	}
	if (server == abuse_server) {
		DEBUG(2, "Won't failover from abuse server");
		close_conn(conn);
		return 0;
	}
	if (server == emerg_server) {
		DEBUG(2, "Already using emergency server, won't fail over");
		close_conn(conn);
		return 0;
	}
	if (conns[conn].upfd != -1) {
		close(conns[conn].upfd);
		conns[conn].upfd = -1;
	}
	do {
		server = (server+1) % nservers;
		DEBUG(2, "Intend to try server %d", server);
		if (try_server(server, conn)) return 1;
	} while (server != conns[conn].initial);
	DEBUG(1, "using emergency server, remember to reset flag");
	emergency = 1;
	if (try_server(emerg_server, conn)) return 1;
	close_conn(conn);
	return 0;
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
		socklen_t len = sizeof *cli_addr;
		rc = recvfrom(listenfd, b, sizeof b, 0, (struct sockaddr *)cli_addr, &len);
		DEBUG(2, "add_client: received %d bytes from client", rc);
		if (rc < 0) {
			if (errno != EINTR)
				debug("Error receiving data");
			return;
		}
	}
	client = store_client(cli_addr);	// no server yet
	DEBUG(2, "store_client returns %d", client);

#ifdef HAVE_LIBSSL
	conn = store_conn(downfd, ssl, client);
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

	conns[conn].initial = initial_server(conn);
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
		rc = send(conns[conn].upfd, b, rc, 0);
		DEBUG(2, "add_client: wrote %d bytes to socket %d", rc, conns[conn].upfd);
	}
}

static int flush_down(int i)
{
	int n, err = 0;

#ifdef HAVE_LIBSSL
	SSL *ssl = conns[i].ssl;

	if (ssl) {
		n = SSL_write(ssl, conns[i].downbptr, conns[i].downn);
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

	if (!udp)
		n = my_send(conns[i].downfd, conns[i].downbptr, conns[i].downn, 0);
	else
		n = sendto(conns[i].downfd, conns[i].downbptr, conns[i].downn, 0,
			(struct sockaddr *) &name, size);
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

	if (!udp)
		n = my_send(conns[i].upfd, conns[i].upbptr, conns[i].upn, 0);
	else
		n = sendto(conns[i].upfd, conns[i].upbptr, conns[i].upn, 0,
			(struct sockaddr *) &name, size);
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

/* For UDP, connection attempts to unreachable servers would sit in the
   connection table forever unless we remove them by force.
   This function is pretty brutal, it simply vacates the next slot
   after the most recently used one. This will always succeed.
*/
static void recycle_connection(void)
{
	int i;

	i = connections_last+1;
	if (i >= connections_max) i = 0;
	close_conn(i);
}

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

static void check_listen_socket(void)
{
	struct sockaddr_storage cli_addr;
	socklen_t clilen = sizeof cli_addr;
	int i, downfd;
	DEBUG(2, "check_listen_socket()");
	/* special case for udp */
	if (udp) {
		downfd = listenfd;
		add_client(downfd, &cli_addr);
	} else {
	/* process tcp connection(s) */
		for (i = 0; i < multi_accept; i++) {
			if (connections_used >= connections_max) break;
			downfd = accept_nb(listenfd,
				(struct sockaddr *)&cli_addr, &clilen);
			if (downfd < 0) {
				if (debuglevel && errno != EAGAIN) {
					perror("accept");
				}
				break;
			}
			if (clilen == 0) {
				if (debuglevel) perror("clilen");
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
		if (debuglevel) perror("accept");
		return;
	}
	if (clilen == 0) {
		if (debuglevel) perror("clilen");
		return;
	}
	do_ctrl(downfd, &cli_addr);
}

static void check_if_connected(int i)
{
	int result;
	socklen_t length = sizeof result;
	DEBUG(2, "Something happened to connection %d", i);
	if (getsockopt(conns[i].upfd, SOL_SOCKET, SO_ERROR, &result, &length) < 0) {
		debug("Can't getsockopt: %s", strerror(errno));
		close_conn(i);
		return;
	}
	if (result != 0) {
		debug("Connect failed: %s", strerror(result));
		blacklist_server(conns[i].server);
		if (failover_server(i) == 0) {
			//close_conn(i);
		}
		return;
	}
	DEBUG(2, "Connection %d completed", i);
	if (conns[i].state == CS_IN_PROGRESS) {
		pending_list = dlist_remove(conns[i].pend);
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

	if (can_accept) {
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
                if (conns[conn].state & CS_IN_PROGRESS) {
                        if (fd == conns[conn].upfd && events & EVENT_WRITE) {
                                check_if_connected(conn);
                        }
                        continue;
                }
		conns[conn].t = now;
                if (fd == conns[conn].downfd) {
                        if (!udp && (events & EVENT_READ)) {
                                if (!try_copy_up(conn)) closing = 1;
                        }
                        if (events & EVENT_WRITE) {
                                if (!try_flush_down(conn)) closing = 1;
                        }
                } else {        /* down */
                        if (events & EVENT_READ) {
                                if (!try_copy_down(conn)) closing = 1;
                        }
                        if (!udp && (events & EVENT_WRITE)) {
                                if (!try_flush_up(conn)) closing = 1;
                        }
                }
		if (closing) {
			pending_close[npc++] = conn;
		}
        }
	return npc;
}

static void close_idlers(int n)
{
	int conn;

	DEBUG(2, "close_idlers(%d)", n);
	for (conn = 0; n > 0 && conn < connections_max; conn++) {
		if (idler(conn)) {
			DEBUG(3, "Closing idling connection %d", conn);
			close_conn(conn);
			n--;
		}
	}
}

static int add_idler(void)
{
#ifdef HAVE_LIBSSL
	int conn = store_conn(-1, NULL, -1);
#else
	int conn = store_conn(-1, -1);
#endif
	if (conn == -1) return 0;
	conns[conn].initial = server_by_roundrobin();
	if (conns[conn].initial == -1) {
		close_conn(conn);
		return 0;
	}
	if (!try_server(conns[conn].initial, conn)) {
		if (!failover_server(conn)) {
			close_conn(conn);
			return 0;
		}
	}
	idlers++;
	return 1;
}

static void pending_and_closing(int *pending_close, int npc)
{
	int j, p, start;

	if (pending_list != -1) {
		p = start = pending_list;
		do {
			int conn = dlist_value(p);
			if (conns[conn].state == CS_IN_PROGRESS) {
				check_if_timeout(conn);
			}
			p = dlist_next(p);
		} while (p != start);
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
                if (udp && (connections_used >= connections_max)) recycle_connection();
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
	char *opt = "B:C:F:O:S:T:b:c:e:i:j:l:m:o:p:q:t:u:w:x:DHPQWXUadfhnrsE:K:G:A:ZRL:";
#else
	char *opt = "B:C:F:O:S:T:b:c:e:i:j:l:m:o:p:q:t:u:w:x:DHPQWXUadfhnrs";
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
			event_init = kqueue_init;
			break;
		case 'P':
			event_init = poll_init;
			break;
		case 'S':
			servers_max = atoi(optarg);
			break;
		case 'T':
			tracking_time = atoi(optarg);
			break;
		case 'U':
			udp = 1;
			break;
		case 'W':
			weight = 1;
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
			clients_max = atoi(optarg);
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
			hash = 1;
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
			roundrobin = 1;
			break;
		case 's':
			stubborn = 1;
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
			connections_max = atoi(optarg);
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
	int i;
	struct passwd *pwd = NULL;
	struct rlimit r;
	int n = options(argc, argv);
	argc -= n;
	argv += n;

	now = time(NULL);
#ifdef WINDOWS
	start_winsock();
#endif

	getrlimit(RLIMIT_CORE, &r);
	r.rlim_cur = r.rlim_max;
	setrlimit(RLIMIT_CORE, &r);

	signal(SIGCHLD, SIG_IGN);

#ifndef WINDOWS
	if (!foreground) {
		background();
	}
#endif

#ifdef HAVE_LIBSSL
	if (certfile) {
		ssl_init();
	}
#endif

	/* we must open listeners before dropping privileges */
	/* Control port */
	if (ctrlport) {
		if (getuid() == 0 && user == NULL) {
			debug("Won't open control port running as root; use -u to run as different user");
		} else {
			ctrlfd = open_listener(ctrlport);
		}
	}

	/* Balancing port */
	if (udp) {
		protoid = SOCK_DGRAM;
		proto = "udp";
	}

	snprintf(listenport, sizeof listenport, "%s", argv[0]);
	listenfd = open_listener(listenport);
	init_mask();
	init(argc, argv);

	/* we must look up user id before chrooting */
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

	read_cfg(cfgfile);
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

#ifdef HAVE_LIBGEOIP
	geoip4 = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_MEMORY_CACHE);
	if (geoip4 == NULL) debug("Could not initialize GeoIP for IPv4");
	geoip6 = GeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_MEMORY_CACHE);
	if (geoip6 == NULL) debug("Could not initialize GeoIP for IPv6");
#endif

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
