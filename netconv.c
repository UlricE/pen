#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifdef WINDOWS
#include <winsock2.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#endif
#include "diag.h"
#include "windows.h"

/* return port number in host byte order */
int getport(char *p, int proto)
{
	struct servent *s = getservbyname(p, proto == SOCK_STREAM ? "tcp" : "udp");
	if (s == NULL) {
		return atoi(p);
	} else {
		return ntohs(s->s_port);
	}
}

/* Takes a struct sockaddr_storage and returns the port number in host order.
   For a Unix socket, the port number is 1.
*/
int pen_getport(struct sockaddr_storage *a)
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

int pen_setport(struct sockaddr_storage *a, int port)
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
char *pen_ntoa(struct sockaddr_storage *a)
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

void pen_dumpaddr(struct sockaddr_storage *a)
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

int pen_ss_size(struct sockaddr_storage *ss)
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
int pen_aton(char *name, struct sockaddr_storage *addr)
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
