#include "config.h"
#include <string.h>
#ifndef WINDOWS
#include <netinet/in.h>
#endif
#include "client.h"
#include "conn.h"
#include "diag.h"
#include "memory.h"
#include "netconv.h"
#include "pen.h"
#include "server.h"

client *clients;
int clients_max = 0;
int client_acl;

/* Store client and return index */
int store_client(struct sockaddr_storage *cli)
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
		DEBUG(2, "Resetting client stats for slot %d", i);
		clients[i].connects = 0;
		clients[i].csx = 0;
		clients[i].crx = 0;
		clients[i].server = NO_SERVER;
	}

	clients[i].last = now;
	clients[i].addr = *cli;
	clients[i].connects++;
	

	DEBUG(2, "Client %s has index %d", pen_ntoa(cli), i);

	return i;
}

void expand_clienttable(int size)
{
	if (size <= clients_max) return;	/* nothing to do */
	clients = pen_realloc(clients, size*sizeof *clients);
	memset(&clients[clients_max], 0, (size-clients_max)*sizeof clients[0]);
	clients_max = size;
}

