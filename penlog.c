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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "diag.h"

#define MAXBUF 1024

int main(int argc, char **argv)
{
	int sk;
	struct addrinfo *client, *server;
	struct addrinfo hints;
	char buf[MAXBUF];
	int n;

	if (argc < 3) {
		error("Usage: %s server_ip server_port [my_ip]", argv[0]);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;
	n = getaddrinfo(argv[1], argv[2], &hints, &server);
	if (n != 0) {
		error("getaddrinfo: %s", gai_strerror(n));
	}

	sk = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
	if (sk == -1) {
		error("Problem creating socket");
	}

	if (argc > 3) { /* set local address */
		memset(&hints, 0, sizeof hints);
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_ADDRCONFIG;
		n = getaddrinfo(argv[3], NULL, &hints, &client);
		if (n != 0) {
			error("getaddrinfo: %s", gai_strerror(n));
		}
		if (bind(sk, client->ai_addr, client->ai_addrlen) != 0) {
			error("Problem creating socket");
		}
	}

	while (fgets(buf, sizeof buf, stdin)) {
		n = sendto(sk, buf, strlen(buf), 0,
			server->ai_addr, server->ai_addrlen);

		if (n < 0) {
			debug("Problem sending data: %s", strerror(errno));
		}
	}

	return 0;
}
