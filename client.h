#include <time.h>
#ifndef WINDOWS
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif

#define CLIENTS_MAX	2048	/* max clients */
#define TRACKING_TIME	0	/* how long a client is remembered */

typedef struct {
	time_t last;		/* last time this client made a connection */
	struct sockaddr_storage addr;
	int server;		/* server used last time */
	long connects;
	long long csx, crx;
} client;

extern client *clients;
extern int clients_max;

extern int store_client(struct sockaddr_storage *);
