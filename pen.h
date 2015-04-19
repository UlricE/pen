#include <time.h>
#include <netinet/in.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <in6addr.h>
extern void stop_winsock();
extern int delete_service(char *);
extern int install_service(char *);
extern int service_main(int, char **);
#define socket_errno WSAGetLastError()
#else
#define socket_errno errno
#endif

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif	/* HAVE_LIBSSL */

/* Connection states, as used in struct conn */
#define CS_UNUSED	(0)	/* not connected, unused slot */
#define CS_IN_PROGRESS	(1)	/* connection in progress */
#define CS_CONNECTED	(2)	/* successfully connected */
#define CS_CLOSED_UP	(4)	/* we read eof from upfd */
#define CS_CLOSED_DOWN	(8)	/* we read eof from downfd */
#define CS_CLOSED	(CS_CLOSED_UP | CS_CLOSED_DOWN)

typedef struct {
	int status;		/* last failed connection attempt */
	int acl;		/* which clients can use this server */
	struct sockaddr_storage addr;
	uint8_t hwaddr[6];
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
	time_t reneg;		/* last time client requested renegotiation */
#endif
} connection;

extern int multi_accept;
extern int nservers;		/* number of servers */
extern server *servers;

extern int socket_nb(int, int, int);

extern int connections_max;
extern time_t now;

extern int unused_server_slot(int);
extern int server_is_blacklisted(int);
extern void mainloop(void);

