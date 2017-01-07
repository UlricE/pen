#include <time.h>
#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include <time.h>

#define CONNECTIONS_MAX	500	/* max simultaneous connections */

/* Connection states, as used in struct conn */
#define CS_UNUSED	(0)	/* not connected, unused slot */
#define CS_IN_PROGRESS	(1)	/* connection in progress */
#define CS_CONNECTED	(2)	/* successfully connected */
#define CS_CLOSED_UP	(4)	/* we read eof from upfd */
#define CS_CLOSED_DOWN	(8)	/* we read eof from downfd */
#define CS_CLOSED	(CS_CLOSED_UP | CS_CLOSED_DOWN)
#define CS_HALFDEAD	(16)	/* has not seen recent traffic */
#define CS_WAIT_PEEK	(32)	/* waiting for client's first frame */

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

extern connection *conns;
extern int idle_timeout;
extern int pending_list;
extern int pending_queue;
extern int pending_max;
extern int connections_max;
extern int connections_used;
extern int connections_last;
extern int tracking_time;

extern void fd2conn_set(int, int);
extern int fd2conn_get(int);
extern int closing_time(int);
#ifdef HAVE_LIBSSL
int store_conn(int, SSL *, int);
#else
int store_conn(int, int);
#endif
extern int idler(int);
extern void close_conn(int);
extern void expand_conntable(size_t);
