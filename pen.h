#ifdef DEBUGGING
#define DEBUG(lvl, ...) \
	if (debuglevel >= lvl) { \
		debug(__VA_ARGS__); \
	}
#define DEBUG_ERRNO(lvl, ...) \
	if (debuglevel >= lvl) { \
		err = socket_errno; \
		debug(__VA_ARGS__); \
	}
#define SPAM \
	if (debuglevel >= 2) \
		debug("File %s, line %d, function %s", \
			__FILE__, __LINE__, __func__);
#else
#define DEBUG(lvl, ...)
#define DEBUG_ERRNO(lvl, ...)
#define SPAM
#endif

#define EVENT_READ              (0x10000)
#define EVENT_WRITE             (0x20000)

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


extern void (*event_add)(int, int);
extern void (*event_arm)(int, int);
extern void (*event_delete)(int);
extern void (*event_wait)(void);
extern int (*event_fd)(int *);

extern int timeout;
extern int connections_max;
extern time_t now;

extern void select_init(void);
extern void poll_init(void);
extern void kqueue_init(void);
extern void epoll_init(void);
extern int debuglevel;
extern void debug(char *, ...);
extern void error(char *, ...);
extern void *pen_malloc(size_t);
extern void *pen_realloc(void *, size_t);
extern void mainloop(void);

