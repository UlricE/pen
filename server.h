#include <stdint.h>
#ifndef WINDOWS
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif

#define ALG_HASH_VALID 1
#define ALG_ROUNDROBIN 2
#define ALG_WEIGHT 4
#define ALG_PRIO 8
#define ALG_HASH 16
#define ALG_STUBBORN 32

#define EMERGENCY_SERVER (-1)
#define ABUSE_SERVER (-2)
#define NO_SERVER (-3)

#define BLACKLIST_TIME	30	/* how long to shun a server that is down */
#define WEIGHT_FACTOR	256	/* to make weight kick in earlier */

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
	uint64_t sx, rx;	/* bytes sent, received */
} server;

extern int nservers;		/* number of servers */
extern server *servers;
extern int current;
extern int emerg_server;
extern int abuse_server;
extern int blacklist_time;
extern int server_alg;

extern char *e_server;
extern char *a_server;

extern void setaddress(int, char *, int, int);
extern void blacklist_server(int);
extern int unused_server_slot(int);
extern int server_is_blacklisted(int);
extern int server_is_unavailable(int);
extern int server_by_roundrobin(void);
extern int initial_server(int);
extern int failover_server(int);
extern int try_server(int, int);
extern void expand_servertable(int);
