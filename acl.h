#ifndef WINDOWS
#include <netinet/in.h>
#include <sys/socket.h>		/* for sockaddr_storage */
#else
#include <winsock2.h>
#include <ws2ipdef.h>
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
#endif

#define ACLS_MAX	10	/* max acls */

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

extern int client_acl;

extern void add_acl_ipv4(int, unsigned int, unsigned int, unsigned char);
extern void add_acl_ipv6(int, unsigned char *, unsigned char, unsigned char);
extern void add_acl_geo(int, char *, unsigned char);
extern void del_acl(int);
extern int match_acl(int, struct sockaddr_storage *);
extern void save_acls(FILE *fp);
extern void acl_init(void);
