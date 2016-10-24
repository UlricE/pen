#include <time.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <in6addr.h>
extern void stop_winsock();
#else
#include <netinet/in.h>
#endif

//#ifdef HAVE_LIBSSL
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#endif	/* HAVE_LIBSSL */

extern int socket_nb(int, int, int);

extern int listenfd;
extern time_t now;
extern struct sockaddr_storage *source;

extern void mainloop(void);

