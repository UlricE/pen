#include <time.h>
#include <netinet/in.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <in6addr.h>
extern void stop_winsock();
#endif

//#ifdef HAVE_LIBSSL
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#endif	/* HAVE_LIBSSL */

extern int socket_nb(int, int, int);

extern int listenfd;
extern time_t now;

extern void mainloop(void);

