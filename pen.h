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

extern void (*event_add)(int, int);
extern void (*event_arm)(int, int);
extern void (*event_delete)(int);
extern void (*event_wait)(void);
extern int (*event_fd)(int *);

extern int timeout;
extern int connections_max;

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

/* dlist.c */
extern int dlist_insert(int, int);
extern int dlist_remove(int);
extern void dlist_free(int);
extern int dlist_next(int);
extern int dlist_value(int);
extern void dlist_init(int);

