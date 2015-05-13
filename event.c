#include "config.h"
#include "event.h"
#include "pen_epoll.h"
#include "pen_kqueue.h"
#include "pen_poll.h"
#include "pen_select.h"

int timeout = TIMEOUT;

void (*event_add)(int, int);
void (*event_arm)(int, int);
void (*event_delete)(int);
void (*event_wait)(void);
int (*event_fd)(int *);
#if defined HAVE_KQUEUE
void (*event_init)(void) = kqueue_init;
#elif defined HAVE_EPOLL
void (*event_init)(void) = epoll_init;
#elif defined HAVE_POLL
void (*event_init)(void) = poll_init;
#else
void (*event_init)(void) = select_init;
#endif

