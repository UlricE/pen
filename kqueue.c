#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
//#include "pen.h"
#include "conn.h"
#include "diag.h"
#include "event.h"
#ifdef HAVE_KQUEUE
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

static int kq;
static struct kevent *kev, *kev_out;
static int nfds, maxevents;
static int count;
static int pindex;

#if 0
static void kqueue_event_reset(void)
{
	DEBUG(2, "kqueue_event_reset()");
        nfds = 0;
}
#endif

static void kqueue_event_add(int fd, int events)
{
	DEBUG(2, "kqueue_event_add(fd=%d, events=%d)", fd, events);
	if (events & EVENT_READ) {
		EV_SET(&kev[nfds], fd, EVFILT_READ, EV_ADD|EV_ENABLE, 0, 0, 0);
	} else {
		EV_SET(&kev[nfds], fd, EVFILT_READ, EV_ADD|EV_DISABLE, 0, 0, 0);
	}
	nfds++;
	if (events & EVENT_WRITE) {
		EV_SET(&kev[nfds], fd, EVFILT_WRITE, EV_ADD|EV_ENABLE, 0, 0, 0);
	} else {
		EV_SET(&kev[nfds], fd, EVFILT_WRITE, EV_ADD|EV_DISABLE, 0, 0, 0);
	}
	nfds++;
}

static void kqueue_event_arm(int fd, int events)
{
	DEBUG(2, "kqueue_event_arm(fd=%d, events=%d)", fd, events);
	if (events & EVENT_READ) {
		EV_SET(&kev[nfds], fd, EVFILT_READ, EV_ENABLE, 0, 0, 0);
	} else {
		EV_SET(&kev[nfds], fd, EVFILT_READ, EV_DISABLE, 0, 0, 0);
	}
	nfds++;
	if (events & EVENT_WRITE) {
		EV_SET(&kev[nfds], fd, EVFILT_WRITE, EV_ENABLE, 0, 0, 0);
	} else {
		EV_SET(&kev[nfds], fd, EVFILT_WRITE, EV_DISABLE, 0, 0, 0);
	}
	nfds++;
}

/* The only time we call event_delete is when we are about to close the fd,
   so we can save this operation since the fd will be deleted automatically.
*/
static void kqueue_event_delete(int fd)
{
	DEBUG(2, "kqueue_event_delete(fd=%d)", fd);
	;
}

static void kqueue_event_wait(void)
{
        struct timespec tv;
	DEBUG(2, "kqueue_event_wait()");
        tv.tv_sec = timeout;
        tv.tv_nsec = 0;
        count = kevent(kq, kev, nfds, kev_out, maxevents, &tv);
	DEBUG(2, "kevent returns %d", count);
        if (count < 0 && errno != EINTR) {
                perror("kevent");
                error("Error on kevent");
        }
	pindex = -1;
	nfds = 0;
}

static int kqueue_event_fd(int *revents)
{
        int events = 0;
	DEBUG(2, "kqueue_event_fd(revents=%p)", revents);
        pindex++;
        if (pindex >= count) return -1;
	DEBUG(3, "\tkev_out[%d] = {filter=%d, ident=%d}", pindex, kev_out[pindex].filter, kev_out[pindex].ident);
        if (kev_out[pindex].filter == EVFILT_READ) events |= EVENT_READ;
        if (kev_out[pindex].filter == EVFILT_WRITE) events |= EVENT_WRITE;
	*revents = events;
        return kev_out[pindex].ident;
}

void kqueue_init(void)
{
	kq = kqueue();
	if (kq == -1) {
		perror("kqueue");
		error("Error creating kernel queue");
	}
	maxevents = connections_max*2+2;
	kev = pen_malloc(maxevents*sizeof *kev);
	kev_out = pen_malloc(maxevents*sizeof *kev_out);
	event_add = kqueue_event_add;
	event_arm = kqueue_event_arm;
	event_delete = kqueue_event_delete;
	event_wait = kqueue_event_wait;
	event_fd = kqueue_event_fd;
	nfds = 0;
}
#else
void kqueue_init(void)
{
	debug("You don't have kqueue");
	exit(EXIT_FAILURE);
}
#endif
