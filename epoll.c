#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include "pen.h"
#include "conn.h"
#include "diag.h"
#include "event.h"
#include "memory.h"
#ifdef HAVE_EPOLL
#include <sys/epoll.h>

static int efd;
static struct epoll_event *epoll_ev;
static int epoll_count, maxevents;
static int pindex;

static void epoll_event_ctl(int fd, int events, int op)
{
	int n, epevents = 0;
	struct epoll_event ev;
	memset(&ev, 0, sizeof(struct epoll_event));
	DEBUG(2, "epoll_event_ctl(fd=%d, events=%d, op=%d)", fd, events, op);
	if (events & EVENT_READ) epevents |= EPOLLIN;
	if (events & EVENT_WRITE) epevents |= EPOLLOUT;
	ev.events = epevents;
	ev.data.fd = fd;
	n = epoll_ctl(efd, op, fd, &ev);
	if (n == -1) {
		error("epoll_ctl: %s", strerror(errno));
	}
}

static void epoll_event_add(int fd, int events)
{
	DEBUG(2, "epoll_event_add(fd=%d, events=%d)", fd, events);
	epoll_event_ctl(fd, events, EPOLL_CTL_ADD);
}

static void epoll_event_arm(int fd, int events)
{
	DEBUG(2, "epoll_event_arm(fd=%d, events=%d)", fd, events);
	epoll_event_ctl(fd, events, EPOLL_CTL_MOD);
}

/* We don't need to do anything here, because this function is only called
   when we are about to close the socket.
*/
static void epoll_event_delete(int fd)
{
	DEBUG(2, "epoll_event_delete(fd=%d)", fd);
}

static void epoll_event_wait(void)
{
	DEBUG(2, "epoll_event_wait()");
	pindex = -1;
        epoll_count = epoll_wait(efd, epoll_ev, maxevents, 1000*timeout);
	DEBUG(2, "epoll_wait returns %d", epoll_count);
        if (epoll_count == -1 && errno != EINTR) {
                error("Error on epoll_wait: %s", strerror(errno));
        }
}

static int epoll_event_fd(int *revents)
{
        int events = 0;
	DEBUG(2, "epoll_event_fd(revents=%p)", revents);
	pindex++;
        if (pindex >= epoll_count) return -1;
	DEBUG(3, "\tepoll_ev[%d] = {revents=%d, data.fd=%d}", pindex, epoll_ev[pindex].events, epoll_ev[pindex].data.fd);
        if (epoll_ev[pindex].events & EPOLLIN) events |= EVENT_READ;
	if (epoll_ev[pindex].events & EPOLLOUT) events |= EVENT_WRITE;
	if (epoll_ev[pindex].events & EPOLLERR) events |= EVENT_ERR;
	if (epoll_ev[pindex].events & EPOLLHUP) events |= EVENT_ERR;
	if (events == 0) DEBUG(2, "events for fd %d = %d", epoll_ev[pindex].data.fd, epoll_ev[pindex].events);
	*revents = events;
	return epoll_ev[pindex].data.fd;
}

void epoll_init(void)
{
	efd = epoll_create1(0);
	DEBUG(2, "epoll_create1 returns %d", efd);
	if (efd == -1) {
		debug("epoll_create1: %s", strerror(errno));
		error("Error creating epoll fd");
	}
	maxevents = connections_max*2+2;
	epoll_ev = pen_malloc(maxevents*sizeof *epoll_ev);
	event_add = epoll_event_add;
	event_arm = epoll_event_arm;
	event_delete = epoll_event_delete;
	event_wait = epoll_event_wait;
	event_fd = epoll_event_fd;
}
#else
void epoll_init(void)
{
	debug("You don't have epoll");
	exit(EXIT_FAILURE);
}
#endif
