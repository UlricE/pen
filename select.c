#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef WINDOWS
#include <winsock2.h>
#endif
#if defined HAVE_SYS_SELECT_H && !defined WINDOWS
/* because windows doesn't have it */
#include <sys/select.h>
#endif
//#include "pen.h"
#include "conn.h"
#include "diag.h"
#include "event.h"

static fd_set w_read, w_write;
static fd_set w_r_copy, w_w_copy;
static int w_max;

static void select_event_ctl(int fd, int events)
{
	DEBUG(2, "select_event_ctl(fd=%d, events=%d)", fd, events);
	if (events & EVENT_READ) FD_SET(fd, &w_read);
	else FD_CLR(fd, &w_read);
	if (events & EVENT_WRITE) FD_SET(fd, &w_write);
	else FD_CLR(fd, &w_write);
	if (events) {
		if (fd >= w_max) w_max = fd+1;
	}
}

static void select_event_add(int fd, int events)
{
	DEBUG(2, "select_event_add(fd=%d, events=%d)", fd, events);
	select_event_ctl(fd, events);
}

static void select_event_arm(int fd, int events)
{
	DEBUG(2, "select_event_arm(fd=%d, events=%d)", fd, events);
	select_event_ctl(fd, events);
}

static void select_event_delete(int fd)
{
	DEBUG(2, "select_event_delete(fd=%d)", fd);
	FD_CLR(fd, &w_read);
	FD_CLR(fd, &w_write);
}

static int fd;

static void select_event_wait(void)
{
	int n, err;
        struct timeval tv;
	DEBUG(2, "select_event_wait()");
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
	memcpy(&w_r_copy, &w_read, sizeof w_read);
	memcpy(&w_w_copy, &w_write, sizeof w_write);
	fd = -1;
        n = select(w_max, &w_r_copy, &w_w_copy, 0, &tv);
	err = socket_errno;
	DEBUG(2, "select returns %d, socket_errno=%d", n, err);
        if (n < 0 && err != EINTR) {
                error("Error on select: %s", strerror(errno));
        }
}

static int select_event_fd(int *revents)
{
        int events = 0;
	DEBUG(2, "select_event_fd(revents=%p)", revents);
	for (fd++; fd < w_max; fd++) {
                if (FD_ISSET(fd, &w_r_copy)) events |= EVENT_READ;
                if (FD_ISSET(fd, &w_w_copy)) events |= EVENT_WRITE;
                if (events) {
			*revents = events;
			return fd;
		}
        }
        return -1;
}

void select_init(void)
{
	DEBUG(2, "select_init()");
	if ((connections_max*2+10) > FD_SETSIZE) {
		error("Number of simultaneous connections too large.\n"
			"Maximum is %d, or re-build pen with larger FD_SETSIZE",
			(FD_SETSIZE-10)/2);
	}
	FD_ZERO(&w_read);
	FD_ZERO(&w_write);
	w_max = 0;
	event_add = select_event_add;
	event_arm = select_event_arm;
	event_delete = select_event_delete;
	event_wait = select_event_wait;
	event_fd = select_event_fd;
}

