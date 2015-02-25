#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "pen.h"
#ifdef HAVE_POLL
#include <poll.h>

struct pollfd *poll_ufds;
static int poll_nfds, poll_count, poll_nfds_max;
static int index;

/* Making a sparse pollfd table, using fd as the index seems most efficient. */
/* Need to make sure to grow the table as necessary. */

static void poll_event_ctl(int fd, int events)
{
        int pollevents = 0;
	DEBUG(2, "poll_event_ctl(fd=%d, events=%d)", fd, events);
	if (fd >= poll_nfds_max) {
		int i, new_max = fd+10000;
		DEBUG(2, "expanding poll_ufds to %d entries", new_max);
		poll_ufds = pen_realloc(poll_ufds, new_max * sizeof *poll_ufds);
		for (i = poll_nfds_max; i < new_max; i++) {
			poll_ufds[i].fd = -1;
			poll_ufds[i].events = 0;
		}
		poll_nfds_max = new_max;
	}
        if (events & EVENT_READ) pollevents |= POLLIN;
        if (events & EVENT_WRITE) pollevents |= POLLOUT;
        poll_ufds[fd].fd = fd;
        poll_ufds[fd].events = pollevents;
        if (fd >= poll_nfds) poll_nfds = fd+1;
}

static void poll_event_add(int fd, int events)
{
	DEBUG(2, "poll_event_add(fd=%d, events=%d)", fd, events);
	poll_event_ctl(fd, events);
}

static void poll_event_arm(int fd, int events)
{
	DEBUG(2, "poll_event_arm(fd=%d, events=%d)", fd, events);
	poll_event_ctl(fd, events);
}

static void poll_event_delete(int fd)
{
	DEBUG(2, "poll_event_delete(fd=%d)", fd);
	poll_ufds[fd].fd = -1;	/* ignore events */
	poll_ufds[fd].events = 0;
}

static void poll_event_wait(void)
{
	DEBUG(2, "poll_event_wait()");
	index = -1;
        poll_count = poll(poll_ufds, poll_nfds, 1000*timeout);
	DEBUG(2, "poll returns %d", poll_count);
        if (poll_count < 0 && errno != EINTR) {
                perror("poll");
                error("Error on poll");
        }
}

static int poll_event_fd(int *revents)
{
        int events = 0;
	DEBUG(2, "poll_event_fd(revents=%p)", revents);
	for (index++; index < poll_nfds; index++) {
		DEBUG(3, "\tpoll_ufds[%d] = {fd=%d, revents=%d}", index, poll_ufds[index].fd, poll_ufds[index].revents);
        	if (poll_ufds[index].revents & POLLIN) events |= EVENT_READ;
        	if (poll_ufds[index].revents & POLLOUT) events |= EVENT_WRITE;
		if (events) {
			*revents = events;
        		return poll_ufds[index].fd;
		}
	}
	return -1;
}

void poll_init(void)
{
	DEBUG(2, "poll_init()");
	poll_nfds = poll_nfds_max = 0;
	poll_ufds = NULL;
	event_add = poll_event_add;
	event_arm = poll_event_arm;
	event_delete = poll_event_delete;
	event_wait = poll_event_wait;
	event_fd = poll_event_fd;
}
#else
void poll_init(void)
{
	debug("You don't have poll");
	exit(EXIT_FAILURE);
}
#endif
