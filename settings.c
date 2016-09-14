#include "config.h"
#ifndef WINDOWS
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif

int foreground;
int abort_on_error = 0;
int multi_accept = 100;
int tcp_fastclose = 0;
int keepalive = 0;
int udp = 0;
int transparent = 0;
