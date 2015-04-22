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

#ifdef WINDOWS
#define socket_errno WSAGetLastError()
#else
#define socket_errno errno
#endif

extern int debuglevel;
extern void debug(char *, ...);
extern void error(char *, ...);
