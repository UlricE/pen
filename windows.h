#ifdef WINDOWS
#define SHUT_WR SD_SEND		/* for shutdown */

#define LOG_CONS	0
#define LOG_USER	0
#define LOG_ERR		0
#define LOG_DEBUG	0

#define CONNECT_IN_PROGRESS (WSAEWOULDBLOCK)
#define WOULD_BLOCK(err) (err == WSAEWOULDBLOCK)

#define SIGHUP	0
#define SIGUSR1	0
#define SIGPIPE	0
#define SIGCHLD	0

typedef int sigset_t;
typedef int siginfo_t;

struct sigaction {
	void     (*sa_handler)(int);
	void     (*sa_sigaction)(int, siginfo_t *, void *);
	sigset_t   sa_mask;
	int        sa_flags;
	void     (*sa_restorer)(void);
};

typedef int rlim_t;

struct rlimit {
	rlim_t rlim_cur;
	rlim_t rlim_max;
};

#define RLIMIT_CORE 0

typedef int uid_t;
typedef int gid_t;

struct passwd {
	uid_t pw_uid;
	gid_t pw_gid;
};

extern int delete_service(char *);
extern int install_service(char *);
extern int service_main(int, char **);
#endif	/* WINDOWS */
