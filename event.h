#define EVENT_READ              (0x10000)
#define EVENT_WRITE             (0x20000)
#define EVENT_ERR		(0x40000)

#define TIMEOUT		3	/* default timeout for non reachable hosts */

extern int timeout;

extern void (*event_init)(void);
extern void (*event_add)(int, int);
extern void (*event_arm)(int, int);
extern void (*event_delete)(int);
extern void (*event_wait)(void);
extern int (*event_fd)(int *);

