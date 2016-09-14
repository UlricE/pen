extern int getport(char *, int);
extern int pen_setport(struct sockaddr_storage *, int);
extern int pen_getport(struct sockaddr_storage *);
extern char *pen_ntoa(struct sockaddr_storage *);
extern void pen_dumpaddr(struct sockaddr_storage *);
extern int pen_ss_size(struct sockaddr_storage *);
extern int pen_aton(char *, struct sockaddr_storage *);
