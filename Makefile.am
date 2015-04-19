
bin_PROGRAMS = pen mergelogs penctl penlog penlogd
noinst_HEADERS = pen.h dlist.h ssl.h dsr.h memory.h diag.h settings.h acl.h

pen_SOURCES = pen.c select.c poll.c kqueue.c epoll.c dlist.c ssl.c dsr.c memory.c diag.c settings.c acl.c
mergelogs_SOURCES = mergelogs.c
penctl_SOURCES = penctl.c
penlog_SOURCES = penlog.c
penlogd_SOURCES = penlogd.c

doc_DATA = penstats HOWTO AUTHORS README ChangeLog COPYING

man_MANS = pen.1 mergelogs.1 penctl.1 penlog.1 penlogd.1

EXTRA_DIST = $(man_MANS) $(doc_DATA) penctl.cgi pen.spec siag.pem \
	Makefile.win X86/Makefile X64/Makefile windows.c config.h.win \
	pen-ocsp.sh

tgz:
	rm -rf tmpinst
	mkdir tmpinst
	make clean
	./configure --prefix=/usr
	make
	make install-strip prefix=tmpinst/usr
	(cd tmpinst && makepkg pen.tgz && mv pen.tgz ..)

