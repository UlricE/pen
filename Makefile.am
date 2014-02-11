
bin_PROGRAMS = pen mergelogs penctl penlog penlogd

pen_SOURCES = pen.c
mergelogs_SOURCES = mergelogs.c
penctl_SOURCES = penctl.c
penlog_SOURCES = penlog.c
penlogd_SOURCES = penlogd.c

doc_DATA = penstats HOWTO AUTHORS README ChangeLog COPYING

man_MANS = pen.1 mergelogs.1 penctl.1 penlog.1 penlogd.1

EXTRA_DIST = $(man_MANS) $(doc_DATA) penctl.cgi pen.spec siag.pem

tgz:
	rm -rf tmpinst
	mkdir tmpinst
	make clean
	./configure --prefix=/usr
	make
	make install-strip prefix=tmpinst/usr
	(cd tmpinst && makepkg pen.tgz && mv pen.tgz ..)

