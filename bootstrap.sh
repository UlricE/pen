#!/bin/sh

aclocal
autoheader
autoconf
libtoolize --copy --automake
automake --copy --add-missing --foreign
