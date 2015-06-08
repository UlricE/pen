#!/bin/sh

aclocal
autoheader
autoconf
automake --copy --add-missing --foreign
