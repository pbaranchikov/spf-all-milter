#!/bin/sh

aclocal && autoheader && automake --add-missing -i && autoconf || exit 1

make clean && make -j10 || exit 3


