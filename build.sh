#!/bin/sh

aclocal && autoheader && automake --add-missing -i && autoconf || exit 1

./configure || exit 2

make clean && make -j10 || exit 3


