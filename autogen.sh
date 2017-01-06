#!/bin/sh

# This generates makefiles, configure, etc.

libtoolize --force
aclocal
autoheader
autoreconf -vfi
