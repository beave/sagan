#!/bin/sh

# This generates makefiles, configure, etc.

#libtoolize --force
#aclocal -I m4
#autoheader -I m4
autoreconf -vfi -I m4
