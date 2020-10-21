#!/bin/bash

# Simple shell script that compiles Sagan with multiple flags.  This helps 
# hunt down compile time bugs. 
# 
# - Public release (06/28/2015) 

#   2016/07/05 - Champ Clark - Replaced jsonc -> libfastjson
#   2017/06/25 - Added "--enable-redis".
#   2017/11/07 - Added test for "saganpeek". 
#   2018/05/08 - Added FLAGS for make
#   2019/11/03 - Removed --disable-snortsam
#   2020/11/20 - Remove --disable-libdnet

# Champ Clark III 

#  --disable-syslog        Disable syslog support.
#  --disable-lognorm       Disable Lognorm (liblognorm) support.
#  --disable-libfastjson   Disable libfastjson.
#  --disable-libpcap       Disable libpcap (plog) support.
#  --enable-bluedot        Enable Quadrant\'s "Bluedot" lookups.  
#  --enable-esmtp          Enable libesmtp support.  
#  --enable-geoip          Enable Maxmind GeoIP support.  
#  --enable-system-strstr  Enable system strstr.  
#  --enable-redis	   Enable redis support.
#  --disable-libfastjson   Endbale libfastjson


STANDARD="--disable-bluedot --disable-esmtp --disable-geoip --disable-system-strstr --enable-syslog --enable-lognorm --enable-libpcap --enable-libfastjson"
ALLFLAGS="--enable-bluedot --enable-esmtp --enable-geoip --enable-system-strstr --enable-syslog --enable-lognorm --enable-libpcap --enable-libfastjson --enable-redis --enable-libfastjson"
NOFLAG="--disable-syslog --disable-lognorm --disable-libpcap --disable-bluedot --disable-esmtp --disable-geoip --disable-system-strstr --disable-system-strstr --disable-libfastjson --disable-redis --disable-libfastjson"

LOG="output.log" 

MAKE_FLAGS="-j5"

autoreconf -vfi

echo "**** STANDARD BUILD | NO FLAGS ****"
echo "**** STANDARD BUILD | NO FLAGS ****" >> $LOG

#make clean
#cd tools && make clean && cd ..

CFLAGS=-Wall ./configure

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
	exit
        fi

make $MAKE_FLAGS 2>> $LOG
cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ] 
	then
	echo "Error on standard build!";
	exit
	fi

echo "**** ALL FLAGS ****"
echo "**** ALL FLAGS ****" >> $LOG

make clean
cd tools && make clean && cd .. 

CFLAGS=-Wall ./configure $ALLFLAGS

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on standard build!";
	exit
        fi

echo "****  NO FLAGS ****"
echo "****  NO FLAGS ****" >> $LOG

make clean
cd tools && make clean && cd ..

CFLAGS=-Wall ./configure $NOFLAG

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on standard build!";
	exit
        fi

for I in $STANDARD
do

make clean
cd tools && make clean && cd ..

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on with $I";
	exit
        fi
done

for I in $ALLFLAGS
do

make clean
cd tools && make clean && cd .. 

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ]
        then
        echo "Error on with $I";
	exit
        fi
done

for I in $NOFLAGS
do

make clean
cd tools && make clean && cd ..

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make $MAKE_FLAGS 2>> $LOG
cd tools && make $MAKE_FLAGS && cd .. 2>> $LOG

if [ "$?" != "0" ]
        then
        echo "Error on with $I";
	exit
        fi
done

