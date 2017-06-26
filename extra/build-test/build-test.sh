#!/bin/bash

# Simple shell script that compiles Sagan with multiple flags.  This helps 
# hunt down compile time bugs. 
# 
# - Public release (06/28/2015) 

#   2016/07/05 - Champ Clark - Replaced jsonc -> libfastjson
#   2017/06/25 - Added "--enable-redis".

# Champ Clark III 

#  --disable-snortsam      Disable Snortsam support.
#  --disable-syslog        Disable syslog support.
#  --disable-lognorm       Disable Lognorm (liblognorm) support.
#  --disable-libfastjson   Disable libfastjson.
#  --disable-libpcap       Disable libpcap (plog) support.
#  --disable-libdnet       Disable libdnet (unified2) support.
#  --enable-bluedot        Enable Quadrant\'s "Bluedot" lookups.  
#  --enable-esmtp          Enable libesmtp support.  
#  --enable-geoip2         Enable Maxmind GeoIP2 support.  
#  --enable-system-strstr  Enable system strstr.  
#  --enable-redis	   Enable redis support.


STANDARD="--disable-bluedot --disable-esmtp --disable-geoip2 --disable-system-strstr --enable-snortsam --enable-syslog --enable-lognorm --enable-libpcap --enable-libdnet"
ALLFLAGS="--enable-bluedot --enable-esmtp --enable-geoip2 --enable-system-strstr --enable-snortsam --enable-syslog --enable-lognorm --enable-libpcap --enable-libdnet --enable-libfastjson --enable-redis"
NOFLAG="--disable-snortsam --disable-syslog --disable-lognorm --disable-libpcap --disable-libdnet --disable-bluedot --disable-esmtp --disable-geoip2 --disable-system-strstr --disable-system-strstr --disable-libfastjson --disable-redis"

LOG="output.log" 

#autoreconf -vfi

echo "**** STANDARD BUILD | NO FLAGS ****"
echo "**** STANDARD BUILD | NO FLAGS ****" >> $LOG

make clean
CFLAGS=-Wall ./configure

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
	exit
        fi

make 2>> $LOG

if [ "$?" != "0" ] 
	then
	echo "Error on standard build!";
	exit
	fi

echo "**** ALL FLAGS ****"
echo "**** ALL FLAGS ****" >> $LOG

make clean
CFLAGS=-Wall ./configure $ALLFLAGS

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on standard build!";
	exit
        fi

echo "****  NO FLAGS ****"
echo "****  NO FLAGS ****" >> $LOG

make clean
CFLAGS=-Wall ./configure $NOFLAG

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on standard build!";
	exit
        fi

for I in $STANDARD
do

make clean

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make 2>> $LOG

if [ "$?" != "0" ] 
        then
        echo "Error on with $I";
	exit
        fi
done

for I in $ALLFLAGS
do

make clean

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make 2>> $LOG

if [ "$?" != "0" ]
        then
        echo "Error on with $I";
	exit
        fi
done

for I in $NOFLAGS
do

make clean

echo "**** FLAGS $I *****"
echo "**** FLAGS $I *****" >> $LOG

CFLAGS=-Wall ./configure $I

if [ "$?" != "0" ]
        then
        echo "./configure failed!";
        exit
        fi

make 2>> $LOG

if [ "$?" != "0" ]
        then
        echo "Error on with $I";
	exit
        fi
done

