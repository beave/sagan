Installation
============

Before Sagan can be used it has to be installed. Sagan can be installed
on various distributions using binary packages;  however,  these are typically out 
of date.  Check your distribution to verify if the latest version of Sagan is 
available. 

For people familiar with compiling their own software, the Source method is
recommended.

libpcre (Regular Expressions)
-----------------------------

Sagan uses ``libpcre`` to use 'Perl Compatible Regular Expressions`.  This is used in many
Sagan signatures and is a required dependency.

To install ``libpcre`` on Debian/Ubuntu:

.. option:: sudo apt-get install libpcre3-dev libpcre3

To install ``libpcre`` on Redhat/CentOS:

.. option:: sudo yum install pcre-devel

To install ``libpcre`` on FreeBSD/OpenBSD:

.. option:: cd /usr/ports/devel/pcre && make && sudo make install

To install ``libpcre`` on Gentoo:

.. option:: emerge -av libpcre

libyaml (YAML configuration files)
----------------------------------

Sagan uses ``libyaml`` to read in configurations files.  This is a required dependency.

To install ``lbyaml`` on Debian/Ubuntue:

.. option:: apt-get install libyaml-dev

To install ``libyaml`` on Redhat/CentOS:

.. option:: yum install libyaml-devel

To install ``libyaml`` on FreeBSD/OpenBSD:

.. option:: cd /usr/ports/textproc/libyaml/ && sudo make install

To install ``libyaml`` on Gentoo:

.. option:: emerge -av libyaml


Other dependencies
------------------

While ``libpcre`` and ``libyaml`` are required Sagan dependencies,  you'll likely want Sagan to perform 
other functions like parsing JSON data or writing data out in various formats.  While these 
prerequisites are not required,  you should look them over for further functionality. 

liblognorm (Normalization)
--------------------------

While not a required dependency,  it is recommended that you install liblognorm.  This library can be
used by Sagan to extract useful data from incoming log data.  ``liblognorm`` is part of the ``rsyslog``
daemon.  Note:  Installing ``liblognorm`` will automatically install ``libfastjson``. 

More information about ``liblognorm`` can be found at the `LibLogNorm <https://FIXME`>_ web site. 

To install ``liblognorm`` on Debian/Ubuntu:

.. option:: apt-get install liblognorm-dev liblognorm2

To install ``liblognorm`` on Redhat/Centos:

.. option:: yum install liblognorm

To build ``liblognorm`` from source code,  see ADD THIS IN

libfastjson (JSON)
------------------

If you install ``liblognorm``,  you do not need to install ``libfastjson`` as it is part of the ``liblognorm``
package.  The library is a fork of ``json-c`` by the ``rsyslog`` team.  It has improvements which make 
parsing and building JSON data faster and more efficent. 

To install ``libfastjson`` on Debian/Ubuntu:

.. option:: LOOK THIS UP

To install ``liblfastjson`` on Redhat/Centos:

.. option:: LOOK THIS UP

To install ``libfastjson`` on FreeBSD/OpenBSD:

.. option:: LOOK THIS UP

To install ``libjson`` on Gentoo:

.. option::  LOOK THIS UP

To build ``libjson`` from source code,  see ADD THIS IN

libdnet (Unified2)
------------------

If you want Sagan to write in the Snort ``unified2`` output format,  you'll need to install ``libdnet``. 
This allows you to use Sagan in conjuction with software like ``Barnyard2``.  **This is not recommended**. 
Consider using Sagan's JSON / EVE output and software like `Meer <https://meer.readthedocs.org>`_ or 
putting data into Elasticsearch. 

To install ``libdnet`` on Debian/Ubuntu:

.. option:: apt-get install libdumbnet1 libdumbnet-dev

To install ``libdnet`` on FreeBSD/OpenBSD:

.. option:: cd /usr/ports/net/libdnet && make && sudo make install

To install ``libdnet`` on Gentoo:

.. option:: emerge -av libdnet

To build ``libdnet`` from source code,  see ADD THIS IN


libesmtp (SMTP)
---------------

Sagan has the ability as an ``output-plugin`` to send alerts via e-mail.  If you would like this type
of functionality,  you will need to install ``libesmtp``.  

To install ``libesmtp`` on Debian/Ubuntu:

.. option:: apt-get install libesmtp-dev

To install ``libesmtp`` on FreeBSD/OpenBSD:

.. option:: cd /usr/ports/mail/libesmtp && make && sudo make install

To install ``libesmtp`` on Gentoo:

.. option:: emerge -av libesmtp


libmaxminddb (GeoIP)
--------------------

Sagan can do GeoIP lookups of Internet Addresses.  Rules that use this functionality are part of the
``-geoip.rules`` rule sets.  While not required,  the data can be very useful.  

To install ``libmaxminddb`` on Debian/Ubuntu:

.. option:: apt-get install libmaxminddb0 libmaxminddb-dev geoip-database-contrib geoipupdate 

To install ``libmaxminddb`` on Redhat/CentOS:

.. option:: yum install GeoIP GeoIP-devel GeoIP-data

From time to time you will need to update your `MaxMind GeoIP Lite Databases <https://dev.maxmind.com/geoip/geoip2/geolite2/>`_ .  Typcially,  you'll need to do something like this:

Basic Maxmind GeoIP2 Country Code updates::

   cd /usr/local/share/GeoIP2
   sudo wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
   sudo gzip -d GeoLite2-Country.tar.gz


hiredis (Redis)
---------------

Sagan has the ability to store ``flexbit`` data in a `Redis <https://redis.oi>`_ database.  This allows data
to be shared over a distributed enviornment.  **This feature is considered beta**.  To use this functionality
you will need to install the ``hiredis`` library.

To install ``hiredis`` on Debian/Ubuntu:

.. option:: apt-get install libhiredis-dev

To install ``hiredis`` on Redhat/CentOS:

.. option:: sudo yum install redis

To install ``hiredis`` from source,  see the `Hiredis Github Page <https://github.com/redis/hiredis>`_ . 


libpcap (Sniffing logs)
-----------------------

By using the ``libpcap`` library,  Sagan has the ability to 'sniff' unencrypted logs 'off the wire' and 
process them.  This can be useful for capturing logs in transit to a centralized log server.   It can also
be useful for testing Sagan's effectiveness before doing a full deployment.   You will need a method to
'capture' the traffic off the wire.  This is typically done via a ``span`` port or a ``network tap``.

To install ``libpcap`` on Debian/Ubuntu:

.. option:: apt-get install libpcap-dev

To install ``libpcap`` on Redhat/CentOS:

.. option:: yum install libpcap

To install ``libpcap`` on Gentoo:

.. option:: emerge -av libpcap


Compiling Sagan
===============

Installation from source distributions files.

Basic steps::

    git clone https://github.com/beave/sagan
    cd sagan
    ./autogen.sh
    ./configure
    make
    sudo make install

By default,  Sagan builds with the ``--enable-lognorm`` (See ``liblognorm`` above) option enabled.  Any 
other options need to be manually enabled or disabled.

Quick start from source
-----------------------

The first example installs Sagan with the basics (all prerequisites and ``liblognorm``).

Quick start with the bare basics::

   sudo apt-get install libpcre3-dev libpcre3 libyaml-dev liblognorm-dev
   wget https://quadrantsec.com/download/sagan-current.tar.gz
   cd sagan-1.2.1
   ./configure
   make
   sudo make install


This example Quick start installs Sagan with more features including the required prerequisites, 
``libognorm`` (log normalization), ``libesmtp`` (e-mail support), ``libmaxminddb`` (GeoIP), 
``hiredis`` (Redis), ``libpcap`` (sniffing logs). 

A more complete quick start
---------------------------

This example installs Sagan with the most common and useful prerequisites.

A more complete quick start::

   sudo apt-get install libpcre3-dev libpcre3 libyaml-dev liblognorm-dev libesmtp-dev libmaxminddb0 libmaxminddb-dev libhiredis-dev libpcap-dev liblognorm-dev libfastjson-dev libestr-dev
   wget https://quadrantsec.com/download/sagan-current.tar.gz
   cd sagan-1.2.1
   ./configure --enable-geoip --enable-esmtp --enable--libpcap --enable-redis
   make
   sudo make install
   

Prerequisites
-------------

Before compiling and installing Sagan,  your system will need some supporting libraries 
installed.  The primary prerequisites are ``libpcre``, ``libyaml`` and ``libpthreads`` (note: most systems
have ``libpthread`` installed by default).  While there are no other required dependencies other than 
these,  you should look over the others for expanded functionality.  For example,  ``liblognorm`` **is not required but highly recommended**.


Common configure options
------------------------

.. option:: --prefix=/usr/

    Installs the Sagan binary in the /usr/bin. The default is ``/usr/local/bin``.

.. option:: --sysconfdir=/etc

    Installs the Meer configuration file (meer.yaml) in the /etc directory.  The default is ``/usr/local/etc/``.

.. option:: --with-libyaml_libraries

   This option points Sagan to where the libyaml files reside.

.. option:: --with-libyaml-includes

   This option points Sagan  to where the libyaml header files reside.

.. option:: --disable-snortsam

   This option disables `Snortsam <http://www.snortsam.net/>_` support.  Snortsam is a firewall blocking
   agent for Snort.

.. option:: --enable-esmtp

   This option enabled Sagan's ability to send data and alerts via e-mail.  In order to use this functionality,
   you will need ``libesmtp`` support (see above).

.. option:: --with-esmtp-includes=DIR

   This points ``configure`` to the libesmtp header files (see ``--enable-esmtp``).

.. option:: --with-esmtp-libraries=DIR

   This points ``configure`` to the library location of ``libesmtp`` (see ``--enable-esmtp``).

.. option:: --enable-geoip

   This option allows Sagan to do GeoIP lookups of TCP/IP addresses via the `Maxmind GeoIP2 Lite <https://dev.maxmind.com/geoip/geoip2/geolite2/>`_ to determine countries of origin or destination.

.. option:: --with-geoip-includes=DIR

   This points ``configure`` to the Maxmind GeoIP header data (see ``--enable-geoip``).

.. option:: --with-geoip-libraries=DIR

   This points ``configure`` to the Maxmind GeoIP library location (see ``--enable-geoip``).

.. option:: --disable-syslog

   By default,  Sagan can send alerts to syslog.  This option disables this feature.

.. option:: --enable-system-strstr

   By default,  Sagan uses a built in assembly version of the C function ``strstr()`` for rule ``content``
   checks.  This code is CPU specific and may cause issues on non-x86 hardware.  This option disables
   Sagans built in ``strstr`` and uses the default operating system's ``strstr``.  This option is 
   useful when building Sagan on embedded systems. 

.. option:: --enable-redis

   Sagan has the ability to store ``flexbits`` in a Redis database.  This option enables this Redis feature.
   You need the ``libhiredis`` library installed (see ``libhiredis`` above).

.. option:: --disable-lognorm

   Sagan uses ``liblognorm`` to 'normalize' log data.  This disables that feature. 

.. option:: --with-lognorm-includes=DIR

   Points ``configure`` to the liblognorm header files.

.. option:: --with-lognorm-libraries=DIR 

   Points ``configure`` to the liblognorm library.

.. option:: --enable-libpcap

   This option enables Sagan to 'sniff' logs off the network.  The ``libpcap`` library needs to be 
   installed (see ``libpcap`` above).

.. option:: --with-libpcap-includes=DIR

   Points ``configure`` to the ``libpcap`` header files.

.. option:: --with-libpcap-libraries=DIR

   Points ``configure`` to the  ``libpcap`` library directory (see ``libpcap`` above).

.. option:: --enable-libdnet

   This allows Sagan to write alert data in a ``unified2`` output format.  To use this option,  the system
   will need ``libdnet`` installed (see ``libdnet`` above).

.. option:: --with-libdnet-includes=DIR

   Points ``configure`` to the ``libdnet`` headers (see ``libdnet`` above).

.. option:: --with-libdnet-libraries=DIR

   Points ``configure`` to the ``libdnet`` library files (see ``libdnet`` above).

.. option:: --disable-libfastjson

   This option disables processing and producting JSON output.  Note: Using ``liblognorm`` automatically
   enables this feature.  **You probably don't want to do with**

.. option:: --with-libfastjson-includes=DIR

   Points ``configure`` to the ``libfastjson`` header files.

.. option:: --with-libfastjson-libraries=DIR

   Points ``configure`` to the ``libfastjson`` library directory.

.. option:: --enable-bluedot

   Bluedot is <Quadrant Information Security's <https://quadrantsec.com>`_ 'Threat Intelligence' plateform.
   This allows Sagan to perform lookups of TCP/IP addresses,  file hashes,  etc.  **Note:  You likely
   do not need this option as the API is not publically available at this time**.

.. option:: --with-libpthread-includes=DIR

   Points ``configure`` to the ``libpthread`` header files.

.. option:: --with-libpthread-libraries=DIR

   Points ``configure`` to the ``libpthread`` library directory.

.. option:: --with-libyaml-includes=DIR

   Points ``configure`` to the ``libyaml`` header files.

.. option:: --with-libyaml-libraries=DIR

   Points ``configure`` to the ``libyaml`` library directory.

.. option:: --with-libpcre-includes=DIR

   Points ``configure`` to the ``libpcre`` header files.

.. option:: --with-libpcre-libraries=DIR

   Points ``configure`` to the ``libpcre`` library directory.

