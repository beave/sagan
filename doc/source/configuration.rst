Syslog Configuration
====================

Sagan typically receives its data from a third party daemon.  This is typically something like 
``rsyslog``, ``syslog-ng`` or ``nxlog``.  The first step is to get one of those systems setup. 


rsyslog
-------



syslog-ng
---------



nxlog
-----



other sources
-------------


Sagan Configuration
===================

The primary Sagan configuration file is ``sagan.yaml``.  Its default location is the ``/usr/local/etc``
directory.  

Comments within the ``sagan.yaml`` file start with a '#'.  Stand alone comments (on lines of there own)
and comments after statements are valid.

The ``sagan.yaml`` is broken up in several parts.  Those parts are ``vars``, ``sagan-core``, ``processors``,
``outputs`` and ``rule-files``. 

vars
====

The ``var`` section of the ``sagan.yaml`` is a place reserved for declaring variables for the Sagan
system to use.  Using variables can be useful when you have multiple rules that use semi dynamic content.
For example,  lets say you have signature that looks for a combination of users.  In the ``vars`` area, 
you might setup a variable like this::

   USERSNAME "bob, frank, mary, david"

Within a signature,  you would then reference ``$USERNAME`` to have access to the values in that variable. 
If at a later date you wish to add or remove values from that variable,  all signatures will adopt the 
new variables values. 

Variables can also be used within the ``sagan.yaml`` file.  For example,  when you set the ``RULE_PATH``
variable, if can be used within signatures but also within the ``sagan.yaml``.  By doing this,  it allows
you one location to make changes across multiple configurations options or signatures.


The ``vars`` section os the ``sagan.yaml`` is broken into subsections.  These subsections are
``sagan-groups``, ``address-groups``, ``port-groups``,  ``geoip-groups``, ``aetas-groups``, 
``mmap-groups``, ``misc-groups``.   Each group has it's own purpose and function. 
In the majority of cases,  if you want to define variables of your own,  you would put them in the
``misc-groups`` subsection.


sagan-groups
~~~~~~~~~~~~

The ``sagan-groups`` section is reserved for core Sagan function.  For example,  where to store
lock files,  where the FIFO (named pipe) is located for Sagan to read data from, where to store logs, 
etc. 

Example ``sagan-groups`` subsection::

   vars:

      # 'Core' variables used by Sagan.

      sagan-groups:

        FIFO: "/var/sagan/fifo/sagan.fifo"
        RULE_PATH: "/usr/local/etc/sagan-rules"
        LOCKFILE: "/var/run/sagan/sagan.pid"
        LOG_PATH: "/var/log/sagan"


address-groups
~~~~~~~~~~~~~~

The ``address-groups`` is an area to define your network.  This is where you define values like
``$HOME_NETWORK`` and ``$EXTERNAL_NETWORK``.  In the majority of cases,  you'll likely want to 
leave these ``any`` and ``any``.  You can create your own separate network groups here.  For example, 
you could create a new variable ``INTERNAL_NETWORK``.   Addresses in this group are in the standard
CIDR network notation.  For example::

   INTERNAL_NETWORK [10.0.0.0/8, 192.168.0.0/16]

Example ``address-groups`` subsection::


     # HOME_NET and EXTERNAL_NET function similar to Suricata/Snort.  However, 
     # it's rare you'll want to set them.  In most situations leaving it set
     # to "any" is best. 

     address-groups:

        HOME_NET: "any"
        EXTERNAL_NET: "any"


port-groups
~~~~~~~~~~~

The ``port-groups`` is an area to define common ports and protocols.  This section allows you to 
tailor ports used within your organization.  For example,  you might run SSH port TCP port 2222 rather
than port 22.  If you modified the variable in this section,  it will be adopted by the rest of the
rules.

Example ``port-groups`` subsection::

     # Common ports used by common protocols.  These variables are used by 
     # rule sets. 

     port-groups:

       SSH_PORT: 22
       HTTP_PORT: 80
       HTTPS_PORT: 443
       TELNET_PORT: 23
       DNS_PORT: 53
       SNMP_PORT: 161
       POP3_PORT: 110
       IMAP_PORT: 143
       SMTP_PORT: 25
       MYSQL_PORT: 3306
       MSSQL_PORT: 1433
       NTP_PORT: 123
       OPENVPN_PORT: 1194
       PPTP_PORT: 1723
       FTP_PORT: 21
       RSYNC_PORT: 873
       SQUID_PORT: 3128

geoip-groups
~~~~~~~~~~~~

The ``geoip-groups`` relate to the ``*-geoip.rules`` sets.  This allows you to set your organizations 
locations.  The ``*-geoip.rules`` can then monitor for usage within your network from outside of your 
``HONE_COUNTRY``. 

Example ``geoip-groups`` subsection::

     # If you are using the -geoip rule sets & Sagan is compile with Maxmind 
     # GeoIP2 support (https://github.com/maxmind/libmaxminddb/releases), 
     # you'll want to define your $HOME_COUNTRY. ISO GeoIP country codes can
     # be found at http://dev.maxmind.com/geoip/legacy/codes/iso3166/

     geoip-groups:

        HOME_COUNTRY: "US,CA"


aetas-groups
~~~~~~~~~~~~

The ``aetas-groups`` relate to the ``*-aetas.rules`` sets.  This allows you to define your organizations
normal "work" hours.   The ``*-aetas.rules`` can then monitor network usage and tool usage at defined 
hours of the day.

Example ``aetas-groups`` subsection::

     # If you want to use -aetas, also know as time based rule sets,  you'll
     # want to define the $SAGAN_HOURS and $SAGAN_DAYS variables. $SAGAN_HOURS is
     # considered "normal" hours in a 24 hour clock format from "start time" to 
     # "end time".  $SAGAN_DAYS is the day of the week (0 == Sunday -> 
     # Saturday).  For more information,  see: 

     aetas-groups:

       SAGAN_HOURS: "0700-1800"
       SAGAN_DAYS: "12345"

mmap-groups
~~~~~~~~~~~

The ``mmap-groups`` allow you to set variables used later in the ``sagan.yaml`` to set storage sizes 
for ``mmap()`` files.  These variables are used later in the ``sagan-core`` section.

Example ``mmap-groups`` subsection::


     # Variable for the max number of entries Sagan will retain via IPC. 

     mmap-groups:

       MMAP_DEFAULT: 10000


misc-groups
~~~~~~~~~~~

The ``misc-groups`` is a generic area to add variables.   If you want to add a variable to the ``sagan.yaml``
file, this is likely the area you want to add them to.  

Example ``misc-groups`` subsection::


     misc-groups: 
    
       CREDIT_CARD_PREFIXES: "4,34,37,300,301,302,303,304,305,2014,2149,309,36,38,39,54,55,6011,6221,6222, 6223,6224,6225,6226,\ 
                              6227,6228,6229,644,645,646,647,648,649,65,636,637,638,639,22,23,24,25,26,27,51,52,53,53,55"
    
        RFC1918: "10.,192.168.,172.16.,172.17.,172.18.,172.19.,172.20.,172.21.,172.22.,172.23.,172.24.,172.25.,172.26.,172.27.,\
                  172.28.,172.29.,172.30.,172.31."

       # $WINDOWS_DOMAINS is used by some Windows rule sets to determine if a log
       # message contains or does not contain a valid DOMAIN for your organization.
       # For more information, see: 
       #
       # https://quadrantsec.com/about/blog/detecting_pass_the_hash_attacks_with_sagan_in_real_time/

       WINDOWS_DOMAINS: "MYCOMPANYDOMAIN,EXAMPLEDOMAIN,ANOTHER_DOMAIN"

       # Known valid Microsoft PSExec MD5 sums.  Versions v1.98, v2.00, v2.10, v2.11, v2.11 (2016).

       PSEXEC_MD5: "CD23B7C9E0EDEF184930BC8E0CA2264F0608BCB3, 9A46E577206D306D9D2B2AB2F72689E4F5F38FB1,\
                    2EDEEFB431663F20A36A63C853108E083F4DA895,B5C62D79EDA4F7E4B60A9CAA5736A3FDC2F1B27E,\
                    A7F7A0F74C8B48F1699858B3B6C11EDA"


sagan-core
==========

The ``sagan-core`` section defines internal Sagan core functionality.  In this section,  you can 
setup Sagan to receive data in different formats,  how different data parsers work,  tuning and 
other items.   

The ``sagan-core`` is broken into subsections.  They are ``core``, ``parse_ip``, ``selector``, 
``redis-server``, ``mmap-ipc``, ``ignore_list``, ``geoip``, ``liblognorm`` and ``plog``.


core
----

The ``core`` subsection defines and sets some important information in the ``sagan.yaml`` configuration. 
Items like the ``default-host`` are used for when Sagan cannot normalize of find IP addresses it needs. 
The default ``default-port`` and ``default-proto`` are used for similar purposes. 

One important item is the ``max-threads``.   This directly controls how much data Sagan can process 
at any given time.  If you find yourself in a situation where Sagan is dropping logs,  you likely need
to increase this value. 

The ``core`` is also the area where you can point Sagan to external data.  For example,  the ``classifications``
file assigns priorities numbers to different classifications levels.  The ``references`` is a pointer 
to addresses that Sagan can point users to find more information about an alert. 

The ``xbit-storage`` tells Sagan "how" to store xbit information.  In most cases, you'll want to leave this
default (mmap).  

The ``input-type`` tells what format Sagan will receive data via the named PIPE (FIFO).  Traditionally, 
Sagan uses a "pipe" delimited format.   Sagan is increasing moving to a JSON format and the JSON
format will become the default.   See the ``Syslog Configuration`` portion of this document for more
information. 


Example ``core`` subsection::

  core:

    sensor-name: "default_sensor_name"  # Unique name for this sensor (no spaces)
    default-host: 192.168.2.1
    default-port: 514
    default-proto: udp
    dns-warnings: disabled
    source-lookup: disabled
    fifo-size: 1048576          # System must support F_GETPIPE_SZ/F_SETPIPE_SZ. 
    max-threads: 100
    classification: "$RULE_PATH/classification.config"
    reference: "$RULE_PATH/reference.config"
    gen-msg-map: "$RULE_PATH/gen-msg.map"
    protocol-map: "$RULE_PATH/protocol.map"
    xbit-storage: mmap          # xbit storage engine. ("mmap" or "redis")

    # Controls how data is read from the FIFO. The "pipe" setting is the traditional 
    # way Sagan reads in events and is default. "json" is more flexible and 
    # will become the default in the future. If "pipe" is set, "json-map"
    # and "json-software" have no function.

    input-type: pipe                                    # pipe or json
    json-map: /usr/local/etc/sagan-rules/json-input.map # mapping file if input-type: json
    json-software: syslog-ng                            # by "software" type. 

    # "parse-json-message" allows Sagan to detect and decode JSON within a 
    # syslog "message" field.  If a decoder/mapping is found,  then Sagan will
    # extract the JSON values within the messages.  The "parse-json-program"
    # tells Sagan to start looking for JSON within the "program" field.  Some
    # systems (i.e. - Splunk) start JSON within the "program" field and
    # into the "message" field.  This option tells Sagan to "append" the 
    # strings together (program+message) and then decode.  The "json-message-map"
    # tells Sagan how to decode JSON values when they are encountered.

    parse-json-message: disable
    parse-json-program: disable
    json-message-map: /usr/local/etc/sagan-rules/json-message.map



parse_ip
--------

The ``parse_ip`` subsection controls what the Sagan rule keywords ``parse_src_ip`` and ``parse_dst_ip``
function from within rules. 

Example ``parse_ip`` subsection::

     # This controls how the "parse_src_ip" and "parse_dst_ip" function within a rule. 

     parse-ip:
       ipv6: enabled                       # Parse IPv6 Addresses
       ipv4-mapped-ipv6: disabled          # Map ffff::192.168.1.1 back to 192.168.1.1


selector
--------

The ``selector`` can be used in "multi-tenant" environments.  This can be useful if you have multiple
organizational logs going into one named pipe (FIFO) and you wish to apply rule logic on a per 
sensor/organization level.

Example ``selector`` subsection::

     # The "selector" adds "multi-tenancy" into Sagan.  Using the "selector" allows Sagan to 
     # track IP source, IP destinations, etc. in order to ensure overlapping logs from different
     # environments are tracked separately. 

     selector:
       enabled: no
       name: "selector name"        # Log entry must be normalized and this value must 
                                    # be present in the normalized result



redis-server (experimental)
---------------------------

The ``redis-server`` is a beta feature that allows Sagan to store ``xbits`` in a Redis database
rather than a ``mmap()`` file.  This can be useful in sharing ``xbits`` across multiple platforms
within a network. 

Example ``redis-server`` subsection::


     # Redis configuration.  Redis can be used to act as a global storage engine for
     # xbits.  This allows Sagan to "share" xbit data across a network infrastructure. 
     # This is experimental! 

     redis-server:

       enabled: no
       server: 127.0.0.1
       port: 6379
       #password: "mypassword"  # Comment out to disable authentication.
       writer_threads: 10


mmap-ipc
--------

The ``mmacp-ipc`` subsection tells Sagan how much data to store in ``mmap()`` files and where
to store it. 

Example ``mmap-ipc`` subsection::


     # Sagan creates "memory mapped" files to keep track of xbits, thresholds, 
     # and afters.  This allows Sagan to "remember" threshold, xbits and after
     # data between system restarts (including system reboots!). 

     # This also allows Sagan to share information with other Sagan processes.
     # For exampe, if one Sagan instance is monitoring "Linux" logs & another is
     # monitoring "Windows" logs, Sagan can communicate between the two Sagan 
     # processes using these memory mapped files. A "xbit" that is "set" by the
     # "Linux" process accessible and "known" to the Windows instance.

     # The storage is pre-allocated when the memory mapped files are created
     # The values can be increased/decreased by altering the $MMAP_DEFAULT
     # variable. 10,000 entries is the system default.

     mmap-ipc:

       ipc-directory: /var/sagan/ipc
       xbit: $MMAP_DEFAULT
       after: $MMAP_DEFAULT
       threshold: $MMAP_DEFAULT
       track-clients: $MMAP_DEFAULT


ignore_list
-----------

The ``ignore_list`` subsection is a simple short circuit list of keywords.  If Sagan encounters any 
keywords in this list,  it is immediately dropped and not passed through the rest of the 
Sagan engine.  In high throughput environments,  this can save CPU time. 

Example ``ignore_list`` subsection::

     # A "short circuit" list of terms or strings to ignore.  If the the string
     # is found in pre-processing a log message, it will be dropped.  This can
     # be useful when you have log messages repeating without any useful 
     # information & you don't want to burn CPU cycles analyzing them.  Items 
     # that match will be "short circuit" in pre-processing before rules & 
     # processors are applied. 

     ignore_list:

       enabled: no
       ignore_file: "$RULE_PATH/sagan-ignore-list.txt"


geoip
~~~~~

The ``geoip`` subsection where you can configure `Maxminds <https://github.com/maxmind/libmaxminddb/releases>`_ 
GeoIP settings.  This includes enabling GeoIP lookups, where to find the Maxmind data files and
what networks to "skip" GeoIP lookups. 

Example ``geoip`` subsection::

     # Maxmind GeoIP2 support allows Sagan to categorize events by their country
     # code. For example; a rule can be created to track "authentication 
     # successes" & associate the country the successful login came from.  If the
     # successful login is from outside your country code,  via the $HOME_COUNTRY
     # variable, an alert can be generated.  Sagan will need to be compiled with 
     # --enable-geoip2 flag. 
     #
     # Maxmind GeoLite2 Free database:
     # http://dev.maxmind.com/geoip/geoip2/geolite2/
     #
     # Country code (ISO3166): 
     # http://dev.maxmind.com/geoip/legacy/codes/iso3166/
     #
     # More information about Sagan & GeoIP, see: 
     # https://quadrantsec.com/about/blog/detecting_adversary_with_sagan_geoip/

     geoip:

       enabled: no
       country_database: "/usr/local/share/GeoIP2/GeoLite2-Country.mmdb"
       skip_networks: "8.8.8.8/32, 8.8.4.4/32"


liblognorm
----------

``liblognorm`` is a way that Sagan can extract useful information from a log file.  For example, 
``liblognorm`` is used to extract source and destination IP addresses, user names, MAC addresses, etc from 
log data.  This option allows you to enable/disable the ``liblognorm`` functionality and where to load
normalization rulebase files from (see ``normalize_rulebase``).  The ``normalize_rulebase`` is a mapping
file that lets Sagan extract useful information from logs.


More information about ``liblognorm`` can be found in the `Prerequisites` section of the Sagan User Guide
and the the `LibLogNorm <https://FIXME`>_ web site.

Example ``liblognorm`` subsection::


     # Liblognorm is a fast sample-base log normalization library.  Sagan uses
     # this library to rapidly extract useful data (IP address, hashes, etc) from
     # log messages.  While this library is not required it is recommended that 
     # Sagan be built with liblognorm enabled.  For more information, see: 
     #
     # https://wiki.quadrantsec.com/bin/view/Main/LibLogNorm
     #
     # The normalize_rulebase are the samples to use to normalize log messages 
     # Sagan receives. 

     liblognorm:

       enabled: yes
       normalize_rulebase: "$RULE_PATH/normalization.rulebase"



plog
----

The ``plog`` functionality use to "sniff" syslog messages "off the wire".   If you already have 
a centralized syslog server you are sending data,  the data is not encrypted and is UDP,  this option
can be used to "sniff" logs while they are in transit to your centralized logging system.  In order 
to "sniff" the logs,  you will need a "span" port or "tap".  This option can be useful when testing 
Sagan's functionality.  This should not be used in production environments since the robustness of 
"sniffing" varies.


Example ``plog`` subsection::

     # 'plog',  the promiscuous syslog injector, allows Sagan to 'listen' on a
     # network interface and 'suck' UDP syslog message off the wire.  When a 
     # syslog packet is detected, it is injected into /dev/log.  This is based
     # on work by Marcus J. Ranum in 2004 with his permission.  
     #
     # For more information,  please see: 
     #
     # https://raw.githubusercontent.com/beave/sagan/master/src/sagan-plog.c

     plog:

       enabled: no
       interface: eth0
       bpf-filter: "port 514"
       log-device: /dev/log	# Where to inject sniffed logs.
       promiscuous: yes


processors
==========

Sagan ``processors`` are methods of detections outside of the Sagan rule engine.  

track-clients
-------------

rule-tracking
-------------

perfmonitor
-----------

blacklist
---------

bluedot
-------

zeek-intel (formally "bro-inte")
--------------------

dynamic_load
------------



outputs
=======

eve-log
-------

alert
-----

fast
----

unified2
--------

external
--------


smtp
----

snortsam
--------

syslog
------



rule-files
==========


