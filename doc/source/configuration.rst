Syslog Configuration
====================

Sagan typically receives its data from a third party daemon.  This is typically something like 
``rsyslog``, ``syslog-ng`` or ``nxlog``.  The first step is to get one of those systems set up. 


rsyslog
-------

syslog-ng - "pipe" mode
-----------------------

Below is a simple `Syslog-NG <https://www.syslog-ng.com/>`_ configuration to ouput to
Sagan in a legacy "pipe" delimited format.  For more complex configurations,  please consult 
the ``syslog-ng`` documentation.  The Sagan ``input-type`` (set in the ``sagan.yaml``) will
need to be set to ``pipe``.  


Example ``syslog-ng`` "pipe" configuration::

   # Sources of log data. 

   source s_src { system(); internal(); }; 	# Internal 
   source syslog_in { udp(port(514)); };	# UDP port 514

   # A "destination" to send log data to.  In our case, a named pipe (FIFO)

   destination sagan_fifo {
      pipe("/var/sagan/sagan.fifo"
      template("$SOURCEIP|$FACILITY|$PRIORITY|$LEVEL|$TAG|$YEAR-$MONTH-$DAY|$HOUR:$MIN:$SEC|$PROGRAM| $MS
      };

   # This line ties the sources and destinations together.

   log { source(s_src); destination(sagan_fifo); };
   log { source{syslog_in}; destination(sagan_fifo); };



syslog-ng - JSON mode
---------------------

Below is a simple `Syslog-NG <https://www.syslog-ng.com/>`_ configuration to ouput to 
Sagan in a "JSON" format.  For more complex configurations,  please consult 
the ``syslog-ng`` documentation.  The Sagan ``input-type`` (set in the ``sagan.yaml``) will
need to be set to ``json``.  You will also need to set your ``json-software`` to ``syslog-ng``. 

Using the Sagan JSON format allows for more flexibility with the log data and is recommended.

Example ``syslog-ng`` JSON configuration:: 

   # Sources of log data. 

   source s_src { system(); internal(); }; 	# Internal 
   source syslog_in { udp(port(514)); };	# UDP port 514

   # A "destination" to send log data to.  In our case, a named pipe (FIFO)

   destination sagan_fifo {
         pipe("/var/sagan/sagan.fifo"
         template("$(format-json --scope selected_macros --scope nv_pairs)\n"));
         };

   # This line ties the sources and destinations together.

   log { source(s_src); destination(sagan_fifo); };
   log { source{syslog_in}; destination(sagan_fifo); };


nxlog
-----



other sources
-------------


Sagan Configuration
===================

The primary Sagan configuration file is ``sagan.yaml``.  Its default location is the ``/usr/local/etc``
directory.  

Comments within the ``sagan.yaml`` file start with a '#'.  Stand-alone comments (on lines of their own)
and comments after statements are valid.

The ``sagan.yaml`` is broken up in several parts.  Those parts are ``vars``, ``sagan-core``, ``processors``,
``outputs`` and ``rule-files``. 

Sagan with JSON input
---------------------

Sagan reads data from your favorite syslog daemon (rsyslog, syslog-ng, nxlog, etc) via a “named pipe” (also known as a FIFO).  A named pipe operates similarly to a file but with the writer (your syslog daemon) and a reader (Sagan).   Rather than the contents being written to a disk or file,  the data is stored in kernel memory.    This data will wait in kernel memory until a process (Sagan) reads it.   Named pipes (FIFOs) allow for separate processes to communicate with each other.  Since this happens in kernel memory,  the communications is extremely fast.

In order for the writer (syslog daemon) and reader (Sagan) to be able to share data,  there has to be a standard between the two.  Traditionally,  Sagan required the syslog daemon to write data to the file in a very specific format.   This was done by a delimiting the data via the ‘|’ (pipe) symbol.   This format was similar to a CSV file. 

A newer and more flexible way for the writer (syslog daemon) and reader (Sagan) to share data is via JSON.  Many modern day syslog daemons offer a JSON output format.   This is the ideal method of sharing data as it allows the data to be more dynamic. 

Sagan-core configurations for JSON

In the ``sagan-core`` section, in the sub section ``core`` is where you can set the ``input-type``.  There are two valid options.  The legacy ``pipe`` format or ``json``.  If you are using the legacy ``pipe`` format,  as long as both the syslog daemon can write to the named pipe in the proper format (see ``Syslog Configuations``),  there are no other configurations. 

If you want to use the ``input-type`` of ``json``,  you’ll need to specify the mapping type.  Below is an example section of the ``input-type`` ::

    input-type: json                       # pipe or json
    json-map: "$RULE_PATH/json-input.map"  # mapping file if input-type: json
    json-software: syslog-ng               # by "software" type.

The ``json-map`` is a mapping file to assist Sagan in decoding JSON supplied by your syslog daemon.   The ``json-software`` configures Sagan “what” JSON map to use in the ``json-map``. 

For example,  let’s say your syslog daemon is Syslog-NG configured to send JSON to the named pipe (JSON).  The data going into the pipe might look similar to this::

    {"TAGS":".source.s_src","SOURCEIP":"127.0.0.1","SEQNUM":"3341","PROGRAM":"sshd","PRIORITY":"info","PID":"23233","MESSAGE":"Failed password for root from 218.92.0.190 port 34979 ssh2","LEGACY_MSGHDR":"sshd[23233]: ","HOST_FROM":"dev-2","HOST":"dev-2","FACILITY":"auth","DATE":"Apr  3 03:00:46"}

Sagan needs to be able to identify the fields within the Syslog-NG formated JSON data.  Within the ``json-map`` file,  we have this line::

   {"software":"syslog-ng","syslog-source-ip":"SOURCEIP","facility":"FACILITY","level":"PRIORITY","priority":"PRIORITY","time":"DATE","date":"DATE","program":"PROGRAM","message":"MESSAGE"}

This maps the Syslog-NG fields to internal fields for Sagan to understand.  For example,  Sagan expects a “message” field.  Syslog-NG has this field named “MESSAGE”.  This mapping maps “message” = “MESSAGE”.   Sagan’s internal “syslog-source-ip” is mapped the Syslog-NG “SOURCEIP” field,  and so on. 

Take special note of the “software” at the beginning of the JSON input mapping file.  This is the name of the “mapping” which is set in the ``sagan.yaml``.   In our example,  the ``json-software`` field is set to ``syslog-ng``.   The mapping file contains mappings for multiple software types (syslog-ng, rsyslog, nxlog, etc).  The ``json-software`` tells Sagan which mapping you want to use. 

An important field,  similar to “software” is “nested”.  Normally,  most JSON from syslog daemon is flat.  In special cases,  you might find yourself dealing with “nested” JSON data.  In that case, you’ll want Sagan to dig into the nested data to extract the fields you need. 


Sagan JSON variables
~~~~~~~~~~~~~~~~~~~~

.. option:: "software": "{software type}"

    This is the name of the mapping.  This is used in the Sagan YAML ``json-software`` type.

.. option:: "nested": "{yes|no|true|false}

    This configures Sagan to look into nested data (automatically) for values for mappings.

Mappings:
~~~~~~~~~

.. option:: “syslog-source-ip”

    TCP/IP address of where the log originated from.  Typically the syslog server.

.. option:: "facility"

    Syslog facility.

.. option:: "level"

    Syslog level.

.. option:: "priority"

    Syslog priority.

.. option:: "time"

    Syslog timestamp.

.. option:: "date"

    Syslog date.

.. option:: "message"

    Syslog "message" field.  This is the only required option.


vars
====

The ``var`` section of the ``sagan.yaml`` is a place reserved for declaring variables for the Sagan
system to use.  Using variables can be useful when you have multiple rules that use semi dynamic content.
For example,  let's say you have a signature that looks for a combination of users.  In the ``vars`` area, 
you might set up a variable like this::

   USERSNAME "bob, frank, mary, david"

Within a signature,  you would then reference ``$USERNAME`` to have access to the values in that variable. 
If at a later date you wish to add or remove values from that variable,  all signatures will adopt the 
new variable's values. 

Variables can also be used within the ``sagan.yaml`` file.  For example,  when you set the ``RULE_PATH``
variable, it can be used within signatures but also within the ``sagan.yaml``.  By doing this,  it allows
you one location to make changes across multiple configuration options or signatures.


The ``vars`` section of the ``sagan.yaml`` is broken into subsections.  These subsections are
``sagan-groups``, ``address-groups``, ``port-groups``,  ``geoip-groups``, ``aetas-groups``, 
``mmap-groups``, ``misc-groups``.   Each group has its own purpose and function. 
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

The ``geoip-groups`` relate to the ``*-geoip.rules`` sets.  This allows you to set your organization's 
locations.  The ``*-geoip.rules`` can then monitor for usage within your network from outside of your 
``HOME_COUNTRY``. 

Example ``geoip-groups`` subsection::

     # If you are using the -geoip rule sets & Sagan is compile with Maxmind 
     # GeoIP2 support (https://github.com/maxmind/libmaxminddb/releases), 
     # you'll want to define your $HOME_COUNTRY. ISO GeoIP country codes can
     # be found at http://dev.maxmind.com/geoip/legacy/codes/iso3166/

     geoip-groups:

        HOME_COUNTRY: "US,CA"


aetas-groups
~~~~~~~~~~~~

The ``aetas-groups`` relate to the ``*-aetas.rules`` sets.  This allows you to define your organization's
normal "work" hours.   The ``*-aetas.rules`` can then monitor network usage and tool usage at defined 
hours of the day.

Example ``aetas-groups`` subsection::

     # If you want to use -aetas, also known as time based rule sets,  you'll
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
Items like the ``default-host`` are used for when Sagan cannot normalize or find IP addresses it needs. 
The default ``default-port`` and ``default-proto`` are used for similar purposes. 

One important item is the ``max-threads``.   This directly controls how much data Sagan can process 
at any given time.  If you find yourself in a situation where Sagan is dropping logs,  you likely need
to increase this value. 

The ``core`` is also the area where you can point Sagan to external data.  For example,  the ``classifications``
file assigns priority numbers to different classification levels.  The ``references`` is a pointer 
to addresses that Sagan can point users to find more information about an alert. 

The ``flexbit-storage`` tells Sagan "how" to store flexbit information.  In most cases, you'll want to leave this
default (mmap).  

The ``input-type`` tells what format Sagan will receive data via the named PIPE (FIFO).  Traditionally, 
Sagan uses a "pipe" delimited format.   Sagan is increasingly moving to a JSON format and the JSON
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
    flexbit-storage: mmap          # flexbit storage engine. ("mmap" or "redis")
    xbit-storage: mmap             # xbit storage engine. ("mmap" or "redis")

    # Sagan can sends logs in "batches" for performance reasons. In most 
    # environments, you'll likely want to set this to 10.  For more busy
    # environments you may want to set this to 100.  This should allow Sagan
    # to comfortably process up to 5k events per/second (EPS).  If you are 
    # looking at rates higher than 5k EPS,  please read:
    #
    # https://sagan.readthedocs.io/en/latest/high-performance.html
    #
    # The default setting is 1 which doesn't lead to the best performance. 
    # If you get more than 10 events per/second,  you might want to increase
    # the batch-size to 10.

    batch-size: 1

    # Controls how data is read from the FIFO. The "pipe" setting is the traditional 
    # way Sagan reads in events and is the default. "json" is more flexible and 
    # will become the default in the future. If "pipe" is set, "json-map"
    # and "json-software" have no function.

    input-type: pipe                          # pipe or json
    json-map: "$RULE_PATH/json-input.map"     # mapping file if input-type: json
    json-software: syslog-ng                  # by "software" type. 

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
    json-message-map: "$RULE_PATH/json-message.map"


sensor-name
~~~~~~~~~~~~

The ``sensor-name`` is a unique human readable name of the Sagan instances.  This is used
to identify data sources.  For example,  Sagan can write ``flexbits`` to a shared database.  The
``sensor-name`` can help identify which Sagan instance wrote which ``flexbit``.

default-host
~~~~~~~~~~~~

The ``default-host`` is the TCP/IP address of the Sagan system.  This is used in cases where
Sagan is unable to normalize data.  Set this to your local IP addess.

default-port
~~~~~~~~~~~~

The ``default-port`` is used when Sagan cannot normalize the destination port from a log message.
When that happens,  this value is used.

default-proto
~~~~~~~~~~~~~

The ``default-proto`` is the default protocol Sagan uses when the protocol cannot be normalized 
from a log message.  Valid types are ``udp``, ``tcp` and ``icmp``.

dns-warnings
~~~~~~~~~~~~

If Sagan receives a hostname rather than an IP address from a syslog server,  Sagan has the ability
to do an "A record" lookup.  If Sagan is unable to do a DNS lookup,  it will emit a DNS warning
message.  The ``dns-warnings`` option disables those warnings.  The ``source-lookup`` option must
be enabled for this to have any effect.  By default, this option is disabled.

source-lookup
~~~~~~~~~~~~~

If enabled,  the ``source-lookup`` option will force Sagan to do a DNS A record lookup when it 
encounters a hostname rather than an IP address.  Sagan performs some internal DNS caching but 
there is a performance penalty when this option is enabled.  Also see ``dns-warnings``.  This
option is disabled by default.

fifo-size
~~~~~~~~~

The ``fifo-size`` lets Sagan adjust the size of the named pipe (FIFO).  The named pipe is how Sagan gets
logs from syslog daemons like ``rsyslog``, ``syslog-ng`` and ``nxlog``.  By default,  most systems
set the named pipe size at 63356 bytes.  For performance reasons,  we set the named pipe to the
largest size possible.  That size is 1048576 bytes, which is what Sagan defaults to.  Valid values
are 65536, 131072, 262144, 524288 and 1048576.

max-threads
~~~~~~~~~~~

The ``max-threads`` allows you to adjust how many worker threads Sagan spawns.  Threads are 
what do the bulk of the log and data analysis work.  Threads are used for CPU intensive analysis
along with high latency operations.  The busier the system is,  the more threads you will need. 
Threads are also dependent on the type of ``processors`` enabled.  Some ``processors``, such as
threat intelligence lookups require more time to complete.  These require idle threads to do those
lookups.  The proper number of threads is largely dependent on several factors.  Start at 100 and
monitor the system's performance.  While running Sagan in the foreground,  monitor the 
``Thread Exhaustion`` statistics.  This will let you know if Sagan is running out of threads.  If
this number goes up,  increase the number of threads available to Sagan.  The default ``max-threads`` is set to 100.  

classification
~~~~~~~~~~~~~~

This points Sagan to the ``classications.config``.  The ``classifications.config`` is a file
that maps classification types (ie - "attempted recon") to a priority level (ie - "1").  This 
data is used in rules via the ``classtype`` keyword.  

https://github.com/beave/sagan-rules/blob/master/classification.config

gen-msg-map
~~~~~~~~~~~

The ``gen-msg-map`` is used to point ``processors`` to their "generator id".  The Sagan engine
uses an ID of "1".  This file is used to assign other ``processors`` other IDs. 

https://github.com/beave/sagan-rules/blob/master/gen-msg.map

reference
~~~~~~~~~

The ``reference`` option points Sagan to where the ``reference.config`` file is located on the 
file system.  This file is used with the ``reference`` rule keyword.  

https://github.com/beave/sagan-rules/blob/master/reference.config

protocol-map
~~~~~~~~~~~~

The ``protocol-map`` is a simple method that Sagan can use to assign a TCP/IP protocol to a 
log message.  The ``protocol-map`` contains either keywords to search for within a log "message"
or within a "program" field.  For example,  if Sagan sees that the program "sshd" is in use,  it 
will assign a TCP/IP protocol of TCP because the protocol SSH uses SSH.  Another example might
be a router log that contains the term "TCP" or "icmp" in it.  Sagan will "see" this and assign
the protocol within the log message internally.  The ``protocol-map`` is used by the ``parse_proto``
rule keyword.

https://github.com/beave/sagan-rules/blob/master/protocol.map

flexbit-storage
~~~~~~~~~~~~~~~

The ``flexbit-storage`` tells Sagan how to store ``flexbit`` data.  The default is ``mmap`` (memory 
mapped files).  Sagan can also store flexbit data in a `Redis <https://redis.io>`_ database.  To use
the Redis value,  Sagan will need to be compiled with ``hiredis`` support.

xbit-storage
~~~~~~~~~~~~

The ``xbit-storage`` tells Sagan how to store ``xbit`` data.  The default is ``mmap`` (memory 
mapped files).  Sagan can also store xbit data in a `Redis <https://redis.io>`_ database.  To use
the Redis value,  Sagan will need to be compiled with ``hiredis`` support.


batch-size
~~~~~~~~~~

The ``batch-size`` option lets you set how much data can be passed from Sagan's master/main thread
to "worker" threads (set by ``max-threads``).  This option can be very important in performance
tuning in high data processing environments.  The number specified in this option represents 
how many "log lines" will be passed.  By default,  it is set to 1.  This means every time that
Sagan gets a log line,  it will pass it to a worker threads.  This isn't very efficient and there
is a performance penalty.  If you are in an environment where you expect to process more
than 10 events per/second (10 EPS),  consider bumping this up to 10 or even the max of 100.  If you
are processing 50k EPS or more,  see the "High Performance Considerations" of this document. 

input-type
~~~~~~~~~~

The ``input-type`` tells Sagan how to decode data it receives from the named pipe.  There are 
two option; ``pipe`` or ``json``.  The ``pipe`` format is a legacy Sagan format.  Data is 
received in the named pipe in a CSV format seperated by the '|' symbol.  The newer ``json``
option tells Sagan to decode the data from the named pipe in a JSON format.  When using the
``json``, you will also need to set the ``json-map`` and ``json-software``. If you are using
the ``pipe`` value,  no other options are needed.  To use the ``json`` option, 
Sagan will need to be compiled with the ``libfastjson`` or ``liblognorm``.

json-map
~~~~~~~~

The ``json-map`` works in conjuction with the ``input-type`` of ``json``.  The ``json-nap``
tells Sagan where to load a mapping table of different software types (ie - ``rsyslog``, 
``syslog-ng``, etc) and their associated JSON decode mappings.  The data in this file is
used with the ``json-software`` option to tell Sagan how do decode incoming JSON data from the
named pipe.  To use the ``json-map`` option, Sagan will need to be compiled with the 
``libfastjson`` or ``liblognorm``.

https://github.com/beave/sagan-rules/blob/master/json-input.map

json-sofware
~~~~~~~~~~~~

The ``json-software`` tells Sagan which "map" to use from the ``json-map`` file that has been
loaded.  This mapping tells Sagan how to decode JSON data from the named pipe.
 To use the ``json-software`` option,   Sagan will need to be compiled with the ``libfastjson`` or ``liblognorm``.

parse-json-message:
~~~~~~~~~~~~~~~~~~~

The ``parse-json-message`` allows Sagan to automatically detect and decode JSON data within a "message"
field of a log line.  The option is used in conjuction with ``parse-message-map`` and requires that
Sagan be compiled with ``libfastjson`` or ``liblognorm`` support.

parse-json-program:
~~~~~~~~~~~~~~~~~~~

The ``parse-json-program`` allows Sagan to detect JSON that starts within the "program" section of a
log message.  In certain situations,  some systems start JSON within the "program" field rather
than within the "message" field.  When this happens,  Sagan detects it and joins the "program" and 
"message" fields together (as one data source).  Once that is done,  the data can be decoded.  This
option is used in conjunction with ``parse-message-map`` and requires that Sagan be compiled with 
``libfastjson`` or ``liblognorm`` support.

json-message-map:
~~~~~~~~~~~~~~~~~

The ``json-message-map`` logs a mapping table for use with ``parse-json-message`` and
``parse-json-program``.  When Sagan detects JSON via ``parse-json-message`` and/or via 
``parse-json-program``,  it will attempt to apply mappings from this file.   The "best mapping"
wins.  That is,  the mapping with the most fields identified will "win" and Sagan will use that
mapping with the log message.   This can be useful for directly processing Suricata EVE logs and
Splunk forwarded logs.

https://github.com/beave/sagan-rules/blob/master/json-input.map


parse_ip
--------

The ``parse_ip`` subsection controls how the Sagan rule keywords ``parse_src_ip`` and ``parse_dst_ip``
function from within rules.  The ``ipv4-mapped-ipv6`` determines how Sagan will work with 
IPv4 addresses mapped as IPv6. 	If ``ipv4-mapped-ipv6`` is enabled,  Sagan will re-write 
IPv6 mapped addresses (for example ffff::192.168.1.1) to normal IPv4 notation (192.168.1.1). 

Example ``parse_ip`` subsection::

     # This controls how "parse_src_ip" and "parse_dst_ip" function within a rule. 

     parse-ip:
       ipv6: enabled                       # Parse IPv6 Addresses
       ipv4-mapped-ipv6: disabled          # Map ffff::192.168.1.1 back to 192.168.1.1


selector
--------

The ``selector`` can be used in "multi-tenant" environments.  This can be useful if you have multiple
organizational logs going into one named pipe (FIFO) and you wish to apply rule logic on a per 
sensor/organization level.  The ``name`` is the keyword that identifies the ``selector``. 

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

The ``redis-server`` is a beta feature that allows Sagan to store ``flexbits`` in a Redis database
rather than a ``mmap()`` file.  This can be useful in sharing ``flexbits`` across multiple platforms
within a network.  The ``server`` is the network address of your Redis server.  The ``port`` is 
the network port address of the Redis server.  The ``password`` is the Redis server's password.
The ``writer_threads`` is how many Redis write threads Sagan should spawn to deal with Redis write operations. 

Example ``redis-server`` subsection::


     # Redis configuration.  Redis can be used to act as a global storage engine for
     # flexbits.  This allows Sagan to "share" flexbit data across a network infrastructure. 
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
to store it.  The ``ipc-directory`` is where Sagan should store ``mmap()`` file.  This is set to
``/dev/shm`` by default.  On Linux systems ``/dev/shm`` is a ram drive.  If you want to store
``mmap()`` files in a more permanent location,  change the ``ipc-directory``.   Keep in mind, 
this may affect ``mmap()`` performance.  The ``flexbit``, ``after``, ``threshold`` and ``track-clients``
are the max items that can be stored in ``mmap()``.  This typically defaults to 10,000 via the
``$MMAP_DEFAULT`` variable.

Example ``mmap-ipc`` subsection::


     # Sagan creates "memory mapped" files to keep track of flexbits, thresholds, 
     # and afters.  This allows Sagan to "remember" threshold, flexbits and after
     # data between system restarts (including system reboots!). 

     # This also allows Sagan to share information with other Sagan processes.
     # For exampe, if one Sagan instance is monitoring "Linux" logs & another is
     # monitoring "Windows" logs, Sagan can communicate between the two Sagan 
     # processes using these memory mapped files. A "flexbit" that is "set" by the
     # "Linux" process is accessible and "known" to the Windows instance.

     # The storage is pre-allocated when the memory mapped files are created
     # The values can be increased/decreased by altering the $MMAP_DEFAULT
     # variable. 10,000 entries is the system default.

     # The default ipc-directory is /dev/shm (ram drive) for performance reasons.

     mmap-ipc:

       ipc-directory: /dev/shm
       flexbit: $MMAP_DEFAULT
       after: $MMAP_DEFAULT
       threshold: $MMAP_DEFAULT
       track-clients: $MMAP_DEFAULT


ignore_list
-----------

The ``ignore_list`` subsection is a simple short circuit list of keywords.  If Sagan encounters any 
keywords in this list,  it is immediately dropped and not passed through the rest of the 
Sagan engine.  In high throughput environments,  this can save CPU time.   The ``ignore_file`` is 
the location and file to load as an "ignore" list.

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
what networks to "skip" GeoIP lookups.   The ``country_database`` is the Maxmind database to load.
The ``skip_networks`` option tells Sagan what networks not to lookup. 


Example ``geoip`` subsection::

     # Maxmind GeoIP2 support allows Sagan to categorize events by their country
     # code. For example, a rule can be created to track "authentication 
     # successes" & associate the country where the successful login came from.  If the
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
and the `LibLogNorm <https://FIXME`>_ web site.

Example ``liblognorm`` subsection::


     # Liblognorm is a fast sample-based log normalization library.  Sagan uses
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
"sniffing" varies.  The ``interface`` option is the network device you want to "sniff" traffic on.
the ``bpf`` (Berkely Packet Filter) is the filter to use to extract logs from the network.   The
``log-device`` is where Sagan will inject logs after they are "sniffed" off the network.  The 
``promiscuous`` option puts the network interface Sagan is using in "promiscious mode" or not.


Example ``plog`` subsection::

     # 'plog',  the promiscuous syslog injector, allows Sagan to 'listen' on a
     # network interface and 'suck' UDP syslog messages off the wire.  When a 
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

Sagan ``processors`` are methods of detection outside of the Sagan rule engine.  

track-clients
-------------

The ``track-clients`` processor is used to detect when a syslog client has stopped or restarted sending
logs to Sagan.  This can be useful for detecting systems where logging has been disabled.  In the 
event a syslog client stops sending logs,  Sagan generates an alert for notification purposes.  When
the syslog client comes back online,  Sagan will generate another alert for notification purposes.  The
``time`` is how long a syslog client has not sent a log message to be considered "down".

Example ``track-clients`` subsection::

     # The "tracking clients" processor keeps track of the systems (IP addresses), 
     # reporting to Sagan.  If Sagan stops receiving logs from a client for a 
     # specified amount of time ("timeout"), an alert/notification is created.  
     # When the system comes back online,  another alert/notification is 
     # created. 

     - track-clients:
         enabled: no
         timeout: 1440             # In minutes


rule-tracking
-------------

The ``rule-tracking`` processor is used to detect unused rule sets.  This can be useful for detecting
when rules are loaded which do not need to be.  Rules that are loaded that are not used waste CPU
cycles.  This assists with rule tuning.  The ``console`` option allows for rule tracking statistics
to the console when Sagan is being run in the foreground.  The ``syslog`` option tells Sagan to send
rule tracking statistics to syslog.  The ``time`` option tells Sagan how often to record rule tracking
statistics (in minutes).

Example ``rule-tracking`` subsection::

     # This reports on rule sets that have and have not "fired".  This can be 
     # useful in tuning Sagan. 

     - rule-tracking:
         enabled: yes
         console: disabled
         syslog: enabled
         time: 1440                # In minutes 

perfmonitor
-----------

The ``perfmonitor`` processor records Sagan statistics to a CSV file.  This can provide useful data
about detection and the performance of Sagan.  The ``time`` option sets how often Sagan should
record ``perfmonitor`` data.


Example ``perfmonitor`` subsection::

     # The "perfmonitor" processor writes statistical information every specified
     # number of seconds ("time") to a CSV file.  This data can be useful for 
     # tracking the performance of Sagan.  This data can also be used with 
     # RRDTool to generate graphs.  

     - perfmonitor:
         enabled: no
         time: 600
         filename: "$LOG_PATH/stats/sagan.stats"

blacklist
---------

The ``blacklist`` processor reads in a file at load time (or reload) that contains IP addresses 
you wish to alert on.  Detection is controlled by the ``*-blacklist.rules`` rule sets.  The idea
is to load IP addresses of interest into this list and Sagan can monitor for them.  The list is a 
file containing IP and network addresses in a CIDR format (ie - 192.168.1.0/24, 10.0.0.0/8). 

Example ``perfmonitor`` subsection::

     # The "blacklist" process reads in a list of hosts/networks that are
     # considered "bad".  For example, you might pull down a list like SANS
     # DShield (http://feeds.dshield.org/block.txt) for Sagan to use.  If Sagan
     # identifies any hosts/networks in a log message from the list, an alert
     # will be generated.  The list can be in a IP (192.168.1.1) or CIDR format
     # (192.168.1.0/24).  Rules identified as -blacklist.rules use this data.  
     # You can load multiple blacklists by separating them with commas.  For 
     # example; filename: "$RULE_PATH/list1.txt, $RULE_PATH/list2.txt". 

     - blacklist:
         enabled: no
         filename: "$RULE_PATH/blacklist.txt"

bluedot
-------

The ``bluedot`` processor looks up data in the Quadrant Information Security "Bluedot"
Threat Intelligence database.  This is done over a ``http`` session.   Access to this
database is not public at this time.  

Example ``bluedot`` subsection::

     # The "bluedot" processor extracts information from logs (URLs, file hashes,
     # IP address) and queries the Quadrant Information Security "Bluedot" threat
     # intelligence database.  This database is 'closed' at this time.  For more 
     # information,  please contact Quadrant Information Security @ 1-800-538-9357
     # (+1-904-296-9100) or e-mail info@quadrantsec.com for more information.  
     # Rules identified with the -bluedot.rules extension use this data.

     - bluedot:
         enabled: no
         device-id: "Device_ID"
         cache-timeout: 120
         categories: "$RULE_PATH/bluedot-categories.conf"

         max-ip-cache: 300000
         max-hash-cache: 10000
         max-url-cache: 20000
         max-filename-cache: 1000

         ip-queue: 1000
         hash-queue: 100
         url-queue: 1000
         filename-queue: 1000

         host: "bluedot.qis.io"
         ttl: 86400
         uri: "q.php?qipapikey=APIKEYHERE"

         skip_networks: "8.8.8.8/32, 8.8.4.4/32"


zeek-intel (formally "bro-intel")
---------------------------------

The ``zeek-intel`` (formally known as ``bro-intel``) allows Sagan to load files from the "Zeek (Bro) 
intelligence framwork".  This allows Sagan to lookup IP address, hashes and other data from Zeek
Intelligence data.

Example ``zeek-intel`` subsection::

     # The "zeek-intel" (formally "bro-intel") processor allows Sagan to use 
     # threat intelligence data from the "Zeek (Bro) Intelligence Framework".  
     # Rules identified with the # -brointel.rules use this data.  For more information 
     # about this processor,  see: 
     #
     # https://quadrantsec.com/about/blog/using_sagan_with_bro_intelligence_feeds/
     # https://wiki.quadrantsec.com/bin/view/Main/SaganRuleReference#bro_intel_src_ipaddr_dst_ipaddr 
     # http://blog.bro.org/2014/01/intelligence-data-and-bro_4980.html
     # https://www.bro.org/sphinx-git/frameworks/intel.html
     #
     # A good aggregate source of Bro Intelligence data is at: 
     #
     # https://intel.criticalstack.com/

     - zeek-intel:
         enabled: no
         filename: "/opt/critical-stack/frameworks/intel/master-public.bro.dat"

dynamic-load
------------

The ``dynamic-load`` processor will detect new logs entering the Sagan engine and can either 
automatically load rules or send an alert about new logs being detected.  The idea here is to have
Sagan assist with the detection of network and hardware changes.  This rule is tied to the 
``dynamic.rules`` rule set.  The ``dynamic.rules`` rule set has signatures used to detect 
new log data entering the Sagan engine.   The ``sample-date`` controls how often to look for 
new logs entering the Sagan engine.  The higher the ``sample-rate`` the less CPU is used but the
longer it will take to detect new data.  The lower the ``sample-rate`` the faster Sagan can detect
new data but at a higher cost to the CPU.  The ``type`` can be ``dynamic_load`` or ``log_only``. 
If set to ``dynamic_load``,  when new data is detected,  Sagan will automatically load the associated
rule from the ``dynamic.rules``.  If set to ``log_only``,  Sagan will not load any data and only
generate an alert that new data was detected.


Example ``dynamic-load`` subsection::

     # The 'dynamic_load' processor uses rules with the "dynamic_load" rule option
     # enabled. These rules tell Sagan to load additional rules when new log
     # traffic is detected.  For example,  if Sagan does not have 'proftpd.rules'
     # enabled but detects 'proftp' log traffic,  a dynamic rule can automatically
     # load the 'proftpd.rules' for you.  Dynamic detection rules are named
     # 'dynamic.rules' in the Sagan rule set.  The "sample-rate" limits amount of
     # CPU to dedicated to detection new logs. The "type" informs the process 
     # "what" to do.  Valid types are "dynamic_load" (load & alert when new rules
     #  are loaded), "log_only" (only writes detection to the sagan.log file) and
     # "alert" (creates an alert about new logs being detected). 

     - dynamic-load:
         enabled: no
         sample-rate: 100          # How often to test for new samples. 
         type: dynamic_load        # What to do on detection of new logs.


outputs
=======

Sagan supports writing data in various formats.  Some formats may be more suitable for humans
to read,  while others might be better for outputing to databases like Elasticsearch and MySQL.


eve-log
-------

Sagan can write to `Suricata's <https://suricata-ids.io>`_ "Extensible Event Format", better
known as "EVE".  This is a JSON format in which events (alerts, etc) are written to.  This data
can then be used to transport data into Elasticsearch (using software like Logstash) or `Meer <https://meer.readthedocs.org>`_ (for MySQL/MariaDB/PostgreSQL) output.  If you are looking to get alert
data into any database back end,  you'll likely want to enable this output plugin.

Example ``eve-log`` subsection::

   outputs:

     # EVE alerts can be loaded into software like Elasticsearch and is a good 
     # replacement for "unified2" with software like "Meer".  For more 
     # information on Meer, Check out:
     #
     # https://github.com/beave/meer

     - eve-log:
         enabled: no
         interface: logs
         alerts: yes                     # Logs alerts
         logs: no                        # Send all logs to EVE. 
         filename: "$LOG_PATH/eve.json"

alert
-----

The ``alert`` format is a simple,  multiline human readable format.  The output is similar
to that of traditional ``Snort`` alert log.

Example ``alert`` subsection::

     # The 'alert' output format allows Sagan to write alerts, in detail, in a 
     # traditional Snort style "alert log" ASCII format. 

     - alert:
         enabled: yes
         filename: "$LOG_PATH/alert.log"

fast
----

The ``fast`` format is a simple, single line human readable format.  The output is similar
to the traditional ``Snort`` "fast" log.

Example ``fast`` subsection::

     # The 'fast' output format allows Sagan to write alerts in a format similar
     # to Snort's 'fast' output format. 

     - fast:
         enabled: no
         filename: "$LOG_PATH/fast.log"

unified2
--------

The ``unified2`` output is a binary blob format used to write event and alert data.  It is 
compatible with the ``Snort`` "unified2" format.  This format has traditionally been used to 
transport alert data from Sagan into a MySQL/MariaDB/PostgreSQL/etc database.   This means that 
it is compatible with software like `Barnyard2 <https://github.com/firnsy/barnyard2>`_ , ``u2spew`` and ``u2boat``.  The ``unified2``. 

``unified2`` is depreciated.  Consider using the ``eve-log`` instead.

Example ``unified2`` subsection::

     # The 'unified2' output allows Sagan to write in Snort's unified2 format. 
     # This allows events/alerts generated by Sagan to be read and queued for
     # external programs like Barnyard2 (http://www.securixlive.com/barnyard2/).
     # Barnyard2 can then record events to various formats (Sguil, PostgreSQL, 
     # MySQL, MS-SQL, Oracle, etc).  Sagan must be compiled with libdnet support
     # to use this function. 

     - unified2:
         enabled: no
         force-ipv4: no
         filename: "$LOG_PATH/unified2.alert"
         limit: 128                                # Max size in MB

smtp
----

The ``smtp`` output allows Sagan to send alerts via e-mail.

Example ``smtp`` subsection::

  # The 'smtp' output allows Sagan to e-mail alerts that trigger.  The rules 
  # you want e-mailed need to contain the 'email' rule option and Sagan must
  # be compiled with libesmtp support.  

  - smtp:
      enabled: no
      from: sagan-alert@example.com
      server: 192.168.0.1:25
      subject: "** Sagan Alert **"

snortsam
--------

The ``snortsam`` output format allows Sagan to communicate with the `Snortsam <http://www.snortsam.net/>`_ firewall blocking agent.  This allows Sagan to create firewall ACLs and block traffic based off 
rule sets.  

Example ``snortsam`` subsection::

     # The 'snortsam' output allows Sagan to send block information to Snortsam 
     # agents.  If a rule has the fwsam: option in it,  the offending IP address can 
     # be firewalled/blocked. For example,  if a rule is triggered with the 'fwsam'
     # option,  Sagan can instruct a firewall (iptables/ebtable/pf/iwpf/Cisco/etc)
     # to firewall off the source or destination. 
     #
     # In order for Sagan to send a blocking request to the SnortSam agent,
     # that agent has to be listed, including the port it listens on, and the
     # encryption key it is using.  The server option is formatted like this: 
     #
     # server: {Snortsam Station}:{port}/{password}
     #
     #   {SnortSam Station}: IP address or host name of the host where SnortSam is
     #                       running.
     #   {port}:             The port the remote SnortSam agent listens on.
     #   {password}:         The password, or key, used for encryption of the
     #                       communication to the remote agent.
     #
     # At the very least, the IP address or host name of the host running SnortSam
     # needs to be specified. If the port is omitted, it defaults to TCP port 898.
     # If the password is omitted, it defaults to a preset password.
     #
     # More than one host can be specified, but has to be done on the same line.
     # Just separate them with one or more spaces.

     - snortsam:
         enabled: no
         server: 127.0.0.1/mykey

syslog
------

The ``syslog`` output plugin writes alerts to the system's syslog that Sagan is running on.  
This can be useful for forwarding Sagan alert data to other SIEMs. 

Example ``syslog`` subsection::

     # The 'syslog' output allows Sagan to send alerts to syslog. The syslog 
     # output format used is exactly the same as Snort's.  This means that your 
     # SIEMs Snort log parsers should work with Sagan.

     - syslog:
         enabled: no
         facility: LOG_AUTH
         priority: LOG_ALERT
         extra: LOG_PID

rule-files
==========

The ``rule-files`` section tells Sagan what "rules" to load.  This can be a list of files or rules
that can be broken out into seperate ``include``. 

Example ``rule-files`` subsection::

   rules-files:

     #############################################################################
     # Dynamic rules - Only use if you have the 'dynamic_load' processor enabled #
     #############################################################################

     #- $RULE_PATH/dynamic.rules

     #############################################################################
     # GeoIP rules - Only use if you have $HOME_COUNTRY and 'geoip' core enabled #
     #############################################################################

     #- $RULE_PATH/cisco-geoip.rules
     #- $RULE_PATH/citrix-geoip.rules
     #- $RULE_PATH/courier-geoip.rules
     #- $RULE_PATH/f5-big-ip-geoip.rules
     #- $RULE_PATH/fatpipe-geoip.rules
     #- $RULE_PATH/fortinet-geoip.rules
     #- $RULE_PATH/imapd-geoip.rules
     #- $RULE_PATH/juniper-geoip.rules
     #- $RULE_PATH/openssh-geoip.rules
     #- $RULE_PATH/proftpd-geoip.rules
     #- $RULE_PATH/riverbed-geoip.rules
     #- $RULE_PATH/snort-geoip.rules
     #- $RULE_PATH/ssh-tectia-server-geoip.rules
     #- $RULE_PATH/vmware-geoip.rules
     #- $RULE_PATH/vsftpd-geoip.rules
     #- $RULE_PATH/windows-geoip.rules
     #- $RULE_PATH/windows-owa-geoip.rules
     #- $RULE_PATH/zimbra-geoip.rules

     #############################################################################
     # Aetas rules - Only use if $SAGAN_HOUR/$SAGAN_DAY is defined!              #
     #############################################################################

     #- $RULE_PATH/cisco-aetas.rules
     #- $RULE_PATH/fatpipe-aetas.rules
     #- $RULE_PATH/fortinet-aetas.rules
     #- $RULE_PATH/juniper-aetas.rules
     #- $RULE_PATH/openssh-aetas.rules
     #- $RULE_PATH/proftpd-aetas.rules
     #- $RULE_PATH/riverbed-aetas.rules
     #- $RULE_PATH/ssh-tectia-server-aetas.rules
     #- $RULE_PATH/windows-aetas.rules

     #############################################################################
     # Malware rules - Rules useful for detecting malware.                       #
     #############################################################################

     #- $RULE_PATH/cisco-malware.rules
     #- $RULE_PATH/fortinet-malware.rules
     #- $RULE_PATH/nfcapd-malware.rules
     #- $RULE_PATH/proxy-malware.rules
     #- $RULE_PATH/windows-malware.rules

     #############################################################################
     # Bro Intel rules - Make sure the 'bro-intel processor is enabled!          #
     #############################################################################

     #- $RULE_PATH/cisco-brointel.rules
     #- $RULE_PATH/citrix-brointel.rules
     #- $RULE_PATH/windows-brointel.rules
     #- $RULE_PATH/windows-owa-brointel.rules
     #- $RULE_PATH/bro-intel.rules

     #############################################################################
     # Bluedot rules - Make sure the 'bluedot' processor is enabled!             #
     #############################################################################

     #- $RULE_PATH/bluedot.rules
     #- $RULE_PATH/bro-bluedot.rules
     #- $RULE_PATH/cisco-bluedot.rules
     #- $RULE_PATH/citrix-bluedot.rules
     #- $RULE_PATH/courier-bluedot.rules
     #- $RULE_PATH/f5-big-ip-bluedot.rules
     #- $RULE_PATH/fatpipe-bluedot.rules
     #- $RULE_PATH/fortinet-bluedot.rules
     #- $RULE_PATH/imapd-bluedot.rules
     #- $RULE_PATH/juniper-bluedot.rules
     #- $RULE_PATH/openssh-bluedot.rules
     #- $RULE_PATH/proftpd-bluedot.rules
     #- $RULE_PATH/riverbed-bluedot.rules
     #- $RULE_PATH/snort-bluedot.rules
     #- $RULE_PATH/ssh-tectia-server-bluedot.rules
     #- $RULE_PATH/vmware-bluedot.rules
     #- $RULE_PATH/vsftpd-bluedot.rules
     #- $RULE_PATH/windows-bluedot.rules
     #- $RULE_PATH/windows-owa-bluedot.rules

     ###############################################################################
     # Correlated rules - Rules that use xbits/flexbit to detect malicious behavior #
     ###############################################################################

     - $RULE_PATH/cisco-correlated.rules
     - $RULE_PATH/citrix-correlated.rules
     - $RULE_PATH/courier-correlated.rules
     - $RULE_PATH/fatpipe-correlated.rules
     - $RULE_PATH/fortinet-correlated.rules
     - $RULE_PATH/imapd-correlated.rules
     - $RULE_PATH/openssh-correlated.rules
     - $RULE_PATH/ssh-tectia-server-correlated.rules
     - $RULE_PATH/vmware-correlated.rules
     - $RULE_PATH/vsftpd-correlated.rules
     - $RULE_PATH/windows-correlated.rules
     - $RULE_PATH/windows-owa-correlated.rules

     #############################################################################
     # Standard rules - Rules that do not require any dependencies.              #
     #############################################################################

     #- $RULE_PATH/as400.rules
     - $RULE_PATH/adtran.rules
     - $RULE_PATH/apache.rules
     - $RULE_PATH/apc-emu.rules
     - $RULE_PATH/arp.rules
     #- $RULE_PATH/artillery.rules
     - $RULE_PATH/asterisk.rules
     - $RULE_PATH/attack.rules
     - $RULE_PATH/barracuda.rules
     - $RULE_PATH/bash.rules
     - $RULE_PATH/bind.rules
     - $RULE_PATH/carbonblack.rules
     - $RULE_PATH/bonding.rules
     - $RULE_PATH/bro-ids.rules
     - $RULE_PATH/cacti-thold.rules
     #- $RULE_PATH/cisco-acs.rules
     - $RULE_PATH/cisco-ise.rules
     - $RULE_PATH/cisco-cucm.rules
     - $RULE_PATH/cisco-ios.rules
     - $RULE_PATH/cisco-meraki.rules
     - $RULE_PATH/cisco-pixasa.rules
     #- $RULE_PATH/cisco-prime.rules
     - $RULE_PATH/cisco-wlc.rules
     - $RULE_PATH/citrix.rules
     - $RULE_PATH/courier.rules
     - $RULE_PATH/cylance.rules
     #- $RULE_PATH/deleted.rules
     #- $RULE_PATH/digitalpersona.rules
     - $RULE_PATH/dovecot.rules
     - $RULE_PATH/f5-big-ip.rules
     - $RULE_PATH/fatpipe.rules
     - $RULE_PATH/fipaypin.rules
     - $RULE_PATH/fortinet.rules
     - $RULE_PATH/ftpd.rules
     - $RULE_PATH/grsec.rules
     - $RULE_PATH/honeyd.rules
     #- $RULE_PATH/hordeimp.rules
     #- $RULE_PATH/hostapd.rules
     - $RULE_PATH/huawei.rules
     - $RULE_PATH/imapd.rules
     - $RULE_PATH/ipop3d.rules
     - $RULE_PATH/juniper.rules
     #- $RULE_PATH/kismet.rules
     - $RULE_PATH/knockd.rules
     - $RULE_PATH/linux-kernel.rules
     - $RULE_PATH/milter.rules
     - $RULE_PATH/mongodb.rules
     - $RULE_PATH/mysql.rules
     - $RULE_PATH/nexpose.rules
     - $RULE_PATH/nfcapd.rules
     - $RULE_PATH/nginx.rules
     - $RULE_PATH/ntp.rules
     - $RULE_PATH/openssh.rules
     - $RULE_PATH/openvpn.rules
     - $RULE_PATH/oracle.rules
     - $RULE_PATH/palo-alto.rules
     - $RULE_PATH/php.rules
     - $RULE_PATH/postfix.rules
     - $RULE_PATH/postgresql.rules
     - $RULE_PATH/pptp.rules
     - $RULE_PATH/procurve.rules
     - $RULE_PATH/proftpd.rules
     - $RULE_PATH/pure-ftpd.rules
     - $RULE_PATH/racoon.rules
     - $RULE_PATH/riverbed.rules
     - $RULE_PATH/roundcube.rules
     - $RULE_PATH/rsync.rules
     - $RULE_PATH/samba.rules
     - $RULE_PATH/sendmail.rules
     - $RULE_PATH/snort.rules
     - $RULE_PATH/solaris.rules
     - $RULE_PATH/sonicwall.rules
     - $RULE_PATH/squid.rules
     - $RULE_PATH/ssh-tectia-server.rules
     - $RULE_PATH/su.rules
     - $RULE_PATH/symantec-ems.rules
     - $RULE_PATH/syslog.rules
     - $RULE_PATH/tcp.rules
     - $RULE_PATH/telnet.rules
     - $RULE_PATH/trendmicro.rules
     - $RULE_PATH/tripwire.rules
     - $RULE_PATH/vmpop3d.rules
     - $RULE_PATH/vmware.rules
     - $RULE_PATH/vpopmail.rules
     - $RULE_PATH/vsftpd.rules
     - $RULE_PATH/web-attack.rules
     #- $RULE_PATH/weblabrinth.rules
     - $RULE_PATH/windows-applocker.rules
     - $RULE_PATH/windows-auth.rules
     - $RULE_PATH/windows-emet.rules
     - $RULE_PATH/windows-misc.rules
     - $RULE_PATH/windows-mssql.rules
     - $RULE_PATH/windows-security.rules
     - $RULE_PATH/windows-owa.rules
     - $RULE_PATH/windows.rules
     - $RULE_PATH/windows-sysmon.rules
     - $RULE_PATH/wordpress.rules
     - $RULE_PATH/xinetd.rules
     - $RULE_PATH/yubikey.rules
     - $RULE_PATH/zeus.rules
     - $RULE_PATH/zimbra.rules

   #
   # Include other configs
   #

   # Includes.  Files included here will be handled as if they were
   # included in this configuration file.

   #include: "/usr/local/etc/include1.yaml"
   #include: "$RULE_PATH/include2.yaml"


