Sagan & JSON
============

Why JSON?
~~~~~~~~~

Sagan has traditionally been a syslog analysis and parsing engine.  Over time,  more and more
platforms have been switching to JSON as an output option.  Not just traditional syslog data
sources but non-traditional sources like APIs and "cloud" platforms.  The good side of this
is the data becomes more structured and now has more context.  Unfortunately,  traditional 
Sagan rules weren't built to process this data. 

The goal of Sagan is to keep the traditional syslog parsing in place and to add on JSON keyword rule
options and functionality. Sagan is about processing log data,  regardless of the source. 
This means that in many cases it is important for Sagan to properly handle JSON.  

Different method of JSON input
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sagan can interpret JSON from two locations.   From the named pipe (FIFO) or from a "syslog message". 

The first methods is that Sagan reads incoming JSON data from a named pipe (FIFO).
Traditionally, this data is in a "pipe" (|) delimited format.  The "pipe" delimitation greatly limits the 
types of data Sagan can process.  As of Sagan 2.0.0,  Sagan can read JSON data via the named pipe.
Most modern day syslog engines (Rsyslog, Syslog-NX, NXlog, etc) support JSON output.  See 
sections
`4.2. rsyslog - JSON mode <https://https://sagan.readthedocs.io/en/latest/configuration.html#rsyslog-json-modeg`>_ or `4.4. syslog-ng - JSON mode <https://sagan.readthedocs.io/en/latest/configuration.html#syslog-ng-json-mode>`_ 
for more information about configuration of various log daemons.

With this in mind,  this means that Sagan can collect data from non-syslog sources.  
For example, the IDS engine Suricata (https://suricata-ids.org) produces
a lot of JSON data.  Various security tool APIs like Cisco Umbrella, AWS Cloudtrail, CrowdStrike Falcon 
Cloud, etc. also generate a lot of JSON output.  These all become possible "sources" for Sagan 
data processing.

The second method of JSON data collection is via the syslog "message" field.  Some syslog "forwarders" 
use this method to send SIEMs data.  The idea is that the data is transferred via the traditional
syslog transport but the message contains the JSON data.  Sagan can interpret that data for
alerting purposes.


JSON "mapping"
~~~~~~~~~~~~~~

Either method you decide to receive the JSON data in, it is likely you will want to "map"
the data so that Sagan can properly process it.  You can think of mapping this way; When Sagan receives
JSON data,  it doesn't know what is "important" and what isn't.  "Mapping" allows you to assign values to the
data so the engine can process it and signatures can be used.  It is
also important to understand that different platforms label key/value pairs differently. For
example,  a source IP address on one platform might be "src_ip",  while on another platform
it might be "source_ip".  Mapping allows you to assign the "source" IP value from the JSON. 

"Mapping" allows you to use signature keys words like ``content``, ``pcre``, ``meta_content``, 
etc. and features like ``threshold``, ``after``, ``xbits``, etc. 

Simply put,  "Mapping" allows you to assign JSON "key" data to specific internal Sagan values.

Within the Sagan rules are two files.  One is ``json-input.map`` and the other is
``json-message.map``.  These are the mapping files that are used depending on your method of
input.  These files can be altered to support the JSON mapping you might need and come with
some example mapping.

In some cases,  "mapping" might be over kill and can be skipped.  See ``When mapping is not needed``.


How JSON nest are processed
~~~~~~~~~~~~~~~~~~~~~~~~~~~

   Sagan will automatically "flatten" nests.  For example,  let say you want to process the
following JSON format.

   {"timestamp":"2019-11-19T20:50:02.856040+0000","flow_id":1221352694083219,"in_iface":"eth0","event_type":"alert","src_ip":"12.12.12.12","dest_ip":"13.13.13.13","proto":"ICMP","icmp_type":8,"icmp_code":0,"alert":{"action":"allowed","gid":1,"signature_id":20000004,"rev":1,"signature":"QUADRANT Ping Packet [ICMP]","category":"Not Suspicious Traffic","severity":3},"flow":{"pkts_toserver":2,"pkts_toclient":0,"bytes_toserver":196,"bytes_toclient":0,"start":"2019-11-19T20:50:01.847507+0000"},"payload":"elXUXQAAAACtDw0AAAAAAE9GVFdJTkstUElOR9raU09GVFdJTkstUElOR9raU09GVFdJTkstUEk=","stream":0,"packet":"VDloD8YYADAYyy0NCABFAABUkEpAAEABniMMnwIKDJHxAQgAk9tJcwACelXUXQAAAACtDw0AAAAAAE9GVFdJTkstUElOR9raU09GVFdJTkstUElOR9raU09GVFdJTkstUEk=","packet_info":{"linktype":1},"host":"firewall"} 

   All nest,  including the top nest,  start with a ``.``.  For example, the JSON key "timestamp" will become ``.timestamp`` 
internally to Sagan.  The "event_type" and "src_ip" would become ``.event_type`` and ``.src_ip``.  For nested objects like "alert", you would access the  "signature_id" as ``.alert.signature_id``.  This structure is similar to JSON processing commands like ``jq``.

   There is no limitations on nest depths.   This logic applies for JSON "mapping" and Sagan signature keywords like ``json_content``,
``json_pcre`` and ``json_meta_content``.


When mapping is not needed
~~~~~~~~~~~~~~~~~~~~~~~~~~

In most cases,  you'll likely want to performing mapping for your JSON data.  However,  there
are some instances where mapping might not be required.   Keep in mind,  without mapping things
like ``threshold``, ``after``, ``xbits`` might not perform properly. 

Regardless of whether Sagan properly maps the JSON, it will internally still split the key/value
pairs in real time.  While you won't be able to use the standard Sagan rule operators (ie - ``content``,
``pcre``, etc) you will be able use some JSON specific operators.  

These are ``json_content``, ``json_pcre`` and ``json_meta_content``.  With these, you can 
specify the key you want to process and then what you are searching for.  

This can be useful when used in conjunction with mapping.  This way you can use traditional 
Sagan keywords (``threshold``, ``after``, ``content``, etc) along with JSON specific (``json_content``, 
``json_pcre``, etc) rule options.


Mappable JSON Fields
~~~~~~~~~~~~~~~~~~~~

While not all JSON field can be internally mapped,  these are the Sagan internal fields that 
should be consider.  Each field has different functionality internally to Sagan.  For example,  if you want
to apply rule operators like ``threshold`` or ``after`` in a signature,  you'll likely want to
map ``src_ip`` and/or ``dst_ip``.  The following are internal Sagan variables/mappings to consider for
mapping.


Fields to consider for internal JSON mappings are as follows.

.. option:: src_ip

This value will become source IP address of the event.  This will apply to rule options like ``threshold``, 
``after``, ``xbits``, ``flexbits``, etc. 

.. option:: dst_ip

This value will become the destination IP address of the event.  This can also be represented
as ``dest_ip``.  This will apply to rule options like ``threshold``, ``after``, ``xbits``, ``flexbits``, 
etc.

.. option:: src_port

JSON data for this will become the source port of the event.  This will apply to rule options like ``flexbits``. 

.. option:: dst_port

JSON data for this will become the destination port for the event.  This will apply to rule options like ``flexbits``.
This can also be represented as ``dest_port``.

.. option:: message

The JSON for this value will becoming the syslog message.  This will apply to rule options like ``content``, 
``pcre``, ``meta_content``,  ``parse_src_ip``, ``parse_dst_ip``, ``parse_hash``, etc. 

.. option:: event_id

The JSON data will be applied to the ``event_id`` rule option. 

.. option:: proto

This will represent the protocol.  Valid options are TCP, UDP and ICMP (case insensitive).

.. option:: facility

The JSON data will be mapped to the syslog facility.  This will apply to the rule option ``facility``. 

.. option:: level

The JSON data will be mapped to the internal Sagan variable level.  This will apply to the rule option ``level``.

.. option:: tag.

The JSON data will be mapped to the internal Sagan variable of tag. This will apply to the rule option ``tag``.

.. option:: syslog-source-ip

The JSON data will be mapped to the internally to Sagan's syslog source.  This should not be confused with ``src_ip``.
If ``src_ip`` is not present, the ``syslog-source-ip`` become the ``src-ip``.  This might apply to ``threshold`` and
``after`` is ``src_ip`` is not populated. 

.. option:: event_type

The JSON data extracted will be applied internally to the Sagan variable of "program".  ``event_type`` is simply an
alias for ``program`` and both can be interchanged.  This applies to rule options like ``program`` and ``event_type``. 

.. option:: program

The JSON data extracted will be applied internally to the Sagan variable of "program".  ``program`` is simply an
alias for ``event_type`` and both can be interchanged.  This applies to rule options like ``program`` and ``event_type``.

.. option:: time

The JSON data extracted will be applied internally to the syslog "time" stamp.  This option is recorded but is not used
in any rule options. 

.. option:: date

The JSON data extracted will be applied internally to the syslog "date" stamp.  This option is recorded but is not used
in any rule options.


JSON via named pipe (FIFO)
~~~~~~~~~~~~~~~~~~~~~~~~~~

Mapping for JSON data coming in via the named pipe (FIFO) is configured in the ``sagan-core``
section under ``input-type``.  Two types are available, ``json`` and ``pipe``. If ``pipe``
is used,  the sections below (``json-map`` & ``json-software``) are ignored. ::

   # Controls how data is read from the FIFO. The "pipe" setting is the traditional 
   # way Sagan reads in events and is default. "json" is more flexible and 
   # will become the default in the future. If "pipe" is set, "json-map"
   # and "json-software" have no function.::

   input-type: json                       # pipe or json
   json-map: "$RULE_PATH/json-input.map"  # mapping file if input-type: json
   json-software: syslog-ng               # by "software" type. 


The ``json-map`` function informs the Sagan engine where to locate the mapping file.  This
is a file that is shipped with the Sagan rule set and already has some mappings within it.  The next
option is the ``json-software`` type.  The ``json-input.map`` typically contains more than
one mapping type.  The ``json-software`` tells Sagan which mapping to use from that file. A
typically mapping for Syslog-NG looks like this: ::

   {"software":"syslog-ng","syslog-source-ip":".SOURCEIP","facility":".FACILITY","level":".PRIORITY","priority":".PRIORITY","time":".DATE","date":".DATE","program":".PROGRAM","message":".MESSAGE"}


These are key/value pairs.  The first option (ie - ``message``, ``program``, etc) is the internal Sagan engine value.  
The value to the key is what Syslog-NG names the key.

When Sagan starts up,  it will parse the ``json-input.map`` for the software type of "syslog-ng".  If the
``software`` of "syslog-ng" is not found,  Sagan will abort. 

When located,  Sagan will expect data via the named pipe to be in the mapped JSON format.  Data that is 
not in this format will be dropped.  To understand mapping better,  below is an example of 
JSON via the named pipe that Sagan might receive: ::

   {"TAGS":".source.s_src","SOURCEIP":"127.0.0.1","SEQNUM":"437","PROGRAM":"sshd","PRIORITY":"notice","Authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=49.88.112.77  user=root","LEGACY_M"dev-2","HOST":"dev-2","FACILITY":"authpriv","DATE":"Jan  2 20:12:36"}

As we can see,  Syslog-NG maps the syslog "message" field as ".MESSAGE".  The Sagan engine takes that
data and internally maps it to the "message" value.  It repeats this through the rest of the
mapping.

Mapping this way becomes a more convient and flexible method of getting data into Sagan than the old "pipe delimited" format.

**Note: When processing JSON via the named pipe,  only one mapping can be used at a time.**


JSON via syslog message field
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The mapping concept for Sagan when receiving JSON data via the syslog "message" is similar to 
JSON data via the named pipe. 

Unlike JSON data via the named pipe,  when receiving data via a syslog "message" multiple 
maps can be applied.  The idea is that your Sagan system might be receiving different types
of JSON data from different systems.

To determine which "map" works best, the Sagan engine does an internal "scoring" of each map.
Sagan will then apply the best map that matches the most fields.   This means that you might 
want to "map" fields event if you don't plan on using them.  This ensures that the proper 
"map" will "win" (score the highest).

To enabled JSON syslog message processing,  you will need to enable the following fields within
the ``sagan-core`` part of the sagan.yaml. ::

   # "parse-json-message" allows Sagan to detect and decode JSON within a 
   # syslog "message" field.  If a decoder/mapping is found,  then Sagan will
   # extract the JSON values within the messages.  The "parse-json-program"
   # tells Sagan to start looking for JSON within the "program" field.  Some
   # systems (i.e. - Splunk) start JSON within the "program" field and
   # into the "message" field.  This option tells Sagan to "append" the 
   # strings together (program+message) and then decode.  The "json-message-map"
   # tells Sagan how to decode JSON values when they are encountered.

   parse-json-message: enabled
   parse-json-program: enabled
   json-message-map: "$RULE_PATH/json-message.map"

The ``parse-json-message`` configures Sagan to automatically detect JSON within the syslog
"message" field.  The ``parse-json-program`` configures Sagan to automatically detect 
JSON within the syslog "program" field. 

Some applications will send the start of the JSON within the "program" field and it will 
overflow into the "message" field.  The ``parse-json-program`` option configures Sagan to 
look for JSON within the "program" field and append the "program" and "message" field if 
JSON detected. 

The ``json-message-map`` contains the mappings for systems that might be sending you JSON.
As with the ``json-input.map``,  the Sagan rule sets come with a ``json-message.map``.

An example mapping::

   { "software":"suricata", "syslog-source-ip":".src_ip","src_ip":".src_ip","dest_ip":".dest_ip","src_port":".src_port","dest_port":".dest_port","message":".alert.signature,.alert_category,.alert.severity","event_type":".hash","time":".timestamp","date":".timestamp", "proto":".proto" } 

Unlike named pipe JSON mapping,  the "software" name is not used other than for debugging. 
When Sagan receives JSON data,  it will apply all mapping to found in the ``json-message.map``
file.  

Note of the “message” field. This shows the "message" being assigned multiple key values. In this case the key “.alert.signature”,”.alert.category” and “.alert.severity” will be become the “message”. Internally to Sagan, the “message” will become “key:value,key:value,key:value”. For example, let say the JSON Sagan is processing is the follow Suricata JSON line:


   {"timestamp":"2020-01-03T18:20:05.716295+0000","flow_id":812614352473482,"in_iface":"eth0","event_type":"alert","src_ip":"12.12.12.12","dest_ip":"13.13.13.13","proto":"ICMP","icmp_type":8,"icmp_code":0,"alert":{"action":"allowed","gid":1,"signature_id":20000004,"rev":1,"signature":"QUADRANT Ping Packet [ICMP]","category":"Not Suspicious Traffic","severity":3},"flow":{"pkts_toserver":5,"pkts_toclient":0,"bytes_toserver":490,"bytes_toclient":0,"start":"2020-01-03T18:20:01.691594+0000"},"payload":"1YUPXgAAAADM7QoAAAAAAE9GVFdJTkstUElOR9raU09GVFdJTkstUElOR9raU09GVFdJTkstUEk=","stream":0,"packet":"VDloD8YYADAYyy0NCABFAABUCshAAEABI6YMnwIKDJHxAQgAHoELvAAF1YUPXgAAAADM7QoAAAAAAE9GVFdJTkstUElOR9raU09GVFdJTkstUElOR9raU09GVFdJTkstUEk=","packet_info":{"linktype":1},"host":"firewall"}

Internally to Sagan the "message" will become: ::

   .alerts.ignature:QUADRANT Ping Packet [ICMP],.alert.category:Not Suspicious Traffic,alert.severity:3

This means any signatures you are going to create will need to take this format into account.  In cases where you would like the
entire JSON string to become the message,  simply make the "message" mapping ``%JSON%``.  This tells Sagan that the entire
JSON string should be considered the "message". 

