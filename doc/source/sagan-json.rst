Sagan & JSON
============

Why JSON?
~~~~~~~~~

Sagan has traditionally been a syslog analysis and parsing engine.  Over time,  more and more
platforms have been switching to JSON as an output option.  Not just traditional syslog data
sources but non-traditional sources like APIs and "cloud" platforms.  The good side of this
is that the data becomes more structures and has more context.  Unfortunately,  traditional 
Sagan rules weren't built to process this data. 

Our main goal is to keep traditional syslog parsing in places and to add on JSON keyword rule
options and functionality.   Sagan is about processing log data,  regardless of the source. 
This means that in many cases it is important for Sagan to properly handle JSON.  

Different method of JSON input
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sagan can interpret JSON from two locations.   From the FIFO input or from a syslog message. 

The first methods general options is that Sagan reads incoming data from a named pipe (FIFO).
Traditionally, this data is in a pipe delimited format.  Pipe delimitation greatly limits the 
types of data Sagan can process.  As of Sagan 2.0.0,  Sagan can now read the named pipe for JSON 
data.  Most modern day syslog engines (rsyslog, syslog-ng, nxlog, etc) support JSON output.  See 
sections
`4.2. rsyslog - JSON mode <https://https://sagan.readthedocs.io/en/latest/configuration.html#rsyslog-json-modeg`>_ or `4.4. syslog-ng - JSON mode <https://sagan.readthedocs.io/en/latest/configuration.html#syslog-ng-json-mode>`_ for more information about configuration of various log daemons.

Keep in mind,  traditional syslog daemons are no longer the only sources Sagan can collect this
type of data from.  For example, the IDS engine Suricata (https://suricata-ids.org) produces
a lot of JSON.  Various security tool APIs like Cisco Umbrella, AWS Cloudtrail, CrowdStrike Falcon 
Cloud, etc. can now become sources for Sagan. 

The second method is to collect JSON data via the syslog "message" field.  Some "forwarders" 
use this method to send SIEMs data.  The idea is that the data is transferred via the traditional
syslog transport but the message contains the JSON data.  Sagan can interpret that data for
alerting.


JSON "mapping"
~~~~~~~~~~~~~~

Either method you decide to receive the JSON data in,  it is likely you will want to "map"
the data so that Sagan can process it.  You can think of mapping this way; When Sagan receives
JSON data,  it initially has no means to determine what is important and what is not.  Sagan
"mapping" allows you to assign values so that the engine and signatures can be used.  It is
also important to understand that different platforms label key/value pairs differently. For
example,  a source IP address on one platform might be "src_ip",  while on another platform
it might be "source_ip".  Mapping allows you to assign the source IP value from the JSON. 

Mapping not only allows you to use signature key words (``content``, ``pcre``, etc) but other
Sagan features like ``threshold``, ``after``, ``xbits``, etc. 

As the name suggests,  "mapping" simply allows key/value pairs to be assigned in specific
Sagan engine values.  

Within the Sagan rules are two files.  One is ``json-input.map`` and the other is
``json-message.map``.  These are the mapping files that are used depending on your method of
input. 

Limitations
~~~~~~~~~~~

Sagan will automatically processes "nested" JSON data.  There is a limitation in that Sagan
will only keep the last "key" name.   To examine this,  lets look at an average Suricata 
"nested" JSON line. ::

   {"timestamp":"2019-11-19T20:50:02.856040+0000","flow_id":1221352694083219,"in_iface":"eth0","event_type":"alert","src_ip":"12.12.12.12","dest_ip":"13.13.13.13","proto":"ICMP","icmp_type":8,"icmp_code":0,"alert":{"action":"allowed","gid":1,"signature_id":20000004,"rev":1,"signature":"QUADRANT Ping Packet [ICMP]","category":"Not Suspicious Traffic","severity":3},"flow":{"pkts_toserver":2,"pkts_toclient":0,"bytes_toserver":196,"bytes_toclient":0,"start":"2019-11-19T20:50:01.847507+0000"},"payload":"elXUXQAAAACtDw0AAAAAAE9GVFdJTkstUElOR9raU09GVFdJTkstUElOR9raU09GVFdJTkstUEk=","stream":0,"packet":"VDloD8YYADAYyy0NCABFAABUkEpAAEABniMMnwIKDJHxAQgAk9tJcwACelXUXQAAAACtDw0AAAAAAE9GVFdJTkstUElOR9raU09GVFdJTkstUElOR9raU09GVFdJTkstUEk=","packet_info":{"linktype":1},"host":"firewall"} 

Internally, Sagan will "break apart" the nests.  However,  the keys will not hold there nested
key names.  For example,  the key "timestamp" will be recorded as "timestamp" within Sagan.
However,  if you look at the "alert" JSON nest,  you might expect the nested value "action" 
to be something like "alert.action".  Internally to Sagan, it will assign it a value of just 
"action". 

When mapping is not needed
~~~~~~~~~~~~~~~~~~~~~~~~~~

In most cases,  you'll likely want to performing mapping for your JSON data.  However,  there
are some instances where mapping might not be required.   Keep in mind,  without mapping things
like ``threshold``, ``after``, ``xbits`` might not perform properly. 

Regardless of whether Sagan properly maps the JSON, it will internally still split the key/value
pairs.  While you won't be able to use the standard Sagan rule operators (ie - ``content``,
``pcre``, etc) you can use some JSON specific operators.  These are ``json_content``, ``json_pcre`` 
and ``json_meta_content``.  With these,  you can specify the key you want to process and 
then what you are searching for.  

JSON Fields to map
~~~~~~~~~~~~~~~~~~

src_ip, dst_ip, message, event_id, proto, src_port, dst_port, facility, priority, level, tag,
syslog-source-ip, event_type, program, time, date. 


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
is a file that come with the Sagan rule set and already has some mappings within.  The next
option is the ``json-software`` type.  The ``json-input.map`` typically contains more than
one mapping type.  The ``json-software`` tells Sagan which mapping to use from that file. A
typically mapping for Syslog-NG looks like this: ::

   {"software":"syslog-ng","syslog-source-ip":"SOURCEIP","facility":"FACILITY","level":"PRIORITY","priore":"DATE","program":"PROGRAM","message":"MESSAGE"}

These are key/value pairs.  The first option (ie - ``message``, ``program``, etc) is the Sagan engine value.  The value to the key is what syslog-ng names the key.

When Sagan starts up,  it will parse the ``json-input.map`` for ``syslog-ng``.  This means that
via the named pipe,  Sagan will expect the data to be in the mapped JSON format.  Data that is 
not in that format will be dropped.  To understand mapping better,  below is an example of 
JSON via the named pipe that Sagan might receive: ::

   {"TAGS":".source.s_src","SOURCEIP":"127.0.0.1","SEQNUM":"437","PROGRAM":"sshd","PRIORITY":"notice","Puthentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=49.88.112.77  user=root","LEGACY_M"dev-2","HOST":"dev-2","FACILITY":"authpriv","DATE":"Jan  2 20:12:36"}

As we can see,  Syslog-NG maps the syslog message field as "MESSAGE".  Sagan engine takens that
data and internally maps it to the "message" value.  It repeats this through the rest of the
mapping.

**Note: When processing JSON via the named pipe,  you can only have one mapping at a time.**

JSON via syslog message field
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The mapping concept for Sagan when receiving JSON data via the syslog message is similar to 
that JSON data via the named pipe. 

Unlike JSON data via the named pipe,  when recieving data via a syslog message mulitple 
maps can be applied.  The idea is that your Sagan system might be receiving different types
of JSON data from different systems.

To determine which "map" works best, the Sagan engine does an internal "scoring" of each map.
The idea is that Sagan will apply the best map that matches the most fields.   This also means
that sometimes mapping fields,  even if you don't plan on using them,  will ensure that the
proper map "wins".  

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
detected. 

The ``json-message-map`` contains the mappings for systems that might be sending you JSON.
As with the ``json-input.map``,  the Sagan rule sets come with a ``json-message.map``.

An example mapping::

   { "software":"suricata", "syslog-source-ip":"src_ip","src_ip":"src_ip","dest_ip":"dest_ip","src_port":"src_port","dest_port":"dest_port","message":"msg,signature_name","event_type":"hash","time":"timestamp","date":"timestamp", "proto":"proto" } 

Unlike named pipe JSON mapping,  the "software" name is not used other than for debugging. 
When Sagan receives JSON data,  it will apply all mapping to found in the ``json-message.map``
file.  

SCORING HERE


Putting it all together
~~~~~~~~~~~~~~~~~~~~~~~



