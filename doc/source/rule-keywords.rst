Rule Keywords
=============


after
-----

.. option:: after: track {by_src|by_dst|by_username|by_string}, count {number of event}, seconds {number of seconds};

"after" is used to trigger an alert "after" a number of events have happened within a specific amount of time. "after" tracks by the source or destination IP address of the event. The example would track events by the source IP address. If the event is triggered more than 10 times within 300 seconds (5 minutes), an alert is triggered.

**after: track by_src, count 10, seconds 300;**

After can be tracked by multiple 'track' options.  For example:

**after: track by_src&by_username, count 5, seconds 300;** 

The above would track by the source IP address and by the username. 

alert_time
----------

.. option:: alert_time: days {days}, hours {hours};

"alert_time" allows a rule to only trigger on certain days and/or certain hours. For example, let's assume that Windows RDP (Remote Desktop Protocol) is normal between the hours of 0800 (8 AM) to 1800 (6 PM). However, RDP sessions outside of that timeframe would be considered suspicious. This allows you to build a rule that will trigger outside of the "normal RDP" times.

Days are represented via digits 0 - 6. 0 = Sunday, 1 Monday, 2 Tuesday, 3 Wednesday, 4 Thursday, 5 Friday, 6 = Saturday.

Hours are represented by the 24 hour clock.

**alert_time: days 0123456, hours 0800-1800;**

The example above would cause a rule to trigger every day of the week between the hours of 0800 (8:00 AM) to 1800 (6:00 PM). One caveat is with "between" days. For example, if you wanted to create an alert_time rule that stretches from Monday 2300 (11 PM) to Tuesday 0700 (7 AM). The format would be:

**alert_time: days 1, hours 2300-0800;**

You do not need to include Tuesday (2) in the "days" option. Since the times stretch between two days, Sagan will automatically take this into consideration and make the adjustments. If you were to include "days 12", this would cause Sagan to alert on Monday-Tueday between 2300 - 0800 and Tuesday-Wednesday 2300-0800.

alert_time can also be used with sagan.yaml variables. For example, if you have "SAGAN_DAYS: 12345" and "SAGAN_HOURS: 0800-1300" in your sagan.yaml (see "aetas-groups" in your sagan.yaml), you could then create a rule like this:

**alert_time: days $SAGAN_DAYS, hours $SAGAN_HOURS;**

blacklist
---------

.. option:: blacklist {by_src|by_dst|both|all};

This looks up the TCP/IP address that was parsed via ``normalize``, ``parse_src_ip`` or ``parse_dst_ip`` 
from a "blacklist" file.  The "blacklist" file is a file that contains IPv4 and IPv6 addresses in CIDR
notation from that file.  In order to use this option the ``sagan.yaml`` processors ``blacklist`` must 
be enabled.

**blacklist: by_src; parse_src_ip: 1;**

bluedot
-------

.. option:: bluedot: type {ip_reputation},track {src|dst|both|all},{none|mdate_effective_period|cdate_effective_period},{category};
.. option:: bluedot: type {file_hash|url|filename},{category};

Bluedot is Quadrant Information Security's Threat Intelligence database that Sagan can query.  In order to use
this functionality you will need a Quadrant Information Security API key and have the ``bluedot`` processors 
enabled. 

As Sagan extracts data like IP addresses, file hashes, URLs and filenames,  Sagan can query the Bluedot
database to determine if they are hostile or not.  These types of lookups can be incorporated into 
signatures.  For example:

**bluedot: type ip_reputation, track by_src, none, Malicious,Tor,Honeypot,Proxy;**

This will lookup the source IP out of the Bluedot database for `Malicious`, `Tor`, `Honeypot` or 
`Proxy` activity.  If the source IP address is found in any of these categories,  the option will
fire. 

In some cases, you might not want to trigger on older IoCs.  To filter out older data from Bluedot
you can use the ``mdate_effective_period`` (last modification of the IoC) or ``cdate_effective_period`` 
(creation date of the IoC).  For example:

**bluedot: type ip_reputation, track all, mdate_effective_period 1 months, Malicious,Tor,Proxy;**

This will query all TCP/IP addresses found in a log line and query for `Malicious`, `Tor` and `Proxy`
addresses that are no older than one month old.  If the time is set to ``none``,  then any IoCs found
for a TCP/IP address are returned reguarless of ``mdate_effective_period`` or ``cdate_effective_perid``.

Below is an example of querying a file hash in Bluedot

**bluedot: type file_hash,Malicious; parse_hash: sha1;**

**Note: Quadrant Information Secrity Bluedot is not yet available to the public.**

zeek-intel
----------

.. option:: zeek-intel: {src_ipaddr},{dst_ipaddr},{both_ipaddr},{all_ipaddr},{file_hash},{url},{software},{email},{user_name},{file_name},{cert_hash};

**Note: This option used to be known as "bro-intel"**

This keyword allows Sagan to look up malicious IP addresses, file hashes, URLs, software, email, user names, and certificate hashes from Bro Intelligence feeds.

In order for the processors to be used, they must be enabled in your sagan.yaml file.

The following is a simple example within a Sagan rule:

**zeek-intel: src_ipaddr;**

This informs Sagan to look up the parsed source address from the Bro Intel::ADDR data. The parsed source address is extracted via liblognorm or parse_src_ip.

Multiple keywords can be used. For example:

**zeek-intel: both_ipaddr, domain, url;**

This instructs Sagan to look up the parsed source and destination from the Bro Intel::ADDR data. It also looks up the Intel::DOMAIN and Intel::URL. If any of the "zeek-intel" lookups return with a positive hit, the zeek-intel option is triggered. Consider the following example:

**content: “thisisatest”; zeek-intel: src_ipaddr;**

If a log message contains the term “thisisatest” but the parsed source IP address is not found in the Bro Intelligence feeds, the rule will not trigger. If the log message “thisisatest” is found and the src_ipaddr is found, the rule will trigger.

Sagan "zeek-intel" types::

   src_ipaddr	Intel::ADDR             Look up the parsed source address
   dst_ipaddr	Intel::ADDR	        Look up the parsed destination address
   all_ipaddr	Intel::ADDR	        Search all IP addresses in a log message and look them up
   both_ipaddr	Intel::ADDR	        Look up the parsed source & destination address
   file_hash	Intel::FILE_HASH	Search message content for malicious file hash
   url	        Intel::URL	        Search message content for malicious URL
   software	Intel::SOFTWARE	        Search message content for malicious software
   email	Intel::EMAIL	        Search message content for malicious email
   user_name	Intel::USER_NAME	Search message content for malicious user names
   file_nasm	Intel::FILE_NAME	Search message content for malicious file names
   cert_has	Intel::CERT_HASH	Search message content for malicious certificate hashes


classtype
---------

.. option:: classtype: {classification}

This links the rule to a classification. Classification can be used to determine priority level. For example:

**classtype: exploit-attempt;**

A "exploit-attempt" classification is a priority 1 (highest) level event. For a complete list of classification types, see http://github.com/beave/sagan-rules/blob/master/classification.config

content
-------

content is a simple means of determining if the {search} string is in an event/syslog message. For example:

**content: "authentication failure";**

Will search a log message for the term "authentication failure". content can also be used as part of a NOT statement. For example:

**content:!"frank";**

This means that the message does NOT contain the term "frank". Tied together, we can make statements like:

**content: "authentication failure"; content:!"frank";**

If the term "authentication failure" is found and does NOT contain the term "frank", then the rule will trigger. Otherwise, the event is ignored.

**content: "User Agent|3a| Testing";**

This tells content to search for "User Agent: Testing". The |3a| is a hex encoded option for a ":". You can use multiple hex encoded options. For example, "|3a 3b 3c|". Hex values can also be broken up. For example, "This |3a| is a testing with |3b| in it".

country_code
------------

.. option:: country_code: track {by_src|by_dst}, {is|isnot} {ISO3166 Country Codes}

Used to track events from specific countries.

**country_code: track by_src, isnot US;**

The example above means, "track by the source address of the event. If the GeoIP 2 location is not from the United States, trigger the rule".

**country_code: track by_dst, is [CN,RU,HK];**

The example above means, "track by the destination address of the event. If the GeoIP 2 location is going to China, Russia or Hong Kong, trigger the rule".

Country codes are based on ISO3166. See http://dev.maxmind.com/geoip/legacy/codes/iso3166/ for the full listing.

Typically, country codes are tied to the sagan.yaml variable $HOME_COUNTRY (See "geoip-groups" in the sagan.yaml). For example:

**country_code: track by_src, isnot $HOME_COUNTRY;**

Note: This requires GeoIP2 support to be compiled into Sagan

default_proto
-------------

.. option:: default_proto: {tcp/udp/icmp}

The default_proto sets the default protocol in the event normalization fails. For example, OpenSSH uses the TCP protocol. However, OpenSSH log messages do not specify the protocol in use. By using the rule option default_proto, Sagan will assign the protocol specified by the rule writer when triggered. This option can be overridden by parse_proto or liblognorm (if used).

Valid values are icmp, tcp and udp or defined variables (ie - "$PROTOCOL"). Defaults to the Sagan YAML "default-proto".

default_dst_port
----------------

.. option:: default_dst_port: {port number}

The default_dst_port sets the default port number in the event normalization fails. For example, OpenSSH typically uses port 22. However, OpenSSH log messages do not specify the port being used. By using the rule option default_dst_port, Sagan will assign the port specified by the rule writer when triggered. This option can be overriden by liblognorm.

Valid values are integers (1-63556) or defined variables (ie - "$SSH_PORT"). Defaults to the Sagan YAML "default-port".

default_src_port
----------------

.. option:: default_src_port: {port number}

The default_src_port sets the default port number in the event normalization fails. For example, if a log message does not contain the source port, this value is used instead. This can be overridden by liblognorm.

Valid values are integers (1-63556) or defined variables (ie - "$SOURCE_PORT). Defaults to the Sagan YAML "default-port".

Note: This requires GeoIP support to be compiled into Sagan

depth
-----

.. option:: depth: {depth value}

The depth keyword allows the rule writer to specify how far into a log line Sagan should search for the specified pattern from a given offset.

For example:

**content: "bob"; depth: 10;**

This would start searching at the begining of the log line (default offset: 0) and search only 10 bytes deep for the term "bob".

Example with offset and depth used together:

**content: "bob"; offset: 5; depth: 10;**

Sagan will start searching for the term "bob" when it gets to 5 bytes into the log line (see offset). It will only search for "bob" after the offset for 10 bytes.

This function is identical to Snort's "depth" rule option. For more information see: http://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html

distance
--------

.. option:: distance: {distance value}

The distance keyword allows the rule writer to specify how far into a log line Sagan should ignore before starting to search for the specified pattern relative to the end of the previous pattern match.

For example:

**content:"GET"; depth:3; content:"downloads"; distance:10;**

This will cause Sagan to look for the word "GET" within the first 3 bytes ( depth) of the log line. The next content will start looking for the term "downloads" 10 bytes away from the previous depth. The above would match on the term "GET /content/downloads" but not "GET /download". The " /content/" (10 bytes) is skipped over in the distance.

This function is identical to Snort's "distance" rule option. For more information see: http://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html

dynamic_load
------------

.. option:: {dynamic_load: /path/to/rules/to/load}

This option works in conjunction with the ``sagan.yaml`` ``dynamic_load`` configuration.  When a rule is 
triggered with this option enabled,  Sagan will dynamically load the rules.  This is useful for detecting
new logs introduced to the system where rules are not enabled.   For more information,  see
https://quadrantsec.com/about/blog/dynamic_rules_with_sagan/

**dynamic_load: $RULE_PATH/oracle.rules;**


email
-----

.. option:: email: {email address}

If present in a rule, Sagan will e-mail the event to the email address supplied.

**email: bob@example.org;**

Note: This requires Sagan to be compiled with libesmtp support.  

external
--------

.. option:: external: {path/and/program};

When a signature triggers with the ``external`` option,  the ``external`` target is executed.  The
``external`` program can be in any language you desire.  Data is passed from Sagan via ``stdin`` to the
``external`` program.  The information that is passed is the signature ID, the message (``msg``), 
the ``classtype``, drop, ``priority``, data, time, source IP, source port, destination IP, destination
port, facility, syslog priority, liblognorm JSON and the syslog message.

**external: /usr/local/bin/myprogram.py**

syslog_facility
---------------

.. option:: syslog_facility: {sylog facility}

Searches only messages from a specified facility.  This can be multiple facilities when separated with an '|' (or) symbol.

**facility: daemon;**

flexbits
--------

.. option:: flexbits: set, {flexbit name}, {expire time}; 

Note: ``flexbits`` are similar to ``xbits`` but can deal with more complex conditions (tracking ports, reverse direction tracking, etc).  However, in most cases you'll likely want to use ``xbits`` which are more simple and are likely to do what you need. 

The ``flexbis`` option is used in conjunection with ``unset``, ``isset``, ``isnotset``. This allows Sagan to "track" through multiple log events to trigger an alert. For example, lets say you want to detect when "anti-virus" has been disabled but is not related to a system reboot. Using the flexbit set you can turn on a flexbit when a system is being rebooted. Our flexbit set would look like this:

**flexbits: set, windows_reboot, 30;**

We are "setting" a flexbit named "windows_reboot" for 30 seconds. This means that thw "windows_reboot" fleflexbit will "expire" in 30 seconds. The flexbit set automatically records the source and destination of the message that triggered the event. It is important to point out, the source and destination addresses are what Sagan has normalized through parse_src_ip, parse_dst_ip or liblognorm.

**flexbits: {unset|isset|isnotset},{by_src|by_dst|both|reverse|none},{flexbit name}**

This option works in conjunction with the flexbit set option. In the flexbit set example above, we are trying to detect when a system's "anti-virus" has been disabled and is not related to a system reboot. If Sagan detects a system reboot, it will set flexbit "windows_reboot". Another rule can use the presence, or lack thereof, to trigger an event. For example:

**flexbits: isnotset, by_src, windows_reboot;**

This means, if the "windows_reboot" flexbit is not set (ie - it did not see any systems rebooting), trigger an event. The by_src tells Sagan that the trigger ( isnotset) is to be tracked by the "source" IP address. by_src, by_dst, both and none are valid options.

More examples:

**flexbits: isset, both, myflexbit;**

If the flexbit "myflexbit" "isset", then trigger an event/alert. Track by the source of the log message.

**flexbits: isnotset, both, myflexbit;**

If the flexbit "myflexbit" "isnotset", then trigger an event/alert. Track by both the source and desination of the message.

**flexbits: unset, both, myflexbit;**

This unset removes a flexbit from memory. In this example, unset is removing a flexbit "myflexbit" if the source and destination match (both).

Example of flexbit use can be found in the rules https://wiki.quadrantsec.com/twiki/bin/view/Main/5001880 and https://wiki.quadrantsec.com/twiki/bin/view/Main/5001881 . The first rule (5001880) "sets" a flexbit is a Microsoft Windows account is "created". The second rule (5001881) alerts an account is "enabled", but the flexbit has not (isnotset) set. In this example, it's normal for a user's account to be "created and then enabled". However, there might be an anomaly if an account goes from a "disabled" and then "enabled" state without being "created".

**flexbits: {noalert|nounified2|noeve}**

This tells Sagan to not record certain types of data with ``flexlbits`` when a condition is met.  For example, you might not want to generate an alert when a ``xbits`` is ``set``. 

flexbits_pause
--------------

 .. option:: flexbits_pause: {seconds}; 

This tells the flexbit ``isset`` or ``isnotset`` to 'wait' for a specified number of seconds before checking the flexbit state.                                                                                                                                                                                                     
flexbits_upause
---------------

.. option:: flexbits_upause: {microseconds}; 

This tells the flexbit ``isset`` or ``isnotset`` to 'wait' for a specified number of microseconds before checking the flexbit state. 

fwsam
-----

.. option:: fwsam: {src|dst}, {number} {second|minute|hour|day|week|month|year}


This informs Sagan that if the rule is successfully trigged, the source or destination IP address should be automatically firewalled via the "Snortsam" facility.

**fwsam: src, 1 day;**

This would firewall the offending source for 1 day. For more information about Snortsam, see: http://www.snortsam.net

syslog_level
------------

.. option:: syslog_level: {syslog level};

Seaches only messages from a specified syslog level.  This can be multiple levels when seperated by a '|' (or) symbol.

**level: notice;**

meta_content
------------

.. option:: meta_content: "string %sagan% string",$VAR;

This option allows you to create a content like rule option that functions with variable content. For example, let's say you want to trigger on the strings "Usernname: bob", "Username: frank" and "Username: mary". Without meta_content, this example would require three separate rules with content keywords. The meta_content allows you to make one rule option with multiple variables. For example:

**meta_content: "Username|3a| %sagan%", $USERS;**

Note: The |3a| is the hexidecimal representation of a ':' .

The %sagan% variable is populated with the values in $USERS. To populate the $USER variable, the sagan.conf would have the following variable declaration:

**var USERS [bob, frank, mary]**

If Sagan detects "Username: bob", "Username: frank" or "Username: mary", an event will be triggered.

Like content the ! can be applied. The ! is a "not" operator. For example:

**meta_content:!"Username|3a| %sagan%", $USERS;**

This will only trigger an event if the content is not "Username: bob", "Username: frank" or "Username: mary". That is, the content must not have any of the values.

The %sagan% portion of meta_content is used to specify "where" to put the $USERS defined variable. For example:

**meta_content: "Username|3a| %sagan% is correct", $USERS;**

Will look for "Username: bob is correct", "Username: frank is correct" and "Username: mary is correct".

meta_depth
----------

.. option:: meta_depth: {depth value}

Functions the same as depth for content but for meta_content. The meta_depth keyword allows the rule writer to specify how far into a log line Sagan should search for the specified patterns from a given offset.

For example, if $VAR is set to "mary, frank, bob":

**meta_content: "%sagan%", $VAR; meta_depth: 10;**

This would start searching at the begining of the log line (default meta_ offset: 0) and search only 10 bytes deep for the term "mary", "frank" or "bob".

Example with offset and depth used together:

**meta_content: "bob"; meta_offset: 5; meta_depth: 10;**

Sagan will start searching for the term "mary", "frank" or "bob" when it gets to 5 bytes into the log line (see meta_offset). It will only search for "mary", "frank" or "bob" after the offset for 10 bytes.

This function is identical to Snort's "depth" rule option. For more information see: http://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html

meta_distance
-------------

.. option:: meta_distance: {distance value}

Functions the same as distance for content but for meta_content. The meta_distance keyword allows the rule writer to specify how far into a log line Sagan should ignore before starting to search for the specified patterns relative to the end of the previous pattern match.

For example, if $VAR1 is set to "GET" and "POST" and $VAR2 is set to "download" and "upload":

**meta_content:"%sagan%", $VAR1; meta_depth: 4; meta_content:"%sagan%", $VAR2; meta_distance:10;**

This will cause Sagan to look for the word "GET" or "POST" within the first 4 bytes (meta_depth) of the log line. The next meta_content will start looking for the term "download" or "upload" 10 bytes away from the previous meta_depth. The above would match on the term "GET /content/downloads" but not "GET /download". The " /content/" (10 bytes) is skipped over in the distance.

This function is identical to Snort's "distance" rule option. For more information see: http://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html

meta_offset
-----------

.. option:: meta_offset: {offset value};

Functions the same as offset for content but for meta_content. The meta_offset keyword allows the rule writer to specify where to start searching for a pattern within a log line. This is used in conjunction with content.

For example, $VAR is set to "mary", "frank" and "bob".

**meta_content: "%sagan%", $VAR; meta_offset: 5;**

This informs meta_content to start searching for the term "mary", "frank" or "bob" after it is 5 bytes into the log line.

This function is identical to Snort's "offset" rule option. For more information see: http://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html

meta_nocase
-----------

This makes the previous meta_content option case insensitive.

**meta_content: "Username: ", $USERS; meta_nocase;**

If $USERS is populated with "bob", "frank" and "mary", meta_content will ignore the case. That is, "Username: mary" and "Username: MARY" will be detected. Without the meta_nocase, meta_content is case sensitive.

meta_within
-----------

.. option:: meta_within: {within value};

Functions the same as within for content but for meta_content. The within keyword is a meta_content modifier that makes sure that at most N bytes are between pattern matches using the meta_content keyword.

For example, $VAR1 is set to "GET" and "POST", while $VAR2 is set to "downloads" and "uploads";

**meta_content:"%sagan", $VAR1; meta_depth:4; meta_content:"%sagan%", $VAR2; meta_distance:10; meta_within:9;**

The first meta_content would ony match on the world "GET" or "POST" if it is contained within the first 4 bytes of the log line. The second meta_content looks for the term "downloads" or "uploads" if it is a meta_distance of 10 bytes away from the meta_depth. From the meta_distance, only the first 9 bytes are examined for the term "downloads" or "uploads" (which is 9 bytes).

This function is identical to Snort's "within" rule option. For more information see: http://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html

msg
---

.. option:: msg: "human readable message";

The "human readable" message or description of the signature.

**msg: "Invalid Password";**

nocase
------

.. option:: nocase

Used after and in conjuction with the "content" option. This forces the previous content to search for the {search} string regardless of case.

**content: "sagan"; nocase;**

This would search for the term "sagan" regardless of its case (ie - Sagan, SAGAN, etc).

normalize
---------

.. option:: normalize;

Informs Sagan to "normalize" the syslog message using the LibLogNorm library and Sagan "rulebase" data.

offset
------

.. option:: offset: {offset value};

The offset keyword allows the rule writer to specify where to start searching for a pattern within a log line. This is used in conjunction with content.

For example:

**content: "bob"; offset: 5;**

This informs content to start searching for the term "bob" after it is 5 bytes into the log line.

This function is identical to Snort's "offset" rule option. For more information see: http://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html

parse_dst_ip
------------

.. option:: parse_dst_ip: {destination position}

Uses Sagan's dynamic IP parsing to locate the "destination" address within a syslog message.

**parse_dst_ip: 2;**

The second IP address found within the syslog message will be used as the destination address. This is useful when LibLogNorm fails, is too difficult to use, or the syslog message is dynamic.

parse_port
----------

.. option:: parse_port;

Attempts to determine the "source port" used from the contents of a syslog message. For example, Bind/DNS messages look something like; "client 32.97.110.50#22865". The "22865" is the source port. Sagan will attempt to extract and normalize this information.

parse_proto
-----------

.. option:: parse_proto;

Attempts to determine the protocol in the syslog message. If the syslog message contains terms in the "protocol.map" (for example, ICMP, UDP, TCP, etc), Sagan assigns the protocol to the assigned value. See fields assigned as "message" in the protocol.map.

parse_proto_program
-------------------

Attempts to determine the protocol by the program generating the message. Values are assigned from the "protocol.map" (program fields). For example, if the program is "sshd" and the parse_proto_program option is used, TCP is assigned.

parse_hash
----------

.. option:: parse_hash: {md5|sha1|sha256};

Parses a hash out of a log message. 

**parse_hash: sha256;**

parse_src_ip
------------

.. option:: parse_src_ip: {source position};

Uses Sagan's dynamic IP parsing to locate the "source" address within a syslog message.

**parse_src_ip: 1;**

The first IP address found within the syslog message will be used as the source address. This is useful when LibLogNorm fails, is too difficult to use, or the syslog message is dynamic.

pcre
----

.. option:: pcre: "{regular expression}"

"Perl Compatible Regular Expressions" (pcre) lets Sagan search syslog messages using "regular expressions". While regular expressions are powerful, they do require slightly more CPU to use. When possible, use the "content" option.

**pcre: "/broken system|breaking system/i";**

Looks for the term "broken system" or "breaking system" regardless of the strings case.

priority
--------

priority: {priority};

Sets the prority of an alert/signature.

**priority: 1;**

If ``priority`` is set, it will override the ``classtype`` priority.

program
-------

.. option:: program: {program name|another program name}

Search only message that are from the {program}. For example:

**program: sshd;**

This will search the syslog message when it is from "sshd". This option can be used with multiple OR's. For example:

**program: sshd|openssh;**

This will search the syslog message when the program that generated it is "sshd" OR "openssh".

reference
----------

.. option:: reference: {reference name}, {reference url}

Sets a reference for the signature/alert. These can be pointers to documentation that will provide more information regarding the alert.

**reference: url, www.quadrantsec.com;**

If the signature/alert is triggered, the reference will be "http://www.quadrantsec.com".

**reference: cve,999-0531;**

Will lookup CVE 999-0531 from http://cve.mitre.org/cgi-bin/cvename.cgi (from the ``references.config`` file). 

rev
---

.. option:: rev: {revision number};

Revision number of the rule. Increment this when a rule is changed.

**rev: 5;**

Revision number 5 of the rule.

sid
---

.. option:: sid: {signature id};

"sid" is the signature ID. This has to be unique per signature.

**sid: 5001021;**

Sagan signatures start at 5000000. To view the "last used" signature, see https://github.com/beave/sagan-rules/blob/master/.last_used_sid

syslog_tag
----------

.. option:: syslog_tag: {syslog tag};

Informs Sagan to only search syslog messages with the specified tag.  This can be multiple tags when separated with an '|' (or) symbol.

**tag: 2d;**

threshold
---------

.. option:: threshold: type {limit|threshold}, track {by_src|by_dst|by_username|by_string}, count {number of event}, seconds {number of seconds}

This allows Sagan to threshold alerts based on the volume of alerts over a specified amount of time.

**threshold: type limit, track by_src, count 5, seconds 300;**

Sagan will limit the amount of alerts via the source IP address if the count exceeds 5 within a 300 second (5 minute) period.

You can also 'track' by multiple types.  For example:

**threshold: type limit, track by_src&by_usernme, count 5, seconds 300;**

The above would threshold by the source IP address and by the username. 

within
------

.. option:: within: {within value};

The within keyword is a content modifier that makes sure that at most N bytes are between pattern matches using the content keyword.

For example:

**content:"GET"; depth:3; content:"downloads"; distance:10; within:9;**

The first content would ony match on the word "GET" if it is contained within the first 3 bytes of the log line. The second content looks for the term "downloads" if it is a distance of 10 bytes away from the depth. From the distance, only the first 9 bytes are examined for the term "downloads" (which is 9 bytes).

This function is identical to Snort's "within" rule option. For more information see: http://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html


xbits
-----

.. option:: xbits:{set|unset|isset},{name},track {ip_src|ip_dst|ip_pair} [,expire <seconds>];

The ``xbits`` rule keyword allows you to track and correlate events between multiple logs.  This is done by detecting an event and using the ``set`` for Sagan to "remember" an event.  Later,  if another event is detected,  xbit can be tested via ``isset`` or ``isnotset`` to determine if an event happened earlier.  For example,  lets say you would like to detect when anti-virus is being shutdown but **not** if it is related to a system reboot or shutdown.  

When Sagan detects a shutdown/reboot,  Sagan can ``set`` an xbit. For this example, we will name the xbit being set 'system.reboot'.  WHen Sagan sees the anti-virus being shutdwn, Sagan can test to see if the xbit 'system.reboot' is set (``isset``) or is not set (``isnotset``).  In our case, if the xbit named 'system.reboot' ``isnotset``, we know that the anti-virus is being shutdown and is NOT related to a system reboot/shutdown. 

Using ``xbis`` can be useful in detecting successful attacks.  Another example would be the Sagan 'brute_force' xbit.  Sagan monitors "brute force" attacks and ``sets`` an xbit associated to the source IP address (the 'brute_force' xbit).  If Sagan later detects a successful login,  we can test via the xbit (``isset``) to determine if the IP address has been associated with brute force attacks in the past. 

Below is an example to set an xbit by the source IP address. 

**xbits: set,brute_force,track ip_src, expire 21600;**

This will set an xbit named 'brute_force' by the source address.  The xbit will expire in 21000 seconds (6 hours). 

To check the xbit later, use the ``isset`` or ``isnotset`` condition.  For example:

**xbits: isset,brute_force,track ip_src;** 

If the xbit 'brute_force' was already set and is within the expire time,  the ``isset`` will return "true" (and fire).  The "track ip_src" on the ``isset`` or ``isnotset`` will compare the ip_src or the ``isset`` or ``isnotset`` rule with the ``set`` condition.  

In certain situations, you may want to have a rule ``unset`` an xbit.  This effectively "clears" the xbit. For example:

**xbits: unset,brute_force,track ip_src;**

In some situations,  you might not want Sagan to record data when a ``xbit`` condition is met.  For example, if you ``set`` an xbit,  you might not want to generate an alert.   To disable certain types of output, you can do this:

**xbits: {noalert|nounified2|noeve}**

xbits_pause
-----------

.. option:: xbits_pause: {seconds}; 

This tells the xbit ``isset`` or ``isnotset`` to 'wait' for a specified number of seconds before checking the xbit state.

xbits_upause
------------

.. option:: xbits_upause: {microseconds}; 

This tells the xbit ``isset`` or ``isnotset`` to 'wait' for a specified number of microseconds before checking the xbit state.  



