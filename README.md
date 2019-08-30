
<pre>
,-._,-.    Sagan, the advanced Suricata/Snort like log analysis engine!
\/)"(\/ 
 (_o_)     Champ Clark III & The Quadrant InfoSec Team [quadrantsec.com]
 /   \/)   Copyright (C) 2009-2019 Quadrant Information Security, et al.
(|| ||) 
 oo-oo  
</pre>


What is Sagan? 
--------------

Sagan is an open source (GNU/GPLv2) high performance, real-time log 
analysis & correlation engine.  It is written in C and uses a 
multi-threaded architecture to deliver high performance log & event 
analysis. The Sagan structure and Sagan rules work similarly to the 
Suricata & Snort IDS engine. This was intentionally done to maintain 
compatibility with rule management software (oinkmaster/pulledpork/etc)
and allows Sagan to correlate log events with your IDS/IPS system. 

Sagan can write out to databases via Suricata EVE formats and/or 
Unified2, it is compatible with all Snort & Suricata consoles.  Sagan
can write also write out JSON which can be ingested by Elasticsearch
and viewed with console like Kibana, EVEbox, etc. 

Sagan supports many different output formats,  log normalization 
(via liblognorm),  GeoIP detection, script execution on event and
automatic firewall support via "Snortsam" (see http://www.snortsam.net).  

Sagan uses the GNU "artisic style". 

Sagan Features:
---------------

* Sagan’s multi-threaded architecture allows it to use all CPUs / cores for real-time log processing.
* Sagan's CPU and memory resources are light weight. 
* Sagan uses a similar rule syntax to Cisco’s “Snort” & Suricata which allows for easy rule management and correlation with Snort or Suricata IDS / IPS systems.
* Sagan can store alert data in Cisco’s “Snort” native “unified2” binary data format  or Suricata's JSON format for easier log-to-packet correlation.
* Sagan is compatible with popular graphical-base security consoles like Snorby, BASE, Sguil, and EveBox.   
* Sagan can easily export data from other SIEMs via syslog.
* Sagan can track events based on geographic locations via IP address source or destination data (e.g., identifying logins from strange geographic locations).
* Sagan can monitor usage based on time of day (e.g., writing a rule to trigger when an administrator logs in at 3:00 AM).
* Sagan has multiple means of parsing and extracting data through liblognorm or built in parsing rule options like parse_src_ip, parse_dst_ip, parse_port, parse_string, parse_hash (MD5, SHA1,SHA256).
* Sagan can query custom blacklists,  Bro Intel subscriptions like Critical Stack and “Bluedot”,  Quadrant Information Security threat intelligence feeds by IP address,  hashes (MD5, SHA1, SHA256),  URLs,  emails,  usernames, and much more.
* Sagan’s “client tracking” can inform you when machines start or stop logging.   This helps you verify that you are getting the data you need.
* Sagan uses “xbits” to correlate data between log events which allows Sagan to “remember” and flag events across multiple log lines and sources. 
* Sagan uses Intra-Process communications between Sagan processes to share data.   Sagan can also use Redis (beta) to share data between Sagan instances within a network.
* To help reduce “alert fatigue”,  Sagan can “threshold” or only alert “after” certain criteria have been met. 

Where can I get help with Sagan?
--------------------------------

For more general Sagan information, please visit the offical Sagan web site: 
https://sagan.quadrantsec.com. 

For Sagan documentation to assist with installation, rule writing, etc.  Check out:
https://sagan.readthedocs.io/en/latest/

For help & assistence,  check out the Sagan mailing list.  If it located at:
https://groups.google.com/forum/#!forum/sagan-users

If you're looking for Sagan rule sets on Github,  they are located at:
https://github.com/beave/sagan-rules

