
Welcome to the README file.
---------------------------

#What is Sagan? 

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

For more general Sagan information, please visit the offical Sagan web site: 
https://sagan.quadrantsec.com. 

For Sagan documentation to assist with installation, rule writing, etc.  Check out:
https://sagan.readthedocs.io/en/latest/

For help & assistence,  check out the Sagan mailing list.  If it located at:
https://groups.google.com/forum/#!forum/sagan-users

If you're looking for Sagan rule sets on Github,  they are located at:

https://github.com/beave/sagan-rules

