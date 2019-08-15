What is Sagan?
==============

Sagan is a log analysis engine.   It was designed with a Security Operations Center (SOC) in mind.  
This makes Sagan’s operations different from most log analysis tools.  Sagan is designed and meant to analyze 
logs across many different platforms in many different locations.   A driving principle behind Sagan is for 
it to do the “heavy lifting” analysis before putting the event in front of a human.   Another driving principle 
is to do all analysis of logs in “real time”.   This is also a differentiating factor of Sagan.  In a SOC 
environment,  waiting for hours for analysis simply isn’t an option.  Delaying analysis gives an attacker an advantage in that they will have been in your network undetected during that lag time.   If you are a security professional reading this,  you likely understand the real-time aspects of packet analysis.  For example, security professionals would never accept prolonged delays in our Intrusion Detection and Intrusion Prevention engines.   Nor would reasonable security professionals find it acceptable to analyze packet data the next day for security related events.  With this in mind,  we demand our packet analysis engines to work in real time or close to it.   This premise is how projects like Snort (https://snort.org) and Suricata (https://suricata-ids.org) function. 

Sagan treats log data similar to how IDS or IPS treats packet data.  In fact,  Sagan treats the data so similarly,  that Sagan rules can confuse even the most seasoned security professionals.  



License
-------

Sagan is licensed under the GNU/GPL version 2. 
