
Sagan output to other SIEMs
===========================

Posted by Champ Clark on November 06, 2014

Sagan is a very powerful engine at detecting threats contained in log data.  When Sagan detects something that it believes you should know about,   it can “output” these alerts in several formats.   The most popular and useful of these output formats is “Unified2”.   Unified2 is typically used by Snort,  Suricata and Sagan to record details about an event/alerts.    It records not only the payload,   or in Sagan's case,  the offending log message but other details as well.  The source,  destination IP address,  source and destination ports and much more.  

What makes this output format so powerful is that it gives Sagan the ability to put event and alert data in the same location as other utilities like Snort and Suricata.   This means you can view “threats” from “one pane of glass” (one console).   So instead of having IDS/IPS threats in one console and Sagan log analysis data in another,   it all gets stored in a unified location.  With that said,   there are power instances you might want to correlate more than just “threat” data.   For example,  you might was to send this data to a centralized log server.   If you are sending your Snort/Suricata data to a centralized log server,   then it likely makes sense you would like to do the same with Sagan data.  

This give you the ability to not only look at the threat data from Snort, Suricata and Sagan,  but other data “surrounding” the event.  

To do this,  we use Sagan's “syslog” output format.   This lets Sagan send events and alerts to the systems “syslog” facility.   These can then be forwarded to our centralized log server and/or SIEM.   As we've stated in pervious blog posts,   we try to maintain some compatibilty with Snort in some respects.   This allows Quadrant Information Security to work on creating the best log analysis engine without having to worry about things like rule management,  rule formats,  etc.

With this in mind,  it should come as no suprise that Sagan's “syslog” output format works very similar to Snort's “syslog” output format.    In your sagan.conf file,   you would add the following:

**output syslog: LOG_AUTH LOG_ALERT LOG_PID**

These are also the default settings for Sagan.   The output format in the configuration file is like this:

**output syslog: (facility) (priority) (syslog options)**

(Supported facilities: LOG_AUTH, LOG_AUTHPRIV, LOG_CRON, LOG_DAEMON, LOG_FTP, LOG_INSTALL, LOG_KERN, LOG_LPR, LOG_MAIL, LOG_NETINFO, LOG_RAS, LOG_REMOTEAUTH, LOG_NEWS, LOG_SYSLOG, LOG_USER, LOG_UUCP, LOG_LOCAL0,  LOG_LOCAL1, LOG_LOCAL2, LOG_LOCAL3, LOG_LOCAL4, LOG_LOCAL5, LOG_LOCAL6,  LOG_LOCAL7)

(Supported priorities: LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG)

(Supported options: LOG_CONS, LOG_NDELAY, LOG_PERROR, LOG_PID, LOG_NOWAIT)


With the syslog output configured,   Sagan can now generate messages to your local syslog daemon that look like this:


**sagan[8517]: [1:5002178:2] [OPENSSH] SSH login success after brute force attack! [Classification: Correlated Attack] [Priority: 1] {TCP} 10.10.10.10:42131 -> 10.10.10.11:22**

You might be thinking to yourself how similar the Sagan syslog message looks to a Snort or Suricata syslog message.   You would be correct! Sagan does this so that you might take advantage of Snort syslog parsers within your SIEM!  For example,   lets say you use Splunk to collect logs from your Snort IDS/IPS systems.   In Splunk,  you might have built a log parser to extract important data from Snort messages (source, destination, protocol, etc).  The same parser you use to extract useful information from your Snort logs will work with Sagan syslog data!  It just “works”.  No new parsing or data extraction techniques are needed. This idea applies to any SIEM technilogies (ELSA, Logstash,  etc). The final step is to get these Sagan log messages from your local system to your SIEM.   In order to do this,   we need the local syslog daemon to forward these events.   

If your system uses syslog-ng as a logging daemon,  you would want to add something like this to your syslog-ng configuration:

**filter f_sagan { program("sagan*"); };
destination f_sagan_siem { udp(“10.10.10.10” port 514); };
log { source(src); filter(f_sagan); destination(f_sagan_siem); };**

If your system uses rsyslog as a logging daemon,  you would want to add something like this to your rsyslog configurations.

**If $programname == 'sagan*' then @10.10.10.10:514**

For a older,  more traditional syslog daemon,  you would use something like this:

**auth.alert  @10.10.10.10**

(Note: “10.10.10.10” would be your SIEM.   After these changes are made,   your syslog daemon will likely need to be reset or restarted).

This will allows Sagan to directly send alerts via syslog.   I should note that if you use Barnyard2 with Sagan,  you've always had this ability!   One of the output formats Barnyard2 has is syslog!  In fact,   if you are using Barnyard2 with Sagan,  you'll likely want to enable the syslog output in your Barnyard2 configurations!  To configure with Barnyard2,  you would add this to your configuration:

**output alert_syslog: host=10.10.10.10:514, LOG_AUTH LOG_ALERT**

With this sort of setup,  Sagan can now share it's threat intelligence directly with your SIEM.

