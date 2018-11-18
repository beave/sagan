Dynamic Rules with Sagan.
=========================

Posted by Champ Clark on November 14, 2016

One of the biggest problems faced with log monitoring is ensuring that the proper rules are loaded. Just like with packet based IDS systems, during the installation and setup process, you typically enable the rules that you think are relevant to your environment. The problem is, environments change over time and we might neglect to go back and determine if the original rules we enabled are still relevant. The idea behind “dynamic rules” is to detect changes in the logging infrastructure and make adjustments by “dynamically” loading rules and letting you and your staff know.

It is pretty common for networks to change over time. For example, let’s say that during deployment of Sagan in your network it was analyzing Linux, Windows, and Palo Alto firewall logs. Two years later, your organization decides to replace its Palo Altos with Cisco ASA firewalls; have you made the appropriate changes to your monitoring infrastructure to take into account the Palo Alto to Cisco ASA Switch? It’s an easy thing to forget and miss.

The idea is to have Sagan “see” the changes and “dynamically” load the rules and alert you to the fact.

To detect the change, we have created a “dynamic.rules” rule set that utilizes the power of the Sagan rule structure. The idea is that we can create rules that will “detect” when Sagan “sees” new logs entering the system. The “dynamic.rules” watches for characteristics of various log types and when they are detected, responds by loading the rules and alerting your staff.

One thing we don’t want to do is take away CPU cycles from normal analysis to detect “new” logs. Think of it this way, the more “signatures” you feed Sagan, or any IDS system, the more CPU it takes to process data through them. Increasing your total signature size increases your load.

We have gotten around the CPU load problem by creating a “sample” rate. We don’t necessarily want to examine every log received to determine if it’s “new” to the system or not. With a “sample” rate, we tell Sagan to only examine every X log for “new” content. This is done by utilizing the “dynamic_load” processor with the “dynamic.rules”. The “processor” line looks like this in your “sagan.conf”:

 

**processor dynamic_load: sample_rate=100 type=dynamic_load********

 

The sample_rate is set to 100. This means that every 100th log line received, Sagan will examine it for “new” characteristics. If the log line is determined to be “new” to the system via the “dynamic.rules”, dynamic_load (via the “type=”) tells Sagan to load the associated rule set. Possible options for “types” are dynamic_load, which logs and writes a unified2 record and loads the associated rule set. The log_only type tells Sagan to simply write out to the sagan.log file that it has detected a new log type. The alert tells Sagan to create a single unified2 record (an alert) that it has detected a new log type.

The use of the sample_rate greatly reduces the CPU load and allows for the amount of fine-tuning that you feel comfortable with. A sample_rate of 100 means you’ll use 1/100 CPU time for new log detection. You could increase the sample_rate but then it might take longer to detect “new” logs entering the system. Alternatively, you could decrease the sample_rate, which will detect new logs entering Sagan faster, but use more CPU.

For the time being and for the purposes of our testing, a default of 100 seems to be a good starting place.

Now that we’ve determined the amount of data we want to process for “new” logs, let’s look into an example of “dynamic.rules”:


**alert syslog $EXTERNAL_NET any -> $HOME_NET any (msg: "[DYNAMIC] Cisco ASA logs detected via program."; program: %ASA*|%FWSM*; dynamic_load: $RULE_PATH/cisco-pixasa.rules; classtype: dynamic-rules; reference: url,wiki.quadrantsec.com/bin/view/Main/5002967; sid:5002967; rev:2;)**


Note the new dynamic_load rule option. This tells Sagan that this is a “dynamic” rule that should follow the configurations set by the “dynamic_load” processor. It also informs Sagan “what” to load when a “new” log type is detected. Note that you can use sagan.conf configuration variables within the rule (i.e. - $RULE_PATH).

The rest of the rule works like a normal Sagan rule. In this simple example, we know that Cisco ASA's typically uses the “program” of %ASA-{number-code}. If Sagan sees a log line with a program of %ASA-* and Sagan has not previously loaded the “cisco-pixasa.rules”, it will automatically load them and trigger a log/unified2 alert.

One interesting result we’ve seen in testing is using “dynamic.rules” to tell the user what rules to load! For example, we could start Sagan without any normal non-dynamic rules enabled. That is, the only rules enabled would be “dynamic.rules”. Sagan could then inform the user what rules it would load. With that data, the user could manually load those and other associated rules (geoip rules, malware rules, etc).

Detection of changes to infrastructure is very important. Using “dynamic.rules” allows you to detect those changes quickly and automatically adjust.


