Sagan Flowbit
=============

Posted by Kat Casey on June 08, 2015
These insights were provided by the expertise of Rob Nunley.

**(Update: November 17th, 2018 - The term 'flowbit' is really tied to 'xbit')**

Daniel Kahneman is a Doctor of Psychology who was awarded the Nobel Prize in Economic Sciences in 2002 (http://www.princeton.edu/~kahneman/).  It may seem strange, initially, that a Psychologist would win one of the most world-renowned economics awards, but Dr. Kahneman’s contributions can be applied to many fields; this includes cybersecurity.  Dr. Kahneman’s primary contribution was related to “human judgment and decision-making under uncertainty” (http://www.nobelprize.org/nobel_prizes/economic-sciences/laureates/2002/kahneman-facts.html), of which he has performed a great deal of research and experimentation.

Dr. Kahneman, who often performed experiments with Dr. Amos Tversky, may be best known for his research into System 1 and System 2 thinking.  System 1 thinking uses heuristics, or quick and dirty “rules”, to make instant and subconscious decisions.  System 2 thinking involves logical and conscious thought to make decisions.  Heuristics are susceptible to a number of systematic errors and pitfalls, but heuristics serve a purpose. (http://people.hss.caltech.edu/~camerer/Ec101/JudgementUncertainty.pdf).

Just as with everyday life, heuristics are often sufficient for many tasks and that utility extends to the realm network monitoring via NIDS and log analyses.  Log messages contain information detailing the occurrence of an event.  At best, a log message might indicate the source and destination of an action, the user(s) involved in the action, the catalyst of an action, and the outcome of an action.  At worst, a log message may contain any one, or none, of those items.  Sagan uses two primary methods for alert detection:  heuristics (i.e., “rules” or signatures) and processors (e.g., reputational lookup of IP addresses).  Some conclusions derived from the application of heuristics are valid—“login failure for user root from src IP 1.2.3.4” is pretty straightforward.  A single log message is not always a valid indicator of an event, however, as we will explore below:

**4722: A user account was enabled.

Subject:
   Security ID:  ACME\administrator
   Account Name:  administrator
   Account Domain:  ACME
   Logon ID:  0x20bad

Target Account:
   Security ID:  ACME\Humpty.Dumpty
   Account Name:  Humpty-Dumpty
   Account Domain:  ACME**

The above log message clearly states that “A user account was enabled”, so what is the confusion?  The log message, by itself, is missing context.  If a Windows account is disabled and re-enabled, only the above log message will appear.  If an account is created, however, there are always two messages created: 4720: A user account was created and 4722: A user account was enabled.

A Sagan feature developed specifically for the clustering of indicators in order to apply context to heuristics-based detection is flowbit.  Flowbit, while not true System 2 thinking, empowers Sagan with the ability to trigger alerts for specific events only in the presence or absence of other events.  Flowbits are given unique names based on what they are being used for (e.g., “created_enabled”).  Sagan can measure for the presence or absence of events with flowbit by using a “flag” to represent whether or not a flowbit is set.  An example of Sagan applying context for more informed decision-making can be observed by revisiting the Windows user account enabled example.

If a Windows account is disabled and re-enabled, there is no “account re-enabled” event.  Instead, research was required to identify indicators and to find unique indicators which could be used for diagnosticity.  As mentioned previously, creation of a new Windows account generates log messages for both enabled and created, but re-enabled accounts only generate account enabled events.  The signatures below are used to determine when a Windows account has been re-enabled.

**alert syslog $EXTERNAL_NET any -> $HOME_NET any (msg:"[WINDOWS-AUTH] User account created [FLOWBIT SET]"; content: " 4720: "; program: Security*; classtype: successful-user; flowbits: set, created_enabled, 30; flowbits: noalert; reference: url,wiki.quadrantsec.com/bin/view/Main/5001880; sid: 5001880; rev:3;)

alert syslog $EXTERNAL_NET any -> $HOME_NET any (msg:"[WINDOWS-AUTH] User account re-enabled"; content: " 4722: "; content:! "$" ;program: Security*; flowbits: isnotset, by_src, created_enabled; classtype: successful-user; reference: url,wiki.quadrantsec.com/bin/view/Main/5001881; sid: 5001881; rev:3;)**

The first flowbit field in the first signature (sid: 5001880) notifies Sagan by using the flowbit command “set”, provides a unique name for the flowbit, and declares how long the flowbit should remain active.

**flowbits: set, created_enabled, 30**

The flowbit details are stored in memory along with other information such as IP addresses involved.  The second flowbit field in the first signature instructs Sagan not to produce an alert if this rule is triggered.

**flowbits: noalert**

The second signature contains only a single flowbit field, but this is what determines if an alert will trigger.  This signature instructs Sagan that, if all other criteria for the signature match, check the flowbit table for a flowbit named created_enabled where the source IP address matches the newly identified source IP address (by_src).  If the flowbit does not exist (isnotset), generate an alert stating that a user account has been re-enabled.

**flowbits: isnotset, by_src, created_enabled**

If there is still some confusion, we can examine once again why we are looking for a flowbit that does not exist in this scenario.

User account created
created message && enabled message

User account re-enabled
enabled message

If it is our intention to know when an account has been re-enabled, we do not want to trigger on any account enabled messages following an user account created message for the same source IP address.  Context is provided by the presence or absence of the user account created message combined with the IP address being tracked.

Flowbit consists of three basic functions:

**flowbits: set, (flowbit name), (expire time);**

Instructs Sagan to create an entry in memory for the unique flowbit name for the duration, in seconds, given as an expire time.

**flowbits: (unset|isset|isnotset), (by_src|by_dst|both|reverse|none), (flowbit name);"**

Instructs Sagan how to respond to an alert with respect to a flowbit that has been set for a unique name.  Possible actions are checking if the flowbit is set or is not set, as well as unsetting the flowbit if it exists.  Search criteria is defined by tracking the source IP address, destination IP address, both IP addresses, the inverse of the original source and destination (i.e., source becomes destination / destination becomes source), or no tracking criteria.

**flowbits: noalert;**

This instructs Sagan not to generate an alert when a rule triggers, and is best used with initial indicators in a chain.
Although flowbit does not have many features by itself, its power comes by chaining, or clustering, events in a multitude of combinations.  Consider the following scenarios:

A Windows server shuts down normally, so logs are generated for each process that is killed.  If a message stating that anti-virus software has been killed is observed in conjunction with a message stating that a server is shutting down, then that is expected.  If a message stating that anti-virus software has been killed is observed but the server is not being shut down or restarted, then that is something that may be of interest to administrators and security analysts.

A user logging in to a system is normal.  Observing five-thousand login failures followed by a login success may be suspect.

What if we want to track more than two indicators in succession?  Sagan can handle that, too!  Not only can Sagan chain numerous indicators, but an initial indicator in a chain can be used by multiple secondary indicators.  Also, since Sagan can process whatever logs are sent to it, we can leverage Snort IDS logs to combine network events with system events.

Consider the following scenarios:

Snort logs (forwarded to Sagan) indicate a remote file inclusion attempt.  This sets the RFI flowbit.

The attack, which was successful, causes the web server to request a Perlbot file.  Sagan checks the RFI flowbit and, because the flowbit was set for the web server’s IP address, we can receive an alert notifying us that there was a successful RFI attack.

If we have another “flowbits: set” instruction in our “flowbits: isset” signature, we have the ability to extend our chain.  With reliable, valid indicators, we are able to receive increasingly relevant information with each additional signature.  Let’s extend the above scenario a little farther.

Snort logs (forwarded to Sagan) indicate a remote file inclusion attempt.  This sets the RFI flowbit.

The attack, which was successful, causes the web server to request a Perlbot file.  Sagan checks the RFI flowbit and, because the flowbit was set for the web server’s IP address, we can receive an alert notifying us that there was a successful RFI attack.  In addition to the alert, we set another flowbit called RFI_Download.

The web server runs a new process (detected via OSSEC, auditd, or some other service).  Since the RFI_Download flowbit is set, we know that the new process started by our web server may be of interest to incident responders, so Sagan can send us another alert!

We’ll discuss more advanced Sagan flowbit usage in a later blog post, but I hope that the example scenarios shown have at least opened the reader’s mind to the possibilities the power and potential of flowbit.

All forms of heuristics are prone to various limitations and shortcomings, but flowbit helps overcome some of the potential pitfalls inherent in heuristics-based detection.  Sagan’s flowbit can increase accuracy and reduce false positives by requiring multiple indicators, potentially from multiple sources, before triggering an alert.  Flowbit can be used to support incident responders, as shown above, by tracking indicators in real-time (this can also help with postmortem incident analysis).  Flowbit also ensures that events occur within the context in which they are relevant.

The possibilities are limited by creativity, observability of events, and diagnosticity of indicators.

