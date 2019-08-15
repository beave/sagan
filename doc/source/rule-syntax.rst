Rule syntax
===========

Sagan rule syntax is very similar to that of `Suricata <https://suricata-ids.org`>_ or `Snort <https://snort.org>`_ .  This is was intentionally done to maintain compatibility with rule management software like ``oinkmaster``
and ``pulledpork`` and allows Sagan to correlate log events with your Snort/Suricata IDS/IPS system.

This also means that if you are already familiar with signature writing in Suricata and Snort,  you already 
understand the Sagan syntax! 

To understand the basic Sagan rule syntax,  we will be using the following simple rule.  This section of the
Sagan user guide only covers up to the first `rule option`.  That is,  this section will cover up to the 
``msg`` portion of this rule only.  The rest of the rule is considered ``rule options``.

Basic Sagan rule::

   alert any $EXTERNAL_NET any -> $HOME_NET any (msg: "[SYSLOG] System out of disk space"; pcre: "/file system full|No space left on device/i"; classtype: hardware-event; threshold: type limit, track by_src, count 1, seconds 300; reference: url,wiki.quadrantsec.com/bin/view/Main/5000116; sid:5000116; rev:2;)

.. option:: alert

This informs Sagan how to flag the event.  Valid options are ``alert`` or ``drop``.

.. option:: any

Valid options for this field are ``any``, ``tcp``, ``udp`` or ``icmp``.  In most cases,  you will 
likely want to specify ``any``.  The protocal is determined by the ``parse_proto`` or ``parse_program_proto``
rule options.  

.. option:: $EXTERNAL_NET

This informs Sagan where the source IP address or addresses must be coming from in order to trigger. By 
default the variable ``$EXTERAL_NET`` is used.  This is set in the ``sagan.yaml`` configurations file and
defaults to ``any``.  most cases,  "any" (any source) is what you want.   In other cases, 
you might want the signature to trigger when it is from a particular host.  For example:

**192.168.1.1**

Makes Sagan only trigger if the source of the event is from the address 192.168.1.1 (/32 is automatically
assumed).   You can also apply multiple networks.  For example:

**[192.168.1.0/24, 10.0.0.0/24]**

Is valid and will only trigger if the network address is within 192.168.1.0/24 or 10.0.0.0/24.  You can
also apply *not* logic to the addresses.  For example. 

**!192.168.1.1/32**

This will only trigger when the IP address is *not* 192.168.1.1. 

This filed is populated by whatever the source IP address within the log might be.  For example,  if the
signature lacks ``parse_src_ip`` or ``normalize`` (see rule options),  then the syslog source is adopted.
If ``parse_src_ip`` or ``normalize`` rule option is used,  then data (if any) that is extracted from the 
log is used.  

.. option:: any

The next ``any`` is the source port.  If the ``normalize`` or ``default_src_port`` rule option is used,  it will be applied here.  This can be useful in filtering out certain subnets or syslog clients. 

.. option:: ->

This would be the direction.  From the $EXTERNAL_NET ``->`` $HOME_NETWORK. 

.. option:: $HOME_NETWORK

This works similarly to how $EXTERNAL_NET functions.  Rather than being the source of the traffic,  this is 
the destination of the traffic.  Like $EXTERNAL_NET,  this is set in the ``sagan.yaml`` configuration file
and defaults to ``any``.  Also like the $EXTERNAL_NET,  network CIDR notation can be used ( ie - 192.168.1.0). 
Data from this is populated by the ``parse_dst_ip`` and ``normalize`` rule options.

.. option:: any

The final rule option is the destination port.  If the ``normalize`` or ``default_dst_port`` rule option is used,  it will be applied here.  This can be useful in filtering out events from certain subnets.

