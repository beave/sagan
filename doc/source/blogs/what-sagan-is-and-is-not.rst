
What the Sagan Log Analysis Engine Is... and What It Is Not.
============================================================

Posted by Champ Clark on August 22, 2016
Article by Champ Clark III.

With so many log analysis tools out there, we sometimes see strange comparisons between the Sagan log analysis engine and unrelated tools. For example, people often ask how Sagan compares to Splunk.  In our opinion, these are two different tools with two different jobs.

For one, the Sagan log analysis engine is a tool that was programmed completely with a focus on security.  Splunk and similar tools, on the other hand, are analysis and log archival search utilities with security focused functionality added on later. We aren’t suggesting that this is a bad thing, and it doesn’t mean that Splunk and similar tools are “bad.” But, as security tools they are attempting to accomplish different goals.

If anything, Sagan is more similar to tools like OSSEC, rather than Splunk.

What we are doing with Sagan is trying to detect the successful “bang” (attack) when it occurs. Robert Nunley turned me on to this military terminology some time ago and I think it applies to information security very well.

“To think about an attack on a timeline, bang is in the middle. Bang is the act. Bang is the IED explosion, the sniper taking a shot, or the beginning of an ambush.” (From the book “Left of Bang”; https://www.amazon.com/Left-Bang-Marine-Combat-Program/dp/1936891301)

“Left of bang” is before the attack has occurred.  The “bang” is the time of the attack and where Sagan does its best detection. Retro or non-real time detection of an attack is at the “right of bang,” where most log analysis tools operate today.

 At Quadrant, we are working with the “bang” and at the “right of bang.” Using technologies that operate at both time points allows our SOC to detect threats better.

Operating on the “left of bang” is more difficult to accomplish. We are proactively working to improve this within our BlueDot threat intelligence (part of Sagan), and this is also where projects like Quadrant's new “APT Deflector” (patent pending) come into play.

The idea behind Sagan is for it to treat logs similarly to how Snort (IDS) treats packets, in rapid, real- time analysis and correlation.  Let's examine these two statements.

Snort (IDS) and “Full Packet Capture” (FPC) have two different functions. If I need to search for something in my FPC archive, I can. I put IDS in front so that it might detect “bad things” happening before I have to go into my FPC archive.

Sagan and log archival have two different functions. If I need to search for something in my log archive, I can. I put Sagan in front so that it might detect “bad things” happening before I have to go into my log archive.

Sagan is the IDS for logs, FPC is the “log archive.”  

In some cases, Sagan is able to tell you enough about an attack, so that you might not need to dig any further. In other cases it does not. Instead, you use the Sagan data to point you in the right direction to use with other tools.

As a “technology + people” company, this is exactly how we use Sagan at Quadrant Information Security in our SOC. When IDS detects a “bad thing” our SOC handlers might utilize “Bro” (https://www.bro.org/) or FPC to get a clearer picture of what is going on. When Sagan detects a “bad thing” happening, our SOC handlers use raw log searches to paint a better picture about what is going on. We then relay that clear picture back to our clients.

Sagan is also intended to be the “glue” between security devices. I just recently had a friendly argument with the author of Snort, Martin Roesch, about something he said in his RSA keynote speech “Advanced Strategies for Defending against a New Breed of Attacks” (The full video is at:  https://www.youtube.com/watch?v=O_mmGUu_6gM . At 9:00 minutes you get to the points I'm referring too).

It seemed to me while watching his video that he was suggesting that we come up with a means that would allow different security devices to communicate with each other. It sounded a lot like “Security Device Event Exchange” (SDEE) (https://en.wikipedia.org/wiki/Security_Device_Event_Exchange) to me. He also stated that he believed this couldn't be accomplished at the log level. 

My counter-argument is that vendors are never going to “work together”, sing “kumbaya” and start using a standard, unified format. It's been tried, multiple times, and each time it has failed. What are the odds that Cisco C-level executives are going to want to see data interaction and exchange with say, Juniper gear? Or Fortinet?

Speaking to his second point, in an ideal world, your Linux servers would be able to share “security” related information with your Microsoft servers. For example, let's say that an attacker is attempting to 'brute force' your Linux server’s SSH service. Let’s also say that the brute force was unsuccessful. One hour later, a valid successful login via Microsoft RDP is detected from the same IP address. This might be something you want to investigate.

This is exactly what Sagan does, at the log level. While the Linux and Windows servers won't “share” information, since they both send data back to Sagan, Sagan becomes the intermediary for the data.    Another example might be your IDS detecting an SQL injection attack, but your “Web Application Firewall” (or mod_security) blocks the attack. We might want this data, but not escalate it to a phone call at 3:00 a.m. We can now also “track” the attacker across our network.

The idea is to do this in real-time.  Not retro-actively hours or days later.

We do this in Sagan with what is known as “flowbits”. Robert Nunley from Quadrant wrote an excellent post some time ago about flowbits (https://quadrantsec.com/about/blog/sagan_flowbit/). The next thing that's usually said is, “ah, but now I have to figure out how to write rules with flowbits.”  Actually, we've already written many rules with flowbits of common scenarios, just like the examples above, and we are constantly improving our rule set. However, you also have the power to write your own rules. 

The idea behind the Sagan log analysis engine is to be a real-time “IDS” for your logs. It is the “glue” between your devices.

There is no single tool that is a silver bullet and anyone claiming that there is, is lying.

