# NetworkSwissArmyKnife
A multi-purpose tool meant for those interested in learning more about network security attacks.

# How do I use this?

This step is usually quite simple, you need to download this project on your machine and make sure you have Python installed. When you're ready and want to use this tool,
it is as simple as running python on the main.py file. If there are any dependency errors, use pip that comes with python to install the missing dependencies.

# What is there?
* A *packet sniffing* module that saves packets to a .pcap file that can be dissected in common pcap editors such as WireShark. 
Also includes support for users to write their own filter to the module. Same as wire shark's filtering langauge.
* An *arp spoofing* module that executes an arp spoofing attack. As simple as supplying the network IPs of the machines that are to be targetted. User as option to allow packets to pass or not.
* A *DNS poisining* module **(only works for Linux)** which works in conjoint with the ARP spoofing module. Alters unencrypted DNS packets to resolve to a different IP address.
* A *port scanning* module whose purpose is to check whether certain ports on a machine are open or not.
* A *host scanning* that is designed to scan a range of IP addresses on a network to discover which machines are open versus not.
* A *monitoring* module whose job is just to passively listen for packets and return the number of packets over time. Can be used to monitor traffic from a machine.

# Questions, comments, bugs?
If there are any problems, or you just want to leave a comment, you can add to this thread here: https://greysec.net/showthread.php?tid=7993

**Disclaimer: THIS TOOL IS FOR EDUCATIONAL PURPOSES ONLY, I AM NOT RESPONSIBLE IN ANY WAY FOR ANY POOR CHOICES PEOPLE MAKE WITH THIS OPEN SOURCE PROJECT.**


