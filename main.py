from collections import Counter
from scapy.all import *

## Create a Packet Counter
packet_counts = Counter()

#Variable that stores the captured packets

captured_packets = []

black_list = ["Raw", "TCP", "UDP"]

## Function that handles packets that might be clear text
def handle_cleartext(pkt):
    global captured_packets
    
    lyr = pkt.lastlayer()
    
    # Check if we don't want this kind of packet
    if lyr.name in black_list:
        # Returns false if we don't want this kind of packet
        return False
    
    # Add packet to "what we want" list
    captured_packets.append(pkt)
    
    # Return true for a success
    return True
    

## Define our Custom Action function
def custom_action(packet):

    # Handle if packet is cleartext
    if handle_cleartext(packet):
        try:
            return "Packet #{}: {} ==> {} Type: {}".format(sum(packet_counts.values()), packet[0][1].src, packet[0][1].dst, packet.lastlayer().name)
        except:
            return packet.lastlayer().name

## Setup sniff, filtering for IP traffic
pkts = sniff(prn=custom_action)
wrpcap('foo.pcap', captured_packets)
