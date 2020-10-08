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
		return False
		
	print(lyr.name)
	captured_packets.append(pkt)
	return True
	

## Define our Custom Action function
def custom_action(packet):
    # Create tuple of Src/Dst in sorted order
    #print(type(packet[3]))
    #print(packet.show())
    #key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    #packet_counts.update([key])
    
    # Handle if packet is cleartext
    if handle_cleartext(packet):
		return "Packet #{}: {} ==> {}".format(sum(packet_counts.values()), packet[0][1].src, packet[0][1].dst)

## Setup sniff, filtering for IP traffic
pkts = sniff(prn=custom_action)
wrpcap('foo.pcap', captured_packets)

## Print out packet count per A <--> Z address pair
#print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))
