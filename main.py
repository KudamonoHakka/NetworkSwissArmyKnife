from collections import Counter
from scapy.all import sniff

## Create a Packet Counter
packet_counts = Counter()

#Variable that stores the captured packets
captured_packets = []

## Define our Custom Action function
def custom_action(packet):
    # Create tuple of Src/Dst in sorted order
    #print(type(packet[3]))
    print(type(packet.lastlayer()))
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])

    captured_packets.append(packet)
    #return "Packet #{}: {} ==> {}".format(sum(packet_counts.values()), packet[0][1].src, packet[0][1].dst)

## Setup sniff, filtering for IP traffic
sniff(prn=custom_action, count=100)

## Print out packet count per A <--> Z address pair
print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in packet_counts.items()))