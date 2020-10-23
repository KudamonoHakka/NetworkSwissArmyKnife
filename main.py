from collections import Counter
import sys
from scapy.all import *

## Create a Packet Counter
packet_counts = Counter()

#Variable that stores the captured packets

captured_packets = []

# Default list of what not to include
black_list = ["Raw", "TCP", "UDP", "ARP"]



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

def printHeader():
	## The logo of the application.
	print(" _   _  _   ___ _  ")
	print("| \ | || | / (_) |  ")
	print("|  \| || |/ / _| |_ ")
	print("| . ` ||    \| | __|")
	print("| |\  || |\  \ | |_ ")
	print("\_| \_/\_| \_/_|\__|")
	print("The general purpose network hacking tool")

def printOptions():
	# Options menu for the main menu
	print("1) Packet Sniffer")
	print("2) ARP Spoof")
	print("q: Quit")

# Parameters for packet sniffing
packet_sniff_filename = "foo"
packet_sniff_count = 0
packet_sniff_filter = "default"

def printPacketSniffOptions():
	# Menu for packet sniffer
	print("")
	print("+=+=+ Packet Sniffer +=+=+")
	print("")
	print("___Parameters___")
	print("file_name: {}".format(packet_sniff_filename))
	print("packet_cap (0 for infinite): {}".format(packet_sniff_count))
	print("filter: {}".format(packet_sniff_filter))
	print("")
	print("___Commands___")
	print("set [variable] [value]) Change parameter value")
	print("op) Options (this menu)")
	print("r) Run")
	print("b) Back")



run_program = True

def handleMenu():
	# Print logo of project
	printHeader()
	
	while run_program:
		# Print the different tools program offers
		printOptions()
		
		# Get user input
		inp_cmd = raw_input(": ")
		
		# Quit application if user specifies
		if inp_cmd == "q":
			sys.exit(0)
		
		# Packet Sniffer Menu
		elif str(inp_cmd) == "1":
			
			# Print different parameters for the packet sniffer tool
			printPacketSniffOptions()
			
			# Variable for staying in sniffer menu
			menu_sniff_run = True
			
			# Keep user in sniffer menu until specified
			while menu_sniff_run:
				
				# Get user input
				inp_cmd = raw_input(": ")
				
				# List options
				if inp_cmd == "op":
					printPacketSniffOptions()
				
				# Exit this tool
				elif inp_cmd == "b":
					menu_sniff_run = False
					continue
				
				# Execute tool with parameters
				elif inp_cmd == "r":
					pass
				
				# Something wrong with specified command
				else:
					print("Unknown Command '{}'".format(inp_cmd))
		else:
			print("Unknown command")
		

handleMenu()
## Setup sniff, filtering for IP traffic
pkts = sniff(prn=custom_action)
wrpcap('foo.pcap', captured_packets)
