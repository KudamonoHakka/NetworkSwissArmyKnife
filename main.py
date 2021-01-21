from collections import Counter
import sys
import os
from scapy.all import *
#import sniff

## Create a Packet Counter
packet_counts = Counter()

#Variable that stores the captured packets

captured_packets = []



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
packet_sniff_interface = "eth0"

# Parameters for arp spoofing
arp_spoof_host = ""
arp_spoof_gateway = ""
arp_spoof_packet_delay = 3000
arp_spoof_forward_packets = "no"


def printPacketSniffOptions():
	# Menu for packet sniffer
	print("")
	print("+=+=+ Packet Sniffer +=+=+")
	print("")
	print("___Parameters___")
	print("file_name: {}".format(packet_sniff_filename))
	print("packet_cap (0 for infinite): {}".format(packet_sniff_count))
	print("filter: {}".format(packet_sniff_filter))
	print("interface: {}".format(packet_sniff_interface))
	print("")
	print("___Commands___")
	print("set [variable] [value]) Change parameter value")
	print("op) Options (this menu)")
	print("r) Run")
	print("b) Back")


run_program = True

def handleMenu():
	# Make certain variables global for editing
	global packet_sniff_filename
	global packet_sniff_count
	global packet_sniff_filter
	global packet_sniff_interface
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

				# Split the user input
				spaced_cmd = inp_cmd.split(" ")

				# List options
				if inp_cmd == "op":
					# Clear menu
					os.system('cls' if os.name == 'nt' else 'clear')
					printPacketSniffOptions()
					continue
					
				if inp_cmd == "r":
					if packet_sniff_filter == "default":
						try:
							if packet_sniff_count == 0:
								pkts = sniff(filter="not arp and not icmp", iface=packet_sniff_interface)
								wrpcap(packet_sniff_filename+'.cap', pkts)
							else:
								pkts = sniff(filter="not arp and not icmp", count=packet_sniff_count, iface=packet_sniff_interface)
								wrpcap(packet_sniff_filename+'.cap', pkts)
						except:
							print("Hmm... Something went wrong. Make sure none of the settings are invalid, such as the interface or filter")
					else:
						if packet_sniff_count == 0:
							pkts = sniff(filter=packet_sniff_filter, iface=packet_sniff_interface)
							wrpcap(packet_sniff_filename+'.cap', pkts)
						else:
							pkts = sniff(filter=packet_sniff_filter, count=packet_sniff_count, iface=packet_sniff_interface)
							wrpcap(packet_sniff_filename+'.cap', pkts)

				# Exit this tool
				elif inp_cmd == "b":
					menu_sniff_run = False
					continue

				elif spaced_cmd[0] == "set" and len(spaced_cmd) >= 2:
					
					# Check if user is setting the filter
					
					if spaced_cmd[1] == "filter":
						
						final_filter = ""
							
						for inp_op in spaced_cmd[2:]:
							final_filter += " " + inp_op
						
						# The slicing here removes the extra space in the start of the final inputted filter
						packet_sniff_filter = final_filter[1:]
						
						print("Setting filter to {}".format(final_filter[1:]))
						
						continue

					# Check if the user didn't specify enough parameters
					if not len(spaced_cmd) == 3:
						
						print("Too many or too few parameters")
						
						continue
					
					# Change scanning interface
					if spaced_cmd[1] == "interface":
						
						packet_sniff_interface = spaced_cmd[2]
						
						print("Setting interface to: {}".format(spaced_cmd[2]))
						
						continue
					
					# Changing file_name parameter
					if spaced_cmd[1] == "file_name":
						
						packet_sniff_filename = spaced_cmd[2]
						
						print("Setting file_name to: {}".format(spaced_cmd[2]))
						
						continue
					
					# Changing packet_cap parameter
					elif spaced_cmd[1] == "packet_cap":
						# Check if user didn't input numbers
						if (spaced_cmd[2].lower()).islower() == True:
							
							print("Please input real numbers")
							
							continue
						packet_sniff_count = int(spaced_cmd[2])
						
						# Be sure that we're working with only positive numbers
						if packet_sniff_count < 0:
							packet_sniff_count = -packet_sniff_count
						
						print("Setting packet_cap to: {}".format(int(spaced_cmd[2])))
						

				# Execute tool with parameters
				elif inp_cmd == "r":
					pass

				# Something wrong with specified command
				else:
					print("Unknown Command '{}', type 'op' for different options and settings.".format(inp_cmd))

		else:
			print("Unknown command")
		
handleMenu()
