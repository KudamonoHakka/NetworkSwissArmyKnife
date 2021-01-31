import sys
import os
from scapy.all import *
# import custom made files
from sniff import *
from arp_spoof import *

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

# Parameters for arp spoofing
arp_spoof_host = ""
arp_spoof_gateway = ""
arp_spoof_packet_delay = 3000
arp_spoof_forward_packets = "yes"


run_program = True
sniff_module = Sniffer()
arp_module = ARP_Spoofer()
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
		        sniff_module.printOptions()

			# Keep user in sniffer menu until specified
			while sniff_module.handle_sniff_menu():
                            pass
		# Arpspoof Menu
		elif str(inp_cmd) == "2":
			arp_module.printOptions()

                        while arp_module.handle_menu():
                            pass
		else:
			print("Unknown command")
		
handleMenu()
