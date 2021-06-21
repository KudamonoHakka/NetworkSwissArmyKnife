import sys
import os
import pyfiglet
import socket
from scapy.all import *
# import custom made files
from sniff import *
from arp_spoof import *
if not os.name == 'nt':
	from dns_spoof import *
from port_scan import *
from host_discovery import *

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
	print("3) DNS Spoof (Linux only)")
	print("4) Port Scan")
	print("5) Host Discovery")
	print("q: Quit")


run_program = True
sniff_module = Sniffer()
arp_module = ARP_Spoofer()
dns_module = ""
if not os.name == 'nt':
	dns_module = DNS_Spoofer()
p_scan_module = Port_Scanner()
h_scan_modle = Ping_Sweeper()
def handleMenu():
	# Print logo of project
	printHeader()

	while run_program:
		# Print the different tools program offers
		printOptions()

		# Get user input
		inp_cmd = input(": ")

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
		elif str(inp_cmd) == "3" and not os.name == 'nt':
		    dns_module.printOptions()
		    while dns_module.handle_menu():
		        pass
		elif str(inp_cmd) == "4":
			p_scan_module.printOptions()
			while p_scan_module.handle_menu():
				pass
		elif str(inp_cmd) == "5":
			h_scan_modle.printOptions()
			while h_scan_modle.handle_menu():
				pass
		else:
			print("Unknown command")

handleMenu()
