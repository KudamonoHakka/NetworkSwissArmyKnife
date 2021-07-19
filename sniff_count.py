import sys
import os
import time
from scapy.all import *

class Sniffer_Count:
    def __init__(self):
        self.data = {"packet_count":0, "start_time":None}
        self.options = {"packet_count":20, "packet_filter":"default"}
    def set_property(self, item_prop, item_val):
        if item_prop in self.options:
            self.options[item_prop] = item_val
        else:
            print("Not a valid option")
    def sniff_net(self):
        self.data["start_time"] = time.time()
        pkts = None
        if self.options["packet_filter"] == "default":
            try:
                pkts = sniff(filter="not arp and not icmp", count=int(self.options["packet_count"]))
            except:
                print("Hmm... Something went wrong. Make sure this program is running as sudo and none of the settings are invalid. If you're using windows, make sure you have npcap installed")
        else:
            try:
                pkts = sniff(filter=self.options["packet_filter"], count=int(self.options["packet_count"]))
            except:
                print("Hmm... Something went wrong. Make sure this program is running as sudo and none of the settings are invalid.")

    def printOptions(self):
        print("")
        print("+=+=+ Packet Sniffer +=+=+")
        print("")
        print("___Parameters___")
        print("packet_count (packets to collect before calculating time delta): {}".format(self.options["packet_count"]))
        print("filter: {}".format(self.options["packet_filter"]))
        print("")
        print("___Commands___")
        print("set [variable] [value]) Change parameter value")
        print("op) Options (this menu)")
        print("r) Run")
        print("b) Back")


    def handle_sniff_menu(self):
	# This function will handle the different user input
        cmd = input(": ")
        spaced_cmd = cmd.split(" ")

        # List options
        if spaced_cmd[0] == "op":
            # Clear menu
            os.system('cls' if os.name == 'nt' else 'clear')
            self.printOptions()
        elif spaced_cmd[0] == "r":
            self.sniff_net()
            print("Total time: "+str(time.time()-self.data["start_time"]) + " seconds")
        elif spaced_cmd[0] == "b":
            return 0
        elif spaced_cmd[0] == "set" and len(spaced_cmd) >= 2:
            final_filter = ""
            for inp_op in spaced_cmd[2:]:
                final_filter += " " + inp_op
            self.set_property(spaced_cmd[1], final_filter)
        return 1
