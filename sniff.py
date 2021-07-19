import sys
import os
from scapy.all import *

class Sniffer:
    def __init__(self):
        self.options = {"file_path": "", "file_name":"foo", "packet_count":0, "packet_filter":"default"}
    def set_property(self, item_prop, item_val):
        if item_prop in self.options:
            self.options[item_prop] = item_val
        else:
            print("Not a valid option")
    def sniff_net(self):
        pkts = None
        if self.options["packet_filter"] == "default":
            try:
                if int(self.options["packet_count"]) == 0:
                    #pkts = sniff(filter="not arp and not icmp", iface=self.options["interface"])
                    pkts = sniff(filter="not arp and not icmp")
                else:
                    #pkts = sniff(filter="not arp and not icmp", count=int(self.options["packet_count"]), iface=self.options["interface"])
                    pkts = sniff(filter="not arp and not icmp", count=int(self.options["packet_count"]))
            except:
                print("Hmm... Something went wrong. Make sure this program is running as sudo and none of the settings are invalid. If you're using windows, make sure you have npcap installed")
        else:
            try:
                if int(self.options["packet_count"]) == 0:
                    pkts = sniff(filter=self.options["packet_filter"])
                else:
                    pkts = sniff(filter=self.options["packet_filter"], count=int(self.options["packet_count"]))

            except:
                print("Hmm... Something went wrong. Make sure this program is running as sudo and none of the settings are invalid.")
        path_ = self.options["file_path"]+self.options["file_name"]+'.pcap'
        path_ = path_[1:]
        pktdump = PcapWriter(path_, append=False, sync=True)
        pktdump.write(pkts)

    def printOptions(self):
        print("")
        print("+=+=+ Packet Sniffer +=+=+")
        print("")
        print("___Parameters___")
        print("file_path (PLEASE CHANGE!: Example: C:\\Somewhere\\NotSure\\): {}".format(self.options["file_path"]))
        print("file_name: {}".format(self.options["file_name"]))
        print("packet_count (0 for infinite): {}".format(self.options["packet_count"]))
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
        elif spaced_cmd[0] == "b":
            return 0
        elif spaced_cmd[0] == "set" and len(spaced_cmd) >= 2:
            final_filter = ""
            for inp_op in spaced_cmd[2:]:
                final_filter += " " + inp_op
            self.set_property(spaced_cmd[1], final_filter)
        return 1
