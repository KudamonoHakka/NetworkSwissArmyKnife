import sys
import os
from scapy.all import *


class Ping_Sweeper:
    def __init__(self):
        self.options = {"ip_net":"192.168.1.0/24"}
    def set_property(self, item_prop, item_val):
        if item_prop in self.options:
            self.options[item_prop] = item_val
        else:
            print("Not a valid option")

    def ping_sweep(self):
        print("Starting scan...")
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.options["ip_net"].strip()), timeout=2)
        for snd, rcv in ans:
            print(rcv.sprintf(r"%ARP.psrc%"))

    def printOptions(self):
        print("")
        print("+=+=+ Packet Sniffer +=+=+")
        print("")
        print("___Parameters___")
        print("ip_net (scans all 256 ips on this subnet): {}".format(self.options["ip_net"]))
        print("")
        print("___Commands___")
        print("set [variable] [value]) Change parameter value")
        print("op) Options (this menu)")
        print("r) Run")
        print("b) Back")


    def handle_menu(self):
        # This function will handle the different user input
        cmd = input(": ")
        spaced_cmd = cmd.split(" ")

        # List options
        if spaced_cmd[0] == "op":
            # Clear menu
            os.system('cls' if os.name == 'nt' else 'clear')
            self.printOptions()
        elif spaced_cmd[0] == "r":
            self.ping_sweep()
        elif spaced_cmd[0] == "b":
            return 0
        elif spaced_cmd[0] == "set" and len(spaced_cmd) >= 2:
            final_filter = ""
            for inp_op in spaced_cmd[2:]:
                final_filter += " " + inp_op
            self.set_property(spaced_cmd[1], final_filter)
        return 1
