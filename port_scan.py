import sys
import os
import pyfiglet
import socket

class Port_Scanner:
    def __init__(self):
        self.options = {"ip_addr":"127.0.0.1", "lower_port_range":1, "upper_port_range":1000}
    def set_property(self, item_prop, item_val):
        if item_prop in self.options:
            self.options[item_prop] = item_val
        else:
            print("Not a valid option")
    def scan_ports(self):
        print("This might take a second, take a sip of your favorite drink and relax")
        for port in range(int(self.options["lower_port_range"]),int(self.options["upper_port_range"])):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            # returns an error indicator
            result = s.connect_ex((self.options["ip_addr"],port))
            if result ==0:
                print("Port {} is open".format(port))
            s.close()

    def printOptions(self):
        print("")
        print("+=+=+ Packet Sniffer +=+=+")
        print("")
        print("___Parameters___")
        print("ip_addr: {}".format(self.options["ip_addr"]))
        print("lower_port_range (0 for infinite): {}".format(self.options["lower_port_range"]))
        print("upper_port_range: {}".format(self.options["upper_port_range"]))
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
            self.scan_ports()
        elif spaced_cmd[0] == "b":
            return 0
        elif spaced_cmd[0] == "set" and len(spaced_cmd) >= 2:
            final_filter = ""
            for inp_op in spaced_cmd[2:]:
                final_filter += " " + inp_op
            self.set_property(spaced_cmd[1], final_filter)
        return 1
