#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 28 22:46:36 2023

@author: kali
"""

from scapy.all import *


# Start services that may have been closed by other detection processes and required for detection
os.system("airmon-ng start wlan0")
os.system("service NetworkManager start")
os.system("service wpa_supplicant start")

AP_MACs = set()

def check_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            # Check beacon frame
            if packet.addr2 not in AP_MACs:
                AP_MACs.add(packet.addr2)
                print(f"New AP found: {packet.info.decode()} with MAC address {packet.addr2}")
        elif packet.type == 2 and packet.subtype == 0:
            # This is a data frame
            if packet.addr2 in AP_MACs and packet.addr1 not in AP_MACs:
                print(f"Evil Twin Rogue AP detected! A client with MAC address {packet.addr2} connected to {packet.info.decode()} with MAC address {packet.addr1} which is not in our list of known APs.")

sniff(iface="wlan0", prn=check_packet)