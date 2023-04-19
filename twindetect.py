#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 28 22:46:36 2023

@author: James Harmon
License Info: https://github.com/jrh079/PythonIDS/blob/add-license-1/LICENSE

This module is in early testing phase and needs work, we are able to build a list of AP's and check against the list and print when duplicates found
Ideally Admin creates a valid AP white List and then we would work from that, for home enviroments with one AP any new MAC showing up would be a clear
indicator of a rouge AP / Possible Evil twin attack, partiucularly if you notice connection is unsecure.  Our instructions file has a link to a website
with instructions on using dnsmasq and airbase-ng.  These tools and directions are all at your own risk and for educational purposes only.  The idea is
we want to build a module that can detect rogue AP's when the appear as a useful tool.  The other modules have all been vetted in my labs in a limited
testing environment, they are for research and learning purposes as well.  Please feel free to test and enhance code as you like.  Please post if you have
any contributions or improvements and share what you learn and find out.  Thanks!
"""

from scapy.all import *


# Start services that may have been closed by other detection processes and required for detection
os.system("airmon-ng start wlan0")
os.system("service NetworkManager start")
os.system("service wpa_supplicant start")


print('###########################')
print('#### Evil Twin-Detect  ####')
print('###########################')

AP_MACs = set()

def check_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            # Check beacon frame
            if packet.addr2 not in AP_MACs:
                AP_MACs.add(packet.addr2)
                print(f"New AP found: {packet.info.decode()} with MAC address {packet.addr2}")
            else:
                print(f"Adress already in List {packet.addr2}. Verify MAC Address is a valid AP / MAC ")
        elif packet.type == 2 and packet.subtype == 0:
            # This is a data frame
            if packet.addr2 in AP_MACs and packet.addr1 not in AP_MACs:
                if packet.haslayer(Dot11Elt) and packet.getlayer(Dot11Elt).ID == 0 and packet.getlayer(Dot11Elt).info:
                    print(f"Evil Twin Rogue AP detected! A client with MAC address {packet.addr2} connected to {packet.getlayer(Dot11Elt).info.decode()} with MAC address {packet.addr1} which is not in our list of known APs.")


sniff(iface="wlan0", prn=check_packet, timeout=30)
#Set Timeout for Loop in seconds with timeout value.
