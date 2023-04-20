#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

@author: James Harmon
License Info: https://github.com/jrh079/PythonIDS/blob/add-license-1/LICENSE


"""

from scapy.all import *


# Start services that may have been closed by other detection processes and required for detection
os.system("airmon-ng start wlan0")
os.system("service NetworkManager start")
os.system("service wpa_supplicant start")


print('###########################')
print('#### Evil Twin-Detect  ####')
print('###########################')
# This version is best for home networks with single AP, it will notify an additional MAC is located with same SSID

AP_MACs = set()
#track macs
APs = {}
#track SSID - APs

def check_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            # Check beacon frame
            ssid = packet.info.decode('utf-8')
            #set beacon frames to UTF otherwise they dont appear
            bssid = packet.addr3
            # bssid is MAC of AP
            if ssid in APs:
                if bssid != APs[ssid]:
                    print(f"Possible evil twin detected for SSID '{ssid}' with MAC addresses {APs[ssid]} and {bssid}")
                    #if bssid doesnt match with our list we may have a problem, were looking for adtl macs
            APs[ssid] = bssid
            # AP list records mac APs durring loop
            if packet.addr2 not in AP_MACs:
                AP_MACs.add(packet.addr2)
                print(f"New AP found: {packet.info.decode()} with MAC address {packet.addr2}")
                #Let Admin know when a new AP is recoreded in list
           
        elif packet.type == 2 and packet.subtype == 0:
            # This is a data frame
            if packet.addr2 in AP_MACs and packet.addr1 not in AP_MACs:
                if packet.haslayer(Dot11Elt) and packet.getlayer(Dot11Elt).ID == 0 and packet.getlayer(Dot11Elt).info:
                    print(f"Evil Twin Rogue AP detected! A client with MAC address {packet.addr2} connected to {packet.getlayer(Dot11Elt).info.decode()} with MAC address {packet.addr1} which is not in our list of known APs.")


sniff(iface="wlan0", prn=check_packet, timeout=15)
#Set Timeout for Loop in seconds with timeout value.