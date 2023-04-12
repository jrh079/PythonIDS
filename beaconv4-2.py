#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Mar 29 13:16:58 2023
@author: James Harmon
License Info: https://github.com/jrh079/PythonIDS/blob/add-license-1/LICENSE
"""



import sys
from scapy import *
from scapy.all import *
import subprocess
import os
import datetime


print("--------------------------------------------------------------")
print("--------------------------------------------------------------")
print("-----BBBBB------EEEEE-----A------CCCC-----OO------NN---N------") 
print("-----B----B-----E--------A-A----C -------O---O----N-N--N--____")
print("-----BBBBB--==--EEEE----A---A---C-------O----O----N  N-N------")
print("-----B----B-----E-------AAAAAA--C------- O---O----N---NN------")
print("-----BBBBB------EEEEEA-A------A--CCCCC----OO------N----N------")
print("--------------------------------------------------------------")

print("--------------------------------------------------------------")
print("--------------------------------------------------------------")
print("-----DDDDD----EEEEEEE    TTTTTTT--EEEEEE----CCCCC--TTTTTT-----") 
print("-----D----D---E------------TT-----E---------C--------TT-------")
print("-----D----D---EEEEE--------TT-----EEEEE-----C--------TT-------")
print("-----D----D---E------------TT-----E---------C--------TT-------")
print("-----DDDDD----EEEEEEE------TT-----EEEEEE----CCCCC----TT-------")
print("--------------------------------------------------------------")
print("--------------------------------------------------------------")

print("")
print("")
anykey = input('Press Anykey to continue')
print("")
print("")

# Set Wireless Interface Recomend using ifconfig to determine wireless adapter you will use
interface = ("wlan0")
# Set system commands to run
# First Command to monitor desired wireless interface
command = ("airmon-ng start wlan0")
#second command to do a capture of traffic
command2 = ("tshark -i wlan0 -a duration:5 -w /home/kali/temp/beaconreplay.pcap")
#3rd command to grant permission to non root users to capture output
command3 = ("chmod a+rw /home/kali/temp/beaconreplay*.pcap")
#  Start Airmon-ng to look at wireless traffic using Scapy Library
# Execute System Function
os.system(command)
# Set additional scripted commands to run if needed 
# os.system(command2)
scan = "1"
count = 0  
reauthcount = 0
os.system('airmon-ng check kill')
monitorssid = input(' Enter SSID to Monitor ')
capturetimeout = input(' Enter Time in Seconds to run Scan ')
#interface Admin set to Network interface
interface = ("wlan0")
capturetimeout = int(capturetimeout)
while scan == "1":

    def sniffReq(packet):
        global count
        global scan
        global reauthcount
        global monitorssid
        #Look for Consecurtive Beacon Flood Requests
       
               
        if packet.haslayer(Dot11Beacon):
            ssid = packet.getlayer(Dot11Elt).info.decode()
            # Look for Beacon Packets and SSID:
            #packet.show()
            if ssid == monitorssid:
                 print ('Beacon Requests Found for your Entered SSID', monitorssid)
                 print (packet[Dot11Beacon].network_stats())
                 #print(ssid + " (" + bssid + ") on channel " + str(channel) + crypto)
                               
                 count += 1
                 #increment and return count via print to screen
                 print ("Beacons Count ", count)
                 packets = sniff(iface=interface, filter="type mgt subtype beacon", timeout=5)  
                 unique_macs = set ()
                 for packet in packets:
                     unique_macs.add(packet.addr2)
                 num_unique_macs = len(unique_macs)
                 
                 if num_unique_macs > 50:
                     print ("***Positive Beacon Singature Suspected - 50+ Unique Beacons Detected***")
                     print("***Beacon flood detected - {} unique MAC addresses".format(num_unique_macs))
                     print ("running 5 second packet capture via tshark command, output to /home/kali/temp/beaconreplay")
                     os.system(command2)    
                     anykey = input('Probable Beacon Flood Detected Advise Review Capture Log -- Press Anykey to Exit')
                     quit()
                
            
                
                             
    
                            

    sniff(iface=interface,prn=sniffReq, filter="type mgt subtype beacon", timeout=capturetimeout)   
    os.system(command3)
