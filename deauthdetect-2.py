#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
"""
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
print("-----DDDDD--------A------U   U---TTTTTT-----HH    HH----------") 
print("-----D----D------A-A-----U---U-----TT-------HH----HH----------")
print("-----D----D--==-AAAAA----U---U-----TT-------HHHHHHHH----------")
print("-----D----D----A-----A---U---U-----TT-------HH----HH----------")
print("-----DDDDD----A-------A---UUU------TT-------HH----HH----------")
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
command2 = ("tshark -i wlan0 -a duration:10 -w /home/kali/temp/deauthtrafficcapture.pcap")
#3rd command to grant permission to non root users to capture output
command3 = ("chmod a+rw /home/kali/temp/deauth*.pcap")
#  Start Airmon-ng to look at wireless traffic using Scapy Library
# Execute System Function
os.system(command)
# Set additional scripted commands to run if needed 
# os.system(command2)
scan = "1"
count = 0  

while scan == "1":

    def sniffReq(packet):
        global count
        global scan
        #Look for Reauthentication that attacker may be capturing hash from
       
           
        if packet.haslayer(Dot11Deauth):
# Look for a deauth packet:
             packet.show()
             print ('Deauth Requests Found')
             print (">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
             print(' [ ' + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))+ ' ] '+  ' Deauthentication Packet detected for device MAC: ' + str(packet.addr2).swapcase())
             print (' [ ' + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))+ ' ] '+  ' Client address: ' + str(packet.addr1).swapcase())
             print ('*** Recomend Admin Review Capture log and check for Attack against Client and Associated AP ***')                     
             count += 1
             #return count
             print ("Deauth Count", count)
             
             if count > 1 and scan == "1" :
                 print ("Positive Deauth Singature Suspected - Multiple deauths")
                 print ("running 10 second packet capture via tshark command, output to /home/kali/temp/deauthtrafficcapture")
                 os.system(command2)                 
                 scan = input("Enter 1 for capture traffic file, 2 for batch scan mode or 3 for end process >> ")
             if scan == "2" :
                 print ("Batch Scan Mode ")
                 print ("Deauth Count", count)
                 # log info to file           
                 if count > 100:
                     scan = input("Enter 1 for capture traffic, 2 for Continue batch scan mode or 3 for end process >> ")
                     
             if scan == "3" :
                 anykey = input('Press Anykey to Exit')
                 sys.exit()
             elif scan != "1" and scan != "2" and scan != "3":
                 print ("Invalid User Input")
                 anykey = input('Press Anykey to continue')
                 scan = input("Enter 1 for capture traffic file, 2 for batch scan mode or 3 for end process >> ")
                
                          
                 

    sniff(iface=interface,prn=sniffReq)
    os.system(command3)
    





