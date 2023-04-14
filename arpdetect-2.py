"""
@author: James Harmon
License Info: https://github.com/jrh079/PythonIDS/blob/add-license-1/LICENSE
"""

import scapy.all as scapy
import os
import datetime


print("--------------------------------------------------------------")
print("--------------------------------------------------------------")
print("---------A------RRRRR---  PPPPP-------------------------------") 
print("--------A-A-----R----R----P----P------------------------------")
print("-------AAAAA----RRRRRR----PPPPP-----======--------------------")
print("------A-----A---R-----R---P-----------------------------------")
print("-----A-------A--R------R--P-----------------------------------")
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

# Mac Check function
def mac(ipaddress):
    arp_request = scapy.ARP(pdst=ipaddress)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = broadcast/arp_request
    answerlist = scapy.srp(arp_req_br, iface="wlan0", timeout=5, verbose=False)[0]
    if answerlist == "":
        return answerlist[0][1].hwsrc
# Interface sniff function without set timeout which may be adjusted
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, timeout=10)
# function to read and do checks.
def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        originalmac = mac(packet[scapy.ARP].psrc)
        responsemac = packet[scapy.ARP].hwsrc
# Check to see if MAC's have been altered / positive signature
        if originalmac != responsemac:
            print("ARP Attack Detected ")
            #anykey = input('Press Anykey to continue')
            print(' [ ' + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))+ ' ] '+  ' <<ARP Attack Detected>> ')
            print('Running 5 second tshark capture for Admin review ')
 # Call Tshark for capture and Admin Review           
            os.system("tshark -i wlan0 -a duration:5 -w /home/kali/temp/arpdetect.pcap")
            os.system("chmod a+rw /home/kali/temp/arpdetect*.pcap")
 # Modifies output to make it easier to work with post capture.
            anykey = input('Press Anykey to Exit')
            quit()
             
           
#set network device to Sniff
sniff("wlan0")

# Can also capture data if more info desired using wrpcap
