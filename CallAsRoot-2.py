#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov  1 12:02:23 2022
Call Python File as Root (Option for not having to have user supply root pass)
@author: kali
"""
import subprocess
import os
import sys
sudoPassword = input("Enter Sudo Password to be used to open interface in monitor mode ")
#Put in Python File you want to call as root

UserSelection=input('Input 1 for Deauth Detection 2 for Arp Replay Detection 3 for Beacon Flood Detection 4 for DNS Verify or Q = Exit ')
if UserSelection == '1':
    command = ('sudo gnome-terminal -- python deauthdetect-2.py')
elif UserSelection == '2':
    command = ('sudo gnome-terminal -- python arpdetect-2.py')
elif UserSelection == '3':
    command = ('sudo gnome-terminal -- python beaconv4-2.py')
elif UserSelection == '4':
    command = ('sudo gnome-terminal -- python dnsverifyv3-2.py')
elif UserSelection == 'q':
    anykey = input('Press Anykey to Exit')
    sys.exit()
elif UserSelection == 'Q':
    anykey = input('Press Anykey to Exit')
    sys.exit()
elif UserSelection != '1' and UserSelection != '2' and UserSelection != '3' and UserSelection != '4':
    print ("Invalid User Input")
    anykey = input('Press Anykey to continue')
    command = ('sudo gnome-terminal -- python CallAsRoot.py')
    
rp = os.system('echo %s|sudo -S %s' % (sudoPassword, command))
