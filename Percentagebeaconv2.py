#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr  4 08:08:33 2023

@author: kali
"""
import csv


# Open the CSV file
with open('beaconcap.csv', 'r') as file:
    reader = csv.DictReader(file)
    
    # Create a set to store MAC addresses
    unique_macs = set()
    
    # Iterate through each row in the CSV
    for row in reader:
        mac_address = row['Source']  
        
        # Check if MAC address is already in the set
        if mac_address in unique_macs:
            print(f"Duplicate MAC address found: {mac_address}")
        else:
            unique_macs.add(mac_address)

# Check if all MAC addresses are unique
if len(unique_macs) == reader.line_num - 1:  # Subtract 1 for the header row
    print("All MAC addresses are unique, 100% Positive Beacon Flood Attack Signature!!")

# Else Calculate percentage of unique MAC addresses to determine likely hood of beacon attack with some non attack frames
total_macs = reader.line_num - 1  # Subtract 1 for the header row
percentage = (len(unique_macs) / total_macs) * 100 if total_macs > 0 else 0

# Check if all MAC addresses are unique
if len(unique_macs) == total_macs:
    print("All MAC addresses in beacon frames are unique!")
else:
    print(f"Percentage of unique MAC addresses: {percentage}%")
    

    



