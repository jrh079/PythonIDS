#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr  4 08:08:33 2023

@author: kali
"""
# Open the CSV file
with open('deauthcapnonfiltered.csv', 'r') as file:
    lines = file.readlines()


total_packets = 0
deauth_packets = 0

for line_index, line in enumerate(lines):
    # Skip header row
    if line_index == 0:
        continue

    # TShark Capture has 7 columns
    columns = line.strip().split(',')
    total_packets += 1  # Increment total packet count
    if 'deauthentication' in columns[6].lower():
        deauth_packets += 1  # Increment deauth packet count

# Calculate percentage of deauth packets
percentage = (deauth_packets / total_packets) * 100

# Print the result
print("Total Packets: {}".format(total_packets))
print("Deauth Packets: {}".format(deauth_packets))
print("Percentage of Deauth Packets: {:.2f}%".format(percentage))

    

    



