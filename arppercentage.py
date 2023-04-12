"""
@author: James Harmon
License Info: https://github.com/jrh079/PythonIDS/blob/add-license-1/LICENSE
"""
import csv

# Open CSV file
with open('arpcap.csv', 'r') as csvfile:
    reader = csv.reader(csvfile)
    
    # Skip header
    next(reader)

    total_packets = 0
    arp_spoofed_packets = 0
    
    # Keywords for SSDP and ARP protocols
    ssdp_protocol = 'SSDP'
    arp_protocol = 'ARP'
    
    # Iterate through each row in the CSV file
    for row in reader:
        # Source, destination, and protocol fields we need for calculations
        source = row[2]
        destination = row[3]
        protocol = row[4]
        
        # Check if the packet is an ARP spoofed packet based on the protocol field
        if (protocol == 'SSDP' or protocol == 'ARP') and (source != destination):
            arp_spoofed_packets += 1
        
        # Increment the total packets counter
        total_packets += 1
    
    # Calculate the percentage of ARP spoofed packets
    arp_spoofed_percentage = (arp_spoofed_packets / total_packets) * 100
    
    # Print the result
    print(f"Total Packets in capture data: {total_packets}")
    print(f"ARP Spoofed Packets based on detection parameters: {arp_spoofed_packets}")
    print(f"ARP Spoofed Percentage: {arp_spoofed_percentage:.2f}%")


