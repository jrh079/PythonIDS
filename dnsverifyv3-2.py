#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Mar 31 12:33:37 2023
@author: James Harmon
License Info: https://github.com/jrh079/PythonIDS/blob/add-license-1/LICENSE
"""
import subprocess


expected_primary_dns = input(" Enter Primary DNS in format #.#.#.# Example 192.168.1.1 ")
expected_secondary_dns = input(" Enter Secondary DNS in format #.#.#.# Example 8.8.8.8 ")
# Optional May hardcode the expected DNS settings instead
#expected_primary_dns = "192.168.1.100"
#expected_secondary_dns = "8.8.8.8"

# Get the current DNS settings for eth0
interface_name = input("Enter the interface name Example eth0, wlan0 ")
dns_settings = subprocess.check_output(f"nmcli dev show {interface_name} | grep IP4.DNS", shell=True).decode("utf-8")

# Extract the primary and secondary DNS values - added if 2nd DNS not present we will set it to admin specified value to prevent false positive due to no value set
dns_list = dns_settings.split()
current_primary_dns = dns_list[1]
if len(dns_list) > 2:
    current_secondary_dns = dns_list[3]
else:
    current_secondary_dns = expected_secondary_dns
    print ("**Secondary DNS not set** setting value to match expected Check Network Configuration on Adapter**")

# Check if the DNS settings have changed
if current_primary_dns != expected_primary_dns or current_secondary_dns != expected_secondary_dns:
    print(f"Alert!! - One or more DNS settings have changed from {expected_primary_dns} and {expected_secondary_dns} Current Values {current_primary_dns} and {current_secondary_dns}!")
    anykey = input(' Press Any Key to Continue ')
else:
    print("DNS settings are correct.  Security Check Passed")
    anykey = input(' Press Any Key to Continue ')
    
    
