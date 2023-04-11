# PythonIDS
"""Python IDS Programs for Academic Research and Learning
These Python files are intended primarily for Academic Research and Learning as well as Admins that may want to program useful detection tools.
Call As Root is intended to allow for calling select modules as root user so that commandline tools may be run from the programs.  Each module ofcourse can be
run as root.  All programs were designed on Kali Linux with Spyder IDE installed as well as libraries such as scapy which helps with packet capture.  All programs are
specifically looking for Wi-Fi based attacks however you may modify to detect similar attacks on other intefaces.

The first main module was deauth-detect designed to pickup repeat deauths on network and flag at an admin set value, when detected a capture is perfomed using Tshark.
the output can be analized in Wireshark and if you output a CSV from there you can also use the percentage tool to calculate how much traffic was deauths further helping
with signature detections.

The ARP module was designed next and successfully detected ARP spoofs from a LT in vacinity.  When MAC table is spoofed it picks this up and also performs a tshark 
pcap capture.  Like the first tool you may run a percentage calculator on CSV outputted from wireshark for analysis.  I am working on additional enhancements
and want to automate outputting this data.

The Beacon Flood DOS detection module will also run a capture once a threshold is met and high number of randomized MAC beacon frames are detected.  It will also 
output a pcap and which allows for the percentage calculations like the first two.  The updated calc program on this will also show if any normal duplicate MAC beacon
frames are present.  If you have alot of AP's in area, some beacon frames sent to those are expected in results, but we are concerned with the rapid randomized MAC
beacon frames.  You will still have a very high percentage of those when an attack is ongoing due to the nature of the DOS attack.

The DNS checker is simple checker tool, ideally an Admin would check against expected values, these can be entered or automated based on needs.  I came up with this
after reading CVE's saying many home routers DNS were being compromised.  So having a warning about this would be useful at home or at work.  In windows you could
run a check at each startup, at work it could be done in AD policy and notify an Admin to verify if change is legit or not.  

Please feel free to freely use, update modify these programs as needed.  I do encourage everyone to post any modifications to this repository.  The idea is to help
one another come up with improvements and aid in learning and detections of current threats. 

I setup several Kali Live machines to do attacks on wifi, and monitor mode is engaged.  Existing Tools like Tshark and Aircrack-ng tools are called as needed.

These files represent current revisions, however I went though many iterations to get to each of these as a simple but practical tool for different detections.

Enjoy!!



"""
