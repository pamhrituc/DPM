# DPM - Detect, Protect, Mitigate

DPM is a personal project which can currently detect ARP Poisoning, DNS Spoofing, the Slowloris DoS attack and real-time SQLi/XSS. This repository contains the following:
- setup.sh: Script which handles the installation of all necessary dependencies needed to run the following tools. To run this script, enter the following command:
```
./script.sh
```
**__To run the above command, make sure the script has execution rights. To do this, run:__**
```
chmod +x script.sh
```
- BAP: ARP Poisoning Detection Tool
- DDS: DNS Spoofing Detection Tool
- DoSM: Slowloris Detection & Mitigation Tool
- SQLi_XSS_D: SQL Injection/Cross-Site Scripting Real-Time Detection Tool


### BAP: ARP Poisoning Detection Tool

The script which detects if/when an ARP Poisoning attack is executed on your system is run using the following command:
```
python3 arp_pam.py
```
This will display your system's IP address, your default gateway and the MAC address associated with your default gateway's IP address, along with your system's ARP cache. Then it will scan any ARP packets your system receives and display a message if the received packets are spoofed.

This tool simply detects an ARP Poisoning attack.

### DDS: DNS Spoofing Detection Tool

To run this script run the following command:
```
python3 dns_detect.py
```
The script will display your host's IP address, before sniffing for packets with an IP & DNS layer. It will check the hostname's associated IP address received from the gateway and the default DNS Server ("8.8.8.8").

### DoSM: Slowloris Detetection & Mitigation Tool

### SQLi_XSS_D: SQL Injection/Cross-Site Scripting Real-Time Detection Tool

###### To-do:
- Block attackers IP address in case of ARP Poisoning
- Allow user to choose DNS Server for DDS
- Improve detection of DNS Spoofing
- Implement detection of incomplete packets for DoS
- Add screenshots
