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

This tool contains the following scripts:
- monitor_connection.py: The script which monitors all connections your server receives & blocks IP addresses which establish more connections than the maximum number allowed (can be set by user, otherwise default: 100).
- no_connections_ip.sh: A script used by monitor_connection that returns the number of connections established by an IP address.
- unblock_ip.sh: A script which unblocks an IP address or all IP address, depending on the option used by the user.

The monitor_connection.py will detect all IP addresses which connect to your server & block any IP address which established more connections than allowed. The following command is used to run this tool:
```
python3 monitor_connection.py
```
This script allows the user to choose the maximum number of connections allowed from any IP address. For example:
```
python3 monitor_connection.py -c 50
```
will block any IP address which opens more than 50 connections with your system. If not parameter is given, the default number of allowed connections is 100.

To unblock a specific IP address, run:
```
./unblock_ip.sh [IP_address]
```
To unblock all blocked IP addresses, run:
```
./unblock_ip.sh -a
```
**__To run the unblocking script, make sure it has execution rights.__**

### SQLi_XSS_D: SQL Injection/Cross-Site Scripting Real-Time Detection Tool

This tool is a real-time SQLi/XSS detector. It checks user input for SQLi/XSS keywords and alerts if any positives are found. Only tested on a website hosted on a Peppermint Linux VM, XAMPP, written in PHP. To run this script, use the following command:
```
python3 sqli_xss_detector.py -u [subpage hosted by your system]
```
or
```
python3 sqli_xss_detector.py --url [subpage hosted by your system]
```

###### To-do:
- Block attackers IP address in case of ARP Poisoning
- Allow user to choose DNS Server for DDS
- Improve detection of DNS Spoofing
- Implement detection of incomplete packets for DoS
- Add screenshots
