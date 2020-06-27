from colorama import init, Fore
from scapy.all import *
import getmac
import netifaces as ni
import os
import re
import signal
import socket
import sys
import threading

init()
BLUE = Fore.BLUE
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

def get_ips_by_mac(cache, mac):
    ip_list = []
    for ip in cache:
        if cache[ip] == mac:
            ip_list.append(ip)
    return ip_list


def get_arp_cache():
    with os.popen('arp -a') as f:
        data = f.read()

    arp_cache = {}
    unprocessed_cache = re.split('\n', data)
    for element in unprocessed_cache:
        if "Interface" in element or "Address" in element:
            continue
        else:
            ip_match = re.search('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', element)
            mac_match = re.search('[0-9a-f]{2}[:][0-9a-f]{2}[:][0-9a-f]{2}[:][0-9a-f]{2}[:][0-9a-f]{2}[:][0-9a-f]{2}', element)
            if ip_match != None and mac_match != None:
                if (ip_match.group(0), mac_match.group(0)) not in arp_cache:
                    arp_cache[ip_match.group(0).replace("-", ".")] = mac_match.group(0)
    #print(arp_cache)
    return arp_cache

def check_if_arp_poison(arp_cache):
    return len(set(arp_cache.values())) == len(set(arp_cache.keys()))

def monitor(packet):
    global arp_cache
    #Check for 2, since this represents a reply
    if packet[ARP].op == 2:
        try:        
            real_mac = getmac.get_mac_address(ip = packet[ARP].psrc)
            response_mac = packet[ARP].hwsrc

            if packet[ARP].psrc not in get_ips_by_mac(arp_cache, response_mac):
                print(f"{BLUE}[!] An ARP Poisoning attack is being attempted. Attacker MAC: {response_mac}. Response MAC: {real_mac}.{RESET}")
            
        except IndexError:
            print(f"{RED}[!!!] Unable to find real MAC. The IP may be fake or the packets are blocked.{RESET}")
    return

try:
    #turn off output
    conf.verb = 0

    hostname = socket.gethostname()
    gateway_ip = ni.gateways()['default'][ni.AF_INET][0]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host_ip = s.getsockname()[0]

    print (f"{BLUE}[*] Your IP Address is: {host_ip}{RESET}")
    print (f"{BLUE}[*] Your default gateway is: {gateway_ip}.{RESET}")

    gateway_mac = getmac.get_mac_address(ip = gateway_ip)

    if gateway_mac is None:
        print (f"{RED}[!!!] Failed to get gateway MAC. Exiting...{RESET}")
        sys.exit(1)
    else:
        print (f"{GREEN}[*] Gateway {gateway_ip} is at {gateway_mac}.{RESET}")

    arp_cache = get_arp_cache()
    print(arp_cache)

    if not check_if_arp_poison(arp_cache):
        print(f"{RED}[!] There is a possibility that your system is under attack.")
        print("[!] There are duplicate MAC entries in your arp_cache.")
        print("[!] Try turning your internet off to stop the attack.")
        print(f"[!] This program cannot run correctly if your arp cache is currently compromised.{RESET}")
        sys.exit(1)

    sniff(filter = "arp", prn = monitor)
except KeyboardInterrupt:
    print(f"{BLUE}[*] User requested shutdown.")
    print(f"[*] Exiting...{RESET}")
    sys.exit(0)
