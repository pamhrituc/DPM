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
            mac_match = re.search('[0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}', element)
            if ip_match != None and mac_match != None:
                if (ip_match.group(0), mac_match.group(0)) not in arp_cache:

                    if sys.platform == 'win32':
                        arp_entry_type = re.search('dynamic', element)
                    else:
                        arp_entry_type = ''

                    if arp_entry_type != None:
                        arp_cache[ip_match.group(0)] = mac_match.group(0)
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

            if sys.platform == 'win32':
                real_mac = real_mac.replace(':', '-')
                response_mac = response_mac.replace(':', '-')
            
            if packet[ARP].psrc not in get_ips_by_mac(arp_cache, response_mac):
                print(f"{BLUE}[!] An ARP Poisoning attack is being attempted. Attacker MAC: {response_mac}. Response MAC: {real_mac}.{RESET}")
                print(f"{BLUE}[*] Measures being taken to protect against this attack...{RESET}")
                try:
                    if sys.platform == 'win32':
                        os.popen('arp -d %s %s' % (packet[ARP].psrc, host_ip))
                        os.popen('arp -s %s %s %s' % (packet[ARP].psrc, arp_cache[packet[ARP].psrc], host_ip))
                    else:
                        os.popen('arp -d %s' % packet[ARP].psrc)
                        os.popen('arp -s %s %s' % (packet[ARP].psrc, arp_cache[packet[ARP].psrc]))
                    print(f"{GREEN}[*] Measures applied successfully.{RESET}")
                except:
                    print(f"{RED}[!!!] An error has occurred while trying to persist changes to ARP cache. Make sure you are running this tool with admin/root privileges{RESET}")
                    print(f"{RED}[!!!] Since your system is under attack, disconnect from the internet. Otherwise, your data can be compromised.{RESET}")
            elif response_mac == gateway_mac:
                if sys.platform == 'win32':
                    os.popen('arp -d %s %s' % (gateway_ip, host_ip))
                    os.popen('ping %s -n 1' % gateway_ip)
                    time.sleep(0.5)
                else:
                    os.popen('arp -d %s' % gateway_ip)
                    os.popen('ping %s -c 1' % gateway_ip)
                    time.sleep(0.5)
                if arp_cache != get_arp_cache():
                    arp_cache = get_arp_cache()
                    print(arp_cache)
            
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
