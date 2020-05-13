from scapy.all import *
import getmac
import netifaces as ni
import os
import re
import signal
import socket
import sys
import threading

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

#turn off output
conf.verb = 0

hostname = socket.gethostname()
gateway_ip = ni.gateways()['default'][ni.AF_INET][0]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
host_ip = s.getsockname()[0]

print ("[*] Your IP Address is: %s" % host_ip)
print ("[*] Your default gateway is: %s" % gateway_ip)

gateway_mac = getmac.get_mac_address(ip = gateway_ip)


if gateway_mac is None:
    print ("[!!!] Failed to get gateway MAC. Exiting...")
    sys.exit(0)
else:
    print ("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

arp_cache = get_arp_cache()
print(arp_cache)

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
                print("[!] An ARP Poisoning attack is being attempted. Attacker MAC: %s. Response MAC: %s." % (response_mac, real_mac))
                print("[*] Measures being taken to protect against this attack...")
                try:
                    if sys.platform == 'win32':
                        os.popen('arp -d %s %s' % (packet[ARP].psrc, host_ip))
                        os.popen('arp -s %s %s %s' % (packet[ARP].pdst, arp_cache[packet[ARP].pdst], host_ip))
                    else:
                        os.popen('arp -d %s' % packet[ARP].psrc)
                        os.popen('arp -s %s %s' % (packet[ARP].psrc, arp_cache[packet[ARP].psrc]))
                    print("[*] Measures applied successfully.")
                except:
                    print("[!!!] An error has occurred while trying to persist changes to ARP cache. Make sure you are running this tool with admin/root privileges")
                    print("[!!!] Since your system is under attack, disconnect from the internet. Otherwise, your data can be compromised.")
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
            print("[!!!] Unable to find real MAC. The IP may be fake or the packets are blocked.")

    return

sniff(filter = "arp", prn = monitor)
