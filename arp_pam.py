from scapy.all import *
import getmac
import netifaces as ni
import os
import re
import signal
import socket
import sys
import threading

def arp_request(ip, gateway_ip):
    results, unanswered = sr(ARP(op = 'who-has', psrc = ip, pdst = gateway_ip))
    for s, r in results:
        print(s.summary())
        print(r.summary())

    return

def get_arp_cache(interface):
    with os.popen('arp -a') as f:
        data = f.read()

    arp_cache = []
    unprocessed_cache = re.split('\n', data)
    for element in unprocessed_cache:
        if "Interface" in element or "Address" in element:
            continue
        else:
            ip_match = re.search('[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', element)
            mac_match = re.search('[0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}', element)
            interface_match = re.search(interface, element)
            arp_entry_type = re.search('dynamic', element)
            if ip_match != None and mac_match != None and (interface_match != None or arp_entry_type != None):
                if (ip_match.group(0), mac_match.group(0)) not in arp_cache:
                    arp_cache.append((ip_match.group(0), mac_match.group(0)))
    print(arp_cache)
    return


def monitor(packet):
    #Check for 2, since this represents a reply
    if packet[ARP].op == 2:
        print("YEET")
        try:
            real_mac = getmac.get_mac_address(ip = packet[ARP].psrc)
            response_mac = getmac.get_mac_address(ip = packet[ARP].hwsrc)

            if real_mac != response_mac:
                print("[!] An ARP Poisoning attack is being attempted. Real MAC: %s. Response MAC: %s." % (real_mac, response_mac))
        except IndexError:
            print("[!!!] Unable to find real MAC. The IP may be fake or the packets are blocked.")

    return

try:
    interface = sys.argv[1]
except:
    print ("Usage: python3 arp_pam.py [interface]")
    sys.exit(0)

#set the interface
#conf.iface = interface

#turn off output
conf.verb = 0


hostname = socket.gethostname()
gateway_ip = ni.gateways()['default'][ni.AF_INET][0]

try:
    ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
except ValueError:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]


print ("[*] Your IP Address is: %s" % ip)
print ("[*] Your default gateway is: %s" % gateway_ip)

gateway_mac = getmac.get_mac_address(ip = gateway_ip)


if gateway_mac is None:
    print ("[!!!] Failed to get gateway MAC. Exiting...")
    sys.exit(0)
else:
    print ("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

get_arp_cache(interface)
sniff(filter = "arp", prn = monitor)
