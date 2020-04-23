from scapy.all import *
import netifaces as ni
import os
import re
import signal
import socket
import sys
import threading

def get_mac(ip_address):

    responses, unanswered = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip_address), timeout = 2, retry = 10)

    #return the MAC address from a respnse
    for s, r in responses:
        return r[Ether].src

    return None

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
            if ip_match != None and mac_match != None and interface_match != None:
                arp_cache.append((ip_match.group(0), mac_match.group(0)))
    print(arp_cache)
    return


def monitor(packet):

    if packet[ARP].op == "is-at":
        try:
            real_mac = get_mac(packet[ARP].psrc)
            response_mac = get_mac(packet[ARP].hwsrc)

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
conf.iface = interface

#turn off output
conf.verb = 0


hostname = socket.gethostname()
gateway_ip = ni.gateways()['default'][ni.AF_INET][0]
ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

print ("[*] Your IP Address is: %s" % ip)
print ("[*] Your default gateway is: %s" % gateway_ip)

gateway_mac = get_mac(gateway_ip)


if gateway_mac is None:
    print ("[!!!] Failed to get gateway MAC. Exiting...")
    sys.exit(0)
else:
    print ("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

get_arp_cache(interface)
#sniff(filter = "arp", prn = monitor)
