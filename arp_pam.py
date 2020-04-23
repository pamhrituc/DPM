from python_arptable import get_arp_table
from scapy.all import *
import netifaces as ni
import os
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
ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']

print ("[*] Your IP Address is: %s" % ip)
print ("[*] Your default gateway is: %s" % gateway_ip)

gateway_mac = get_mac(gateway_ip)


if gateway_mac is None:
    print ("[!!!] Failed to get gateway MAC. Exiting...")
    sys.exit(0)
else:
    print ("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac))

arp_table = []
temp_arp_table = get_arp_table()
for i in range(0, len(temp_arp_table)):
    arp_table.append([('IP address', temp_arp_table[i]['IP address']), ('HW address', temp_arp_table[i]['HW address'])])

print(arp_table)

sniff(filter = "arp", prn = monitor)
