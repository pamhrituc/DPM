from scapy.all import *
import socket
import sys
import time

def querysniff(packet):
    global host_ip
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if ip_src == host_ip and packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            dns_hostname = str(packet.getlayer(DNS).qd.qname)[2:-1]
            try:
                ip_from_gateway = socket.gethostbyname(dns_hostname)
                ans = sr1(IP(dst = "8.8.8.8")/UDP(sport = RandShort(), dport = 53)/DNS(rd = 1, qd = DNSQR(qname = dns_hostname, qtype = "A")))
                ip_from_address = ans.an.rdata
                if str(ip_from_address).find('b') > -1:
                    dot_gateway = ip_from_gateway.find('.')
                    dot_address = ip_from_address.find('.')
                    if ip_from_gateway[:dot_gateway] != ip_from_address[:dot_address]:
                        print("(%s, %s)" % (ip_from_gateway, ip_from_address))
                        print("%s -> %s: (%s)" % (str(ip_src), str(ip_dst), dns_hostname))
                        print()
            except socket.gaierror:
                print()


try:
    conf.verb = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    host_ip = s.getsockname()[0]
    print("[*] Your host IP address is: %s" % host_ip)
    
    sniff(filter = "port 53", prn = querysniff, store = 0)
except KeyboardInterrupt:
    print("[*] User requested shutdown.")
    print("[*] Exiting...")
    sys.exit(1)

