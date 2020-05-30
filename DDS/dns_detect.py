from colorama import init, Fore
from scapy.all import *
import socket
import sys
import time

init()
BLUE = Fore.BLUE
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

def querysniff(packet):
    global host_ip
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if ip_src == host_ip and packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            dns_hostname = str(packet.getlayer(DNS).qd.qname)[2:-1]
            os.popen('ping %s -c 1' % dns_hostname)
            time.sleep(0.1)
            try:
                ip_from_gateway = socket.gethostbyname(dns_hostname)
                ans = sr1(IP(dst = "8.8.8.8")/UDP(sport = RandShort(), dport = 53)/DNS(rd = 1, qd = DNSQR(qname = dns_hostname, qtype = "A")))
                ip_from_address = ans.an.rdata
                if str(ip_from_address).find('b') != 0:
                    if ip_from_gateway != ip_from_address:
                        print(f"{BLUE}[*] Your system might be under a DNS Spoofing attack.{RESET}")
                        print(f"{RED}[*] IP address of {dns_hostname} returned from gateway: {ip_from_gateway}.{RESET}")
                        print(f"{GREEN}[*] IP address of {dns_hostname} returned from DNS server: {ip_from_address}.{RESET}")
                        print()
            except socket.gaierror:
                print()

if __name__ == "__main__":
    try:
        conf.verb = 0
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        host_ip = s.getsockname()[0]
        print(f"{BLUE}[*] Your host IP address is: {host_ip}.{RESET}")

        sniff(filter = "port 53", prn = querysniff, store = 0)
    except KeyboardInterrupt:
        print(f"{BLUE}[*] User requested shutdown.{RESET}")
        print(f"{BLUE}[*] Exiting...{RESET}")
        sys.exit(1)

