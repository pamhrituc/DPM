from colorama import init, Fore
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import socket
import sys

init()
BLUE = Fore.BLUE
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        src_ip = packet[IP].src
        if src_ip != host_ip:
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            method = packet[HTTPRequest].Method.decode()
            print(f"\n{GREEN}[*] {src_ip} Requested {url} with {method}{RESET}")
            print(packet.show())
            if packet.haslayer(Raw) and method == "POST":
                print(f"\n{BLUE}[*] Some useful Raw data: {packet[raw].load}{RESET}")

if __name__ == "__main__":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        print(f"\n{GREEN}[*] Your host ip: {host_ip}")

        sniff(filter = "port 80", prn = process_packet, store = False)

    except KeyboardInterrupt:
        print(f"\n{BLUE}[*] User requested shutdown.{RESET}")
        print(f"{BLUE}[*] Exiting...{RESET}")
    except socket.error:
        print(f"\n{RED}[!] Unable to retreive host's ip.")
        print(f"{BLUE}[*] Exiting...{RESET}")
        sys.exit(1)
