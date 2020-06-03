from colorama import init, Fore
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import os
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
            if packet[HTTPRequest].Host != None:
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                method = packet[HTTPRequest].Method.decode()

            print(f"\n{BLUE}[**] We just got a request!{RESET}")
            print(packet.show())

    if packet.haslayer(HTTPResponse):
        src_ip = packet[IP].src
        if src_ip != host_ip:
            print(f"\n{GREEN}[**] We just got a response!{RESET}")
            print(packet.show())


if __name__ == "__main__":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        print(f"\n{BLUE}[*] Your host ip: {host_ip}.{RESET}")

        sniff(filter = "port 80", prn = process_packet, store = False)

    except KeyboardInterrupt:
        print(f"\n{BLUE}[*] User requested shutdown...{RESET}")
        print(f"{BLUE}[*] Exiting...{RESET}")
    except socket.error:
        print(f"\n{RED}[!] Unable to retreive host's IP.{RESET}")
        print(f"\n{BLUE}[*] Exiting...{RESET}")
        sys.exit(1)
