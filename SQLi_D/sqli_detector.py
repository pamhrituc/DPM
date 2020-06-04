from colorama import init, Fore
from flak import request
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import datetime
import os
import requests
import socket
import sys

init()
BLUE = Fore.BLUE
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET

def return_fields(text):
    fields = []
    unprocessed_fields = re.findall("name=[a-zA-Z0-9]+", text)
    for field in unprocessed_fields:
        fields.append(field[field.find('=') + 1:])

    return fields

def process_packet(packet):
    now = datetime.datetime.now()
    if packet.haslayer(HTTPRequest):
        src_ip = packet[IP].src
        if src_ip != host_ip:
            if packet[HTTPRequest].Host != None:
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                method = packet[HTTPRequest].Method.decode()
                
                print(f"\n{GREEN}[*] {src_ip} requested {url} with {method}.{RESET}")
                print(f"\n{BLUE}[{now.hour}:{now.minute}:{now.second}] We just got a request!{RESET}")
                if packet.haslayer(Raw) and method == 'POST':
                    print(f"\n{RED}[*] Raw data: {packet[Raw].load}.{RESET}")

                    print(request)
                    try:
                        response = requests.get('http://' + url)
                        for field in return_fields(response.text):
                            print(request.form[field])


    if packet.haslayer(HTTPResponse):
        src_ip = packet[IP].src
        if src_ip != host_ip:
            if packet[HTTPResponse].Status_Code.decode() == '200':
                print(f"\{GREEN}[{now.hour}:{now.minute}:{now.second}] We just got a response!{RESET}")
                print(request)
                if packet.haslayer(Raw):
                    print(f"\n{RED}[*] Raw data: {packet[Raw].load}.{RESET}")


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
