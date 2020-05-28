from colorama import init, Fore
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import socket
import subprocess
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
                print(f"\n{GREEN}[*] {src_ip} Requested {url} with {method}{RESET}")
                print(packet.show())
                if packet.haslayer(Raw) and method == "POST":
                    print(f"\n{BLUE}[*] Some useful Raw data: {packet[raw].load}{RESET}")
            else:
                print(f"\n{RED}[!] Host was not found.{RESET}")
                print
                process = subprocess.Popen(['./no_connections_ip.sh', src_ip], stdout = subprocess.PIPE)
                process = process.communicate()[0]
                result = str(process)[2:-4]
                print(result)
                number_of_communications = result[:result.find(" ")]
                print(f"\n{BLUE}[*] The number of connections established from IP: {src_ip} is {number_of_communications}.{RESET}")


if __name__ == "__main__":
    try:
        subprocess.call(["chmod", "+x", "no_connections_ip.sh"])

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
