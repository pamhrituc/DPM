from colorama import init, Fore
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import argparse
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
    input_types = ["email", "file", "hidden", "image", "password", "search", "tel", "text", "url"]
    fields = []
    unprocessed_input_fields = re.findall("<input [a-zA-Z0-9=\" \' /]+>", text)
    for i in range(len(unprocessed_input_fields)):
        for input_type in input_types:
            if input_type in unprocessed_input_fields[i]:
                if "name" in unprocessed_input_fields[i]:
                    temp = re.findall("name ?= ?[\"\']?[a-zA-Z0-9]+[\"\']?", unprocessed_input_fields[i])[0]
                    fields.append(temp[temp.find('=') + 2:-1])
                elif "id" in unprocessed_input_fields[i]:
                    temp = re.findall("id ?= ?[\"\']?[a-zA-Z0-9]+[\"\']?", unprocessed_input_fields[i])[0]
                    fields.append(temp[temp.find('=') + 2 : -1])
                continue

    return fields

def data_polisher(field, text):
    if field not in text:
        return text
    else:
        if "&" in text:
            index_1 = text.find("=")
            index_2 = text.find("&")
            text = text[index_1 : index_1 + index_2]
            return text
        else:
            #no idea, what else could the data look like??
            pass

def sqli_detector(text):
    sql_key_terms = ["AND", "CREATE", "DELETE", "DROP", "FROM", "INSERT", "JOIN", "LIKE", "NOT", "OR", "ORDER", "SELECT", "TABLE", "UNION", "UPDATE", "VALUES", "WHERE"]
    for sql_key_term in sql_key_terms:
        if sql_key_term in text:
            return True
    return False

def xss_detector(text):
    xss_key_terms = ["script"]
    for xss_key_term in xss_key_terms:
        if xss_key_term in text:
            return True
    return False

def process_packet(packet):
    global url
    global fields
    now = datetime.datetime.now()
    if packet[TCP].payload:
        data_packet = str(packet[TCP].payload)
        src_ip = packet[IP].src
        if src_ip != host_ip:
            print(f"\n{GREEN}[{now.hour}:{now.minute}:{now.second}] {src_ip} requested {url}.{RESET}")
            print(f"\n{BLUE}[{now.hour}:{now.minute}:{now.second}] We just got a request!{RESET}")
            try:
                for field in fields:
                    if field in data_packet.lower():
                        print(f"3: {data_packet}")
                        data_packet_polished = data_polisher(dat_packet)
                        if sqli_detector(data_packet_polished):
                            print(f"\n{RED}Possible SQLi detected. User inputed: {data_packet_polished} in field {field}{RESET}")
                        if xss_detector(data_packet_polished):
                            print(f"\n{RED}Possible XSS detected. User inputed: {data_packet_polished} in field {field}{RESET}")
            except Exception as e:
                print(e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "")
    parser.add_argument("-u", "--url", help = "The url to track after SQLi or XSS", required = True)
    args = parser.parse_args()
    if args.url:
        url = args.url

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        print(f"\n{BLUE}[*] Your host ip: {host_ip}.{RESET}")

        if 'http' not in url:
            url = 'http://' + url

        fields = return_fields(requests.get(url).text)
        sniff(filter = 'tcp', prn = process_packet, store = False)

    except KeyboardInterrupt:
        print(f"\n{BLUE}[*] User requested shutdown...{RESET}")
        print(f"{BLUE}[*] Exiting...{RESET}")
    except socket.error:
        print(f"\n{RED}[!] Unable to retreive host's IP.{RESET}")
        print(f"\n{BLUE}[*] Exiting...{RESET}")
        sys.exit(1)
