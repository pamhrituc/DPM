from colorama import init, Fore
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from urllib.parse import unquote
import argparse
import datetime
import os
import re
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
                    temp = re.findall("name ?= ?[\"\']?[a-zA-Z0-9]+[\"\']?", unprocessed_input_fields[i])[0].replace(" ", "")
                    fields.append(temp[temp.find('=') + 1:])
                elif "id" in unprocessed_input_fields[i]:
                    temp = re.findall("id ?= ?[\"\']?[a-zA-Z0-9]+[\"\']?", unprocessed_input_fields[i])[0].replace(" ", "")
                    fields.append(temp[temp.find('=') + 1:])
                continue

    return fields

def data_polisher(field, text):
    if field not in text:
        return text
    else:
        if "&" in text and "=" in text:
            if text[:2] == "b'":
                text = text[2:-1]
            index_1 = text.find(field + "=")
            index_2 = text[index_1:].find("&")
            text = text[len(field + "=") + index_1 : index_1 + index_2]
            return str(text)

def sqli_detector(text):
    sqli_key_terms = ["AND", "CREATE", "DELETE", "DROP", "FROM", "INSERT", "JOIN", "LIKE", "NOT", "OR", "ORDER", "SELECT", "TABLE", "UNION", "UPDATE", "VALUES", "WHERE"]
    for sqli_key_term in sqli_key_terms:
        if sqli_key_term in text.upper():
            return True
    return False

def xss_detector(text):
    pattern = re.compile('[\W_]+')
    text = pattern.sub('', text.lower())
    xss_key_terms = ["alert", "document", "onerror", "onmouseover", "script"]
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
            print(f"\n{BLUE}[{now.hour}:{now.minute}:{now.second}] {src_ip} accessed {url}.{RESET}")
            try:
                for field in fields:
                    if field in data_packet.lower():
                        data_packet_polished = unquote(data_polisher(field, data_packet))
                        if sqli_detector(data_packet_polished):
                            print(f"\n{BLUE}[{now.hour}:{now.minute}:{now.second}]{RED}Possible SQLi detected. {src_ip} inputed: {data_packet_polished} in field {field}{RESET}")
                        if xss_detector(data_packet_polished):
                            print(f"\n{BLUE}[{now.hour}:{now.minute}:{now.second}]{RED}Possible XSS detected. {src_ip} inputed: {data_packet_polished} in field {field}{RESET}")
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
