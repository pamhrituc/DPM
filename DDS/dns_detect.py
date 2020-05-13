from scapy.all import *
import sys

def querysniff(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            print(str(ip_src) + "->" + src(ip_dst) ": (" + packet.getlayer(DNS).qd.qname.decode("utf-8") + ")")


try:
    interface = input("[*] Enter interface: ")
    sniff(iface = interface, filter = "port 53", prn = querysniff, store = 0)
except KeyboardInterrupt:
    print("[*] User requested shutdown.")
    print("[*] Exiting...")
    sys.exit(1)

'''
#this part returns the actual IP of the address. All we need to do it check this with the ping
ans = sr1(IP(dst="8.8.8.8")/UDP(sport=RandShort(), dport = 53)/DNS(rd=1,qd=DNSQR(qname="secdev.org", qtype = "A")))
print(ans.an.rdata) #secdev.org's IP
'''
