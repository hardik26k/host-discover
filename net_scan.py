import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    scapy.ls(scapy.ARP())
    print("----------------------------------")
    print(arp_request.summary())


scan("127.0.0.1/24")