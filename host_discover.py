import scapy.all as scapy
import argparse
import app

def scan (ip):
    #creates an arp packet
    arp_request = scapy.ARP(pdst=ip)

    #creates an ethernet frame with destination address set to broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    #combining both the arp packet and ethernet frame
    arp_request_broadcast = broadcast/arp_request

    #sending the packet using srp (send, receive, packet ) method and  recording the response
    answered,unanswered = scapy.srp(arp_request_broadcast,timeout=2 , verbose=False)

    client_list = []
    for element in answered:
        clients = {"ip":element[1].psrc , "Mac":element[1].hwsrc}
        client_list.append(clients)
    return client_list

#function to print the result
def print_result(clients):
    count=0
    print("     IP\t\t\t  Mac Address\t\t\t Vendor")
    print("-------------------------------------------------------------------")
    for hosts in clients:
        mac = hosts["Mac"]
        mac = mac[:8].replace(":","-")
        vendor = app.find_vendor(mac)
        print(hosts["ip"] + "\t\t" + hosts["Mac"] + "\t\t"+str(vendor)+"\n")
        count+=1
    print(f"Total addresses found : {count}")
        
#function to parse the arguments
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest = "target",help="IP Range. (ex- 10.0.1.3/24")
    options = parser.parse_args()
    return options



options = get_arguments()

scan_result = scan(options.target)

print_result(scan_result)





