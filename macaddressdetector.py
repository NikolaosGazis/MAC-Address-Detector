# Libraries #
import json
import os
from scapy.all import sniff, ARP # ARP: Address Resolution Protocol.
from collections import defaultdict

# Pass the file path of the script and where the MAC Addresses will be stored #
script_dir = os.path.dirname(os.path.abspath(__file__))
db_file = os.path.join(script_dir, "database.json")

# Load database #
if os.path.exists(db_file):    
    try:
        with open(db_file, "r") as file:
            mac_addresses = json.load(file)
    except json.JSONDecodeError: # throw error.
        mac_addresses = {}
else: # empty dictionary.
    mac_addresses = {}

# Functions #
# Update database #
def save_data():
    with open(db_file, "w") as file:
        json.dump(mac_addresses, file)

def process_packet(packet):
    if ARP in packet and packet[ARP].op in (1,2): # ARP packets (request/reply).
        mac_address = packet[ARP].hwsrc # hardware source.
        if mac_address not in mac_addresses:
            # New MAC Address detected #
            ip_addr = packet[ARP].psrc # protocol source.
            hostname = packet[ARP].hwsrc
            print(f"[SYSTEM] New device connected with MAC Address: {mac_address}")
            print(f"[SYSTEM] IP Address: {ip_addr} & Hostname: {hostname}")
            name = input("[SYSTEM] Assign a name fo this device: ")
            mac_addresses[mac_address] = {"name": name, "ip_address": ip_addr, "hostname": hostname}
            save_data()
            print(f"New device has been added.")

# Start fetching ARP packets #
sniff(prn=process_packet, filter="arp", store=0)