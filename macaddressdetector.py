# Libraries #
import json
import os
import logging
import threading
from scapy.all import sniff, ARP # ARP: Address Resolution Protocol.
from collections import defaultdict

# Logging #
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Pass the file path of the script and where the MAC Addresses will be stored #
script_dir = os.path.dirname(os.path.abspath(__file__))
db_file = os.path.join(script_dir, "database.json")

# Load/Initialize database #
if os.path.exists(db_file):    
    try:
        with open(db_file, "r") as file:
            mac_addresses = json.load(file)
    except json.JSONDecodeError: # throw error.
        mac_addresses = {}
        logger.warning("[SYSTEM] Creating a new database as previous one is unaccessable.")
else: # empty dictionary.
    mac_addresses = {}

# Functions #
def save_data():
    with open(db_file, "w") as file:
        json.dump(mac_addresses, file)
    logger.info("[SYSTEM] Database has been updated!")

def validation(prompt, default=None):
    while True:
        user = input(prompt).strip()
        if user:
            return user
        elif default is not None:
            return default
        else:
            logger.warning("[SYSTEM] Input is invalid! Please enter a valid name:")

def process(packet):
    if ARP in packet and packet[ARP].op in (1,2): # ARP request or reply.
        mac_address = packet[ARP].hwsrc # Hardware source.
        if mac_address not in mac_addresses:
            # New MAC Address detected #
            ip_addr = packet[ARP].psrc # Protocol source.
            hostname = packet[ARP].hwsrc # Placeholder.
            print(f"[SYSTEM] New device connected with MAC Address: {mac_address}")
            print(f"[SYSTEM] IP Address: {ip_addr} & Hostname: {hostname}")
            name = input("[SYSTEM] Assign a name fo this device: ")
            mac_addresses[mac_address] = {"name": name, "ip_address": ip_addr, "hostname": hostname}
            save_data()
            logger.info("[SYSTEM] Device has been added to the database!")

def sniffing():
    logger.info("[SYSTEM] Sniffing packets!")
    sniff(prn=process, filter="arp", store=0)

def main():
    thread = threading.Thread(target=sniffing)
    thread.start()

    try:
        while True:
            pass # Keeps thread running.
    except KeyboardInterrupt:
        logger.info("[SYSTEM shutting down!")
        thread.join()

# Execute program #
if __name__ == "__main__":
    main()
