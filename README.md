# MAC Address Detector

## Overview
This Python script is designed to monitor a local network for new devices connecting to it and to maintain a database of their MAC addresses, IP addresses, hostnames, and assigned names. It uses the Scapy library for packet sniffing and parsing Address Resolution Protocol (ARP) packets.

## Features

   - Detects new devices connecting to the local network.
   - Captures ARP packets to extract MAC addresses, IP addresses, and hostnames.
   - Allows users to assign names to newly detected devices.
   - Stores device information in a JSON database for persistence.

## Usage

   - Ensure that Python and the required libraries (Scapy) are installed.
   - Run the script mac_address_detector.py.
   - The script will continuously monitor the network for new devices.
   - When a new device is detected, the user will be prompted to assign a name to it.
   - The device information (MAC address, IP address, hostname, and assigned name) will be stored in the database.

## Files

   - mac_address_detector.py: Main Python script containing the MAC Address Detector functionality.
   - database.json: JSON file used to store device information.
    
### License
This project is licensed under the [MIT License](https://github.com/NikolaosGazis/Employee-Management?tab=MIT-1-ov-file).
