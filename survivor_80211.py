#!/usr/bin/env python3
from scapy.all import *
import time
import hashlib

def generate_survivor_id():
    """Generate a unique survivor ID from MAC address"""
    mac = get_if_hwaddr(conf.iface)
    # Use last 4 hex digits of MAC
    #Then, when reading the MAC, the discoverer must respond properly
    return mac.replace(':', '')[-8:].upper()

def create_rescue_beacon(survivor_id, sequence):
    """
    Create a custom 802.11 beacon frame
    """
    # Custom SSID format: RESCUE-[ID]-[SEQ]
    ssid = f"RESCUE-{survivor_id}-{sequence:04d}"
    
    # Use slots 2/3 for redundancy of your MAC 
    src_mac = get_if_hwaddr(conf.iface)
    bssid = "de:ad:be:ef:00:00" #| int(src_mac, 16)  # Custom BSSID
    
    frame = (
        RadioTap() /  
        Dot11(
            type=0,           # Management frame
            subtype=8,        # Beacon subtype
            addr1="ff:ff:ff:ff:ff:ff",  # Destination (broadcast)
            addr2=src_mac,              # Source (transmitter address)
            addr3=bssid                 # BSSID (network ID)
        ) /
        Dot11Beacon(
            cap=0x1111        # Capability info (ESS, no privacy)
        ) /
        Dot11Elt(
            ID=0,             # SSID element ID
            info=ssid         # Your custom SSID
        ) /
        Dot11Elt(
            ID=1,             #Rates element ID
            info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24'
        # Each byte represents a supported data rate in 500
        # kbps units:
        # Access point supports all the following:
        # - \x82 = 130 → 1 Mbps (basic rate, MSB set)
        # - \x84 = 132 → 2 Mbps (basic rate)
        # - \x8b = 139 → 5.5 Mbps (basic rate)
        # - \x96 = 150 → 11 Mbps (basic rate)
        # - \x0c = 12 → 6 Mbps
        # - \x12 = 18 → 9 Mbps
        # - \x18 = 24 → 12 Mbps
        # - \x24 = 36 → 18 Mbps
        ) /
        Dot11Elt(
            ID=3,             # Channel ID
            info=bytes([6])   # Channel 6
        )
    )
    
    return frame

def survivor_transmit(interface):
    """Survivor beacon transmission"""
    survivor_id = generate_survivor_id()
    sequence = 0
    
    print(f"Survivor Beacon Transmitter")
    print(f"Interface: {interface}")
    print(f"Survivor ID: {survivor_id}")
    print(f"=" * 50)
    
    try:
        while True:
            beacon = create_rescue_beacon(survivor_id, sequence)
            sendp(beacon, iface=interface, verbose=False)
            
            print(f"[{time.strftime('%H:%M:%S')}] Sent beacon #{sequence}")
            
            sequence += 1
            time.sleep(1)  # Transmit every second
            
    except KeyboardInterrupt:
        print("\nStopping transmission")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 survivor.py <interface>")
        sys.exit(1)
    
    survivor_transmit(sys.argv[1])