#!/usr/bin/env python3
"""
survivor.py - Transmit beacon frames for search and rescue
"""

import sys
import time
import uuid
import subprocess
from scapy.all import *

class SurvivorBeacon:
    def __init__(self, interface, channel, survivor_id=None):
        self.interface = interface
        self.channel = channel
        self.survivor_id = survivor_id or str(uuid.uuid4())[:8]
        self.sequence = 0
        
    def set_monitor_mode(self):
        """Set interface to monitor mode"""
        print(f"Setting {self.interface} to monitor mode on channel {self.channel}...")
        subprocess.run(['bash', 'set_monitor.sh', self.interface, str(self.channel)])
        time.sleep(2)
        
    def create_beacon(self):
        """Create a custom beacon frame with RadioTap header"""
        # RadioTap header (required for injection)
        radiotap = RadioTap()
        
        # 802.11 frame - using Dot11Beacon
        # Source MAC - unique to this survivor
        src_mac = f"02:{self.survivor_id[:2]}:{self.survivor_id[2:4]}:{self.survivor_id[4:6]}:00:00"
        dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast
        bssid = src_mac
        
        # Create management frame
        dot11 = Dot11(type=0, subtype=8, addr1=dst_mac, addr2=src_mac, addr3=bssid)
        
        # Beacon frame
        beacon = Dot11Beacon(cap='ESS')
        
        # Add SSID element with survivor ID
        ssid = f"RESCUE-{self.survivor_id}"
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        
        # Add custom information element with timestamp and sequence
        info = f"SEQ:{self.sequence:06d}|TIME:{int(time.time())}"
        custom_ie = Dot11Elt(ID='VendorSpecific', info=info, len=len(info))
        
        # Assemble packet
        packet = radiotap / dot11 / beacon / essid / custom_ie
        
        self.sequence += 1
        return packet
    
    def transmit(self, interval=0.5):
        """Continuously transmit beacon frames"""
        print(f"Survivor {self.survivor_id} starting beacon transmission...")
        print(f"Interface: {self.interface}, Channel: {self.channel}")
        print(f"Transmitting every {interval} seconds")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                packet = self.create_beacon()
                sendp(packet, iface=self.interface, verbose=False)
                print(f"[{time.strftime('%H:%M:%S')}] Beacon {self.sequence-1} sent - ID: {self.survivor_id}")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\nStopping beacon transmission...")

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 survivor.py <interface> <channel> [survivor_id]")
        print("Example: sudo python3 survivor.py wlan0 6")
        sys.exit(1)
    
    interface = sys.argv[1]
    channel = int(sys.argv[2])
    survivor_id = sys.argv[3] if len(sys.argv) > 3 else None
    
    beacon = SurvivorBeacon(interface, channel, survivor_id)
    beacon.set_monitor_mode()
    beacon.transmit()

if __name__ == "__main__":
    main()
