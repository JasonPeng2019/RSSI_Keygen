#!/usr/bin/env python3
"""
RSSI-based Key Generation - Frame Exchange
Rapidly exchange frames between initiator and responder, measuring RSSI
"""

import threading
import time
import json
import argparse
from scapy.all import *
import sys
from collections import defaultdict

# Configuration
INTERFACE = "wlan0mon"  # Your monitor mode interface
CHANNEL = 6  # WiFi channel to use
NUM_FRAMES = 300  # Number of frames to exchange
EXCHANGE_TIMEOUT = 60  # Maximum time for exchange in seconds
FRAME_INTERVAL = 0.01  # Time between frame transmissions (10ms for fast exchange)

# Custom frame types
FRAME_TYPE_EXCHANGE = 0xCC  # Frame exchange data frame
FRAME_TYPE_EXCHANGE_COMPLETE = 0xDD  # Signal that exchange is complete

# Magic number to identify our protocol
MAGIC_BYTES = b"RSSI_EXCHANGE"

class FrameExchanger:
    def __init__(self, interface, mac_addr, role, peer_mac):
        self.interface = interface
        self.mac_addr = mac_addr
        self.role = role
        self.peer_mac = peer_mac
        
        # Storage for RSSI measurements
        self.rssi_measurements = {}  # {frame_index: rssi_value}
        self.measurements_lock = threading.Lock()
        
        # Tracking
        self.frames_sent = 0
        self.frames_received = 0
        self.running = True
        self.exchange_complete = threading.Event()
        
        # Initiator-specific
        self.next_frame_index = 0
        self.send_lock = threading.Lock()
        
    def create_exchange_frame(self, frame_index):
        """Create a frame with an embedded index for the exchange"""
        # Create 802.11 data frame
        dot11 = Dot11(
            type=2,  # Data frame
            subtype=FRAME_TYPE_EXCHANGE,
            addr1=self.peer_mac,  # Destination
            addr2=self.mac_addr,  # Source
            addr3=self.mac_addr   # BSSID
        )
        
        # Payload contains magic bytes + frame index
        payload_data = MAGIC_BYTES + b"|" + str(frame_index).encode()
        payload = Raw(load=payload_data)
        
        # Combine into RadioTap frame
        frame = RadioTap() / dot11 / payload
        return frame
    
    def create_complete_frame(self):
        """Create a frame signaling exchange completion"""
        dot11 = Dot11(
            type=2,
            subtype=FRAME_TYPE_EXCHANGE_COMPLETE,
            addr1=self.peer_mac,
            addr2=self.mac_addr,
            addr3=self.mac_addr
        )
        payload = Raw(load=MAGIC_BYTES + b"|COMPLETE")
        frame = RadioTap() / dot11 / payload
        return frame
    
    def extract_frame_info(self, pkt):
        """Extract frame index and RSSI from received packet"""
        if not pkt.haslayer(Dot11):
            return None, None
        
        # Check if it's from our peer
        if pkt[Dot11].addr2 != self.peer_mac:
            return None, None
        
        # Extract RSSI from RadioTap header
        rssi = None
        if pkt.haslayer(RadioTap):
            # RSSI is typically in dBm_AntSignal field
            if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                rssi = pkt[RadioTap].dBm_AntSignal
            elif hasattr(pkt[RadioTap], 'Antenna_Signal'):
                rssi = pkt[RadioTap].Antenna_Signal
        
        # Extract frame index from payload
        frame_index = None
        frame_type = pkt[Dot11].subtype
        
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            if MAGIC_BYTES in payload:
                try:
                    # Parse: MAGIC_BYTES|frame_index
                    parts = payload.split(b"|")
                    if len(parts) >= 2:
                        if parts[1] == b"COMPLETE":
                            return "COMPLETE", rssi
                        frame_index = int(parts[1].decode())
                except:
                    pass
        
        return frame_index, rssi
    
    def sniff_thread(self):
        """Continuously sniff for frames and measure RSSI"""
        print(f"[{self.role} Sniffer] Started sniffing thread")
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            frame_index, rssi = self.extract_frame_info(pkt)
            
            if frame_index == "COMPLETE":
                print(f"[{self.role} Sniffer] Received EXCHANGE_COMPLETE signal")
                self.exchange_complete.set()
                return
            
            if frame_index is not None and rssi is not None:
                with self.measurements_lock:
                    self.rssi_measurements[frame_index] = rssi
                    self.frames_received += 1
                
                print(f"[{self.role} Sniffer] Received frame #{frame_index}, RSSI: {rssi} dBm (Total: {self.frames_received})")
                
                # Responder immediately replies when it receives a frame
                if self.role == "RESPONDER":
                    self.send_reply(frame_index)
        
        # Sniff continuously
        sniff(iface=self.interface, prn=packet_handler,
              stop_filter=lambda x: not self.running, store=0)
        
        print(f"[{self.role} Sniffer] Sniffing thread stopped")
    
    def send_reply(self, frame_index):
        """Responder sends immediate reply with same index"""
        frame = self.create_exchange_frame(frame_index)
        sendp(frame, iface=self.interface, verbose=False)
        with self.send_lock:
            self.frames_sent += 1
        print(f"[{self.role} Transmitter] Sent reply for frame #{frame_index} (Total sent: {self.frames_sent})")
    
    def initiator_transmit_thread(self):
        """Initiator sends frames with incrementing indices"""
        print(f"[{self.role} Transmitter] Started transmit thread")
        
        start_time = time.time()
        
        while self.running and self.next_frame_index < NUM_FRAMES:
            if time.time() - start_time > EXCHANGE_TIMEOUT:
                print(f"[{self.role} Transmitter] Timeout reached!")
                break
            
            # Send frame with current index
            frame = self.create_exchange_frame(self.next_frame_index)
            sendp(frame, iface=self.interface, verbose=False)
            
            with self.send_lock:
                self.frames_sent += 1
            
            print(f"[{self.role} Transmitter] Sent frame #{self.next_frame_index} (Total sent: {self.frames_sent})")
            
            self.next_frame_index += 1
            
            # Small delay between transmissions
            time.sleep(FRAME_INTERVAL)
        
        # Signal completion
        print(f"[{self.role} Transmitter] Finished sending {NUM_FRAMES} frames")
        print(f"[{self.role} Transmitter] Sending COMPLETE signal...")
        
        # Send complete signal multiple times to ensure delivery
        for _ in range(5):
            complete_frame = self.create_complete_frame()
            sendp(complete_frame, iface=self.interface, verbose=False)
            time.sleep(0.1)
        
        self.running = False
        print(f"[{self.role} Transmitter] Transmit thread stopped")
    
    def wait_for_completion(self):
        """Wait for exchange to complete (responder waits for COMPLETE signal)"""
        print(f"[{self.role}] Waiting for exchange completion...")
        
        # Wait for complete signal or timeout
        if self.exchange_complete.wait(timeout=EXCHANGE_TIMEOUT + 10):
            print(f"[{self.role}] Exchange complete signal received!")
        else:
            print(f"[{self.role}] Timeout waiting for completion signal")
        
        self.running = False
    
    def exchange_frames(self):
        """Main frame exchange logic"""
        print("=" * 60)
        print(f"Starting Frame Exchange - Role: {self.role}")
        print("=" * 60)
        print(f"Target frames: {NUM_FRAMES}")
        print(f"Peer MAC: {self.peer_mac}\n")
        
        # Start sniffer thread (both roles)
        sniffer = threading.Thread(target=self.sniff_thread, daemon=True)
        sniffer.start()
        
        time.sleep(0.5)  # Let sniffer start up
        
        if self.role == "INITIATOR":
            # Initiator sends frames with incrementing indices
            transmitter = threading.Thread(target=self.initiator_transmit_thread, daemon=True)
            transmitter.start()
            transmitter.join()
            
        else:  # RESPONDER
            # Responder just waits and replies in the sniffer thread
            self.wait_for_completion()
        
        # Stop sniffer
        self.running = False
        sniffer.join(timeout=2)
        
        print("\n" + "=" * 60)
        print("Frame Exchange Complete")
        print("=" * 60)
        print(f"Frames sent: {self.frames_sent}")
        print(f"Frames received (with RSSI): {self.frames_received}")
        print(f"Unique RSSI measurements: {len(self.rssi_measurements)}")
        print("=" * 60 + "\n")
        
        return self.rssi_measurements
    
    def save_rssi_to_file(self, rssi_measurements, filename):
        """Save RSSI measurements to file, ordered by frame index"""
        # Sort by frame index
        sorted_indices = sorted(rssi_measurements.keys())
        
        print(f"Saving RSSI measurements to {filename}...")
        
        with open(filename, 'w') as f:
            f.write(f"# RSSI Measurements - Role: {self.role}\n")
            f.write(f"# Peer MAC: {self.peer_mac}\n")
            f.write(f"# Total measurements: {len(rssi_measurements)}\n")
            f.write(f"# Format: frame_index,rssi_dbm\n")
            f.write("#" + "=" * 50 + "\n\n")
            
            for idx in sorted_indices:
                rssi = rssi_measurements[idx]
                f.write(f"{idx},{rssi}\n")
        
        print(f"✓ Saved {len(sorted_indices)} measurements to {filename}")
        
        # Also save as JSON for easier processing later
        json_filename = filename.replace('.txt', '.json')
        with open(json_filename, 'w') as f:
            json_data = {
                'role': self.role,
                'peer_mac': self.peer_mac,
                'num_measurements': len(rssi_measurements),
                'measurements': {str(k): v for k, v in rssi_measurements.items()}
            }
            json.dump(json_data, f, indent=2)
        
        print(f"✓ Saved measurements to {json_filename}")


def load_role_config():
    """Load role and peer MAC from role_config.json if available"""
    try:
        with open('role_config.json', 'r') as f:
            config = json.load(f)
            return config.get('role'), config.get('peer_mac')
    except FileNotFoundError:
        return None, None


def get_mac_address(interface):
    """Get MAC address of interface"""
    try:
        mac = get_if_hwaddr(interface)
        return mac
    except:
        import random
        return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])


def main():
    parser = argparse.ArgumentParser(description='RSSI-based Frame Exchange')
    parser.add_argument('--role', type=str, choices=['INITIATOR', 'RESPONDER'],
                        help='Device role (INITIATOR or RESPONDER)')
    parser.add_argument('--peer-mac', type=str,
                        help='MAC address of peer device')
    parser.add_argument('--interface', type=str, default=INTERFACE,
                        help=f'Monitor mode interface (default: {INTERFACE})')
    parser.add_argument('--num-frames', type=int, default=NUM_FRAMES,
                        help=f'Number of frames to exchange (default: {NUM_FRAMES})')
    parser.add_argument('--output', type=str, default='rssi_measurements.txt',
                        help='Output filename for RSSI measurements')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    
    # Try to load from config file if not provided
    role = args.role
    peer_mac = args.peer_mac
    
    if not role or not peer_mac:
        print("Attempting to load role configuration from role_config.json...")
        config_role, config_peer = load_role_config()
        if config_role and config_peer:
            role = role or config_role
            peer_mac = peer_mac or config_peer
            print(f"✓ Loaded: Role={role}, Peer MAC={peer_mac}")
    
    if not role or not peer_mac:
        print("\nError: Role and peer MAC must be provided either via:")
        print("  1. Command line: --role INITIATOR --peer-mac aa:bb:cc:dd:ee:ff")
        print("  2. Configuration file: role_config.json")
        print("\nRun role_determination.py first to generate role_config.json")
        sys.exit(1)
    
    # Update global NUM_FRAMES if specified
    global NUM_FRAMES
    NUM_FRAMES = args.num_frames
    
    print("\nRSSI-Based Key Generation - Frame Exchange")
    print("=" * 60)
    
    # Get MAC address
    mac_addr = get_mac_address(args.interface)
    print(f"Interface: {args.interface}")
    print(f"My MAC: {mac_addr}")
    print(f"My Role: {role}")
    print(f"Peer MAC: {peer_mac}")
    print(f"Frames to exchange: {NUM_FRAMES}")
    print("=" * 60 + "\n")
    
    # Create frame exchanger
    exchanger = FrameExchanger(args.interface, mac_addr, role, peer_mac)
    
    try:
        # Perform frame exchange
        rssi_measurements = exchanger.exchange_frames()
        
        # Save results
        if rssi_measurements:
            exchanger.save_rssi_to_file(rssi_measurements, args.output)
            print(f"\n✓ SUCCESS: Exchanged frames and measured RSSI")
            print(f"✓ Results saved to {args.output}")
            
            # Show statistics
            if rssi_measurements:
                rssi_values = list(rssi_measurements.values())
                print(f"\nRSSI Statistics:")
                print(f"  Min: {min(rssi_values)} dBm")
                print(f"  Max: {max(rssi_values)} dBm")
                print(f"  Avg: {sum(rssi_values)/len(rssi_values):.2f} dBm")
        else:
            print("\n✗ WARNING: No RSSI measurements collected")
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        exchanger.running = False
        sys.exit(0)


if __name__ == "__main__":
    main()