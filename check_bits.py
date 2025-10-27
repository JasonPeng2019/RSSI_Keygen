#!/usr/bin/env python3
"""
RSSI-based Key Generation - Bit Verification
Verify reconciled keys between devices using CRC checks over IEEE 802.11
"""

import threading
import time
import json
import argparse
import sys
import zlib
from scapy.all import *
import os

# Configuration
INTERFACE = "wlan0mon"  # Your monitor mode interface
LISTEN_TIMEOUT = 5  # Listen for 5 seconds before talking
TALK_TIMEOUT = 10  # Wait 10 seconds for ACKs when talking
CRC_INTERVAL = 0.5  # Send CRC every 0.5 seconds
CRC_REPEAT_COUNT = 5  # Send CRC 5 times

# Custom frame types for verification
FRAME_TYPE_IM_TALKING = 0xBA  # "I'm talking" signal
FRAME_TYPE_VERIFY_ACK = 0xBB  # ACK response with MAC
FRAME_TYPE_CRC_CHECK = 0xBC   # CRC of reconciled key
FRAME_TYPE_VERIFY_SUCCESS = 0xBD  # Success response
FRAME_TYPE_VERIFY_FAILED = 0xBE   # Failed response

# Magic number to identify our verification protocol
MAGIC_BYTES = b"RSSI_VERIFY"

class BitVerifier:
    def __init__(self, interface, mac_addr, reconciled_key_file):
        self.interface = interface
        self.mac_addr = mac_addr
        self.reconciled_key_file = reconciled_key_file
        
        # Load reconciled key data
        self.reconciled_key_string, self.role = self.load_reconciled_key()
        self.my_crc = self.calculate_crc(self.reconciled_key_string)
        
        # Protocol state
        self.is_talking = False
        self.is_listening = False
        self.peer_mac = None
        self.running = True
        
        # Synchronization
        self.acks_received = threading.Event()
        self.verification_complete = threading.Event()
        self.verification_result = None
        
        # Locks
        self.state_lock = threading.Lock()
        
    def load_reconciled_key(self):
        """Load reconciled key data from JSON file"""
        try:
            with open(self.reconciled_key_file, 'r') as f:
                data = json.load(f)
            
            key_string = data.get('reconciled_key_string', '')
            role = data.get('role', 'UNKNOWN')
            
            print(f"Loaded reconciled key: {len(key_string)} bits")
            print(f"Key preview: {key_string[:50]}{'...' if len(key_string) > 50 else ''}")
            return key_string, role
            
        except FileNotFoundError:
            print(f"Error: Reconciled key file {self.reconciled_key_file} not found")
            print("Run reconcile_bits.py first to generate reconciled key")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {self.reconciled_key_file}")
            sys.exit(1)
    
    def calculate_crc(self, data_string):
        """Calculate CRC32 of the key string"""
        if not data_string:
            return 0
        crc = zlib.crc32(data_string.encode()) & 0xffffffff
        print(f"Calculated CRC: {crc:08x}")
        return crc
    
    def create_verify_frame(self, frame_type, payload_data=b""):
        """Create a verification frame"""
        # For ACK frames, include our MAC in the destination field
        if frame_type == FRAME_TYPE_VERIFY_ACK:
            dest_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast for ACK discovery
        elif self.peer_mac:
            dest_mac = self.peer_mac
        else:
            dest_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast if no peer known
            
        dot11 = Dot11(
            type=2,  # Data frame
            subtype=frame_type,
            addr1=dest_mac,
            addr2=self.mac_addr,  # Source
            addr3=self.mac_addr   # BSSID
        )
        
        payload = Raw(load=MAGIC_BYTES + b"|" + payload_data)
        frame = RadioTap() / dot11 / payload
        return frame
    
    def extract_verify_info(self, pkt):
        """Extract verification information from received packet"""
        if not pkt.haslayer(Dot11):
            return None, None, None
        
        frame_type = pkt[Dot11].subtype
        source_mac = pkt[Dot11].addr2
        payload_data = None
        
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            if MAGIC_BYTES in payload:
                try:
                    # Parse: MAGIC_BYTES|payload_data
                    parts = payload.split(b"|", 1)
                    if len(parts) >= 2:
                        payload_data = parts[1]
                except:
                    pass
        
        return frame_type, source_mac, payload_data
    
    def listen_phase(self):
        """Listen for 5 seconds to see if anyone is talking"""
        print(f"\n[Listen] Listening for {LISTEN_TIMEOUT} seconds...")
        
        heard_talker = False
        
        def packet_handler(pkt):
            nonlocal heard_talker
            if not self.running:
                return
            
            frame_type, source_mac, payload_data = self.extract_verify_info(pkt)
            
            if frame_type == FRAME_TYPE_IM_TALKING and source_mac != self.mac_addr:
                print(f"[Listen] Heard 'I'm talking' from {source_mac}")
                self.peer_mac = source_mac
                heard_talker = True
                return True  # Stop sniffing
        
        # Sniff for talkers
        sniff(iface=self.interface, prn=packet_handler,
              stop_filter=lambda x: heard_talker or not self.running,
              timeout=LISTEN_TIMEOUT, store=0)
        
        if heard_talker:
            print(f"[Listen] Switching to responder mode for peer: {self.peer_mac}")
            self.is_listening = True
            return True
        else:
            print(f"[Listen] No talkers heard - switching to talking mode")
            self.is_talking = True
            return False
    
    def send_acks(self):
        """Send 5 ACKs with our MAC"""
        print(f"[Responder] Sending 5 ACKs to {self.peer_mac}")
        
        for i in range(5):
            ack_frame = self.create_verify_frame(FRAME_TYPE_VERIFY_ACK, self.mac_addr.encode())
            sendp(ack_frame, iface=self.interface, verbose=False)
            print(f"[Responder] Sent ACK {i+1}/5")
            time.sleep(0.1)
        
        print(f"[Responder] All ACKs sent - waiting for CRC checks")
    
    def talk_phase(self):
        """Send 'I'm talking' and wait for ACKs"""
        print(f"\n[Talker] Sending 'I'm talking'")
        
        # Send "I'm talking" frame
        talk_frame = self.create_verify_frame(FRAME_TYPE_IM_TALKING)
        sendp(talk_frame, iface=self.interface, verbose=False)
        
        # Wait for ACKs
        print(f"[Talker] Waiting {TALK_TIMEOUT} seconds for ACKs...")
        
        if self.acks_received.wait(timeout=TALK_TIMEOUT):
            print(f"[Talker] Received ACKs from peer: {self.peer_mac}")
            return True
        else:
            print(f"[Talker] No ACKs received - timing out")
            return False
    
    def send_crc_checks(self):
        """Send CRC checks 5 times every 0.5 seconds"""
        print(f"\n[Talker] Sending CRC checks to {self.peer_mac}")
        print(f"[Talker] My CRC: {self.my_crc:08x}")
        
        for i in range(CRC_REPEAT_COUNT):
            crc_data = str(self.my_crc).encode()
            crc_frame = self.create_verify_frame(FRAME_TYPE_CRC_CHECK, crc_data)
            sendp(crc_frame, iface=self.interface, verbose=False)
            print(f"[Talker] Sent CRC check {i+1}/{CRC_REPEAT_COUNT}")
            time.sleep(CRC_INTERVAL)
        
        print(f"[Talker] All CRC checks sent - waiting for response")
    
    def handle_crc_check(self, peer_crc_data):
        """Handle received CRC check from peer"""
        try:
            peer_crc = int(peer_crc_data.decode())
            print(f"[Responder] Received peer CRC: {peer_crc:08x}")
            print(f"[Responder] My CRC: {self.my_crc:08x}")
            
            if peer_crc == self.my_crc:
                print(f"[Responder] CRC match! Sending SUCCESS")
                response_frame = self.create_verify_frame(FRAME_TYPE_VERIFY_SUCCESS)
                sendp(response_frame, iface=self.interface, verbose=False)
                self.verification_result = "SUCCESS"
            else:
                print(f"[Responder] CRC mismatch! Sending FAILED")
                response_frame = self.create_verify_frame(FRAME_TYPE_VERIFY_FAILED)
                sendp(response_frame, iface=self.interface, verbose=False)
                self.verification_result = "FAILED"
                
            self.verification_complete.set()
            
        except (ValueError, UnicodeDecodeError) as e:
            print(f"[Responder] Error parsing peer CRC: {e}")
    
    def verification_listen_thread(self):
        """Listen for verification frames"""
        def packet_handler(pkt):
            if not self.running:
                return
            
            frame_type, source_mac, payload_data = self.extract_verify_info(pkt)
            
            if source_mac == self.mac_addr:
                return  # Ignore our own frames
            
            if frame_type == FRAME_TYPE_VERIFY_ACK and self.is_talking:
                if payload_data:
                    self.peer_mac = payload_data.decode()
                    print(f"[Talker] Received ACK from {self.peer_mac}")
                    self.acks_received.set()
                    
            elif frame_type == FRAME_TYPE_CRC_CHECK and self.is_listening:
                if payload_data:
                    self.handle_crc_check(payload_data)
                    
            elif frame_type == FRAME_TYPE_VERIFY_SUCCESS and self.is_talking:
                print(f"[Talker] Received SUCCESS from peer!")
                self.verification_result = "SUCCESS"
                self.verification_complete.set()
                
            elif frame_type == FRAME_TYPE_VERIFY_FAILED and self.is_talking:
                print(f"[Talker] Received FAILED from peer!")
                self.verification_result = "FAILED"
                self.verification_complete.set()
        
        # Continuous listening
        sniff(iface=self.interface, prn=packet_handler,
              stop_filter=lambda x: not self.running, store=0)
    
    def save_verification_result(self):
        """Save verification result to JSON"""
        output_file = self.reconciled_key_file.replace('.json', '_verified.json')
        
        if self.verification_result == "SUCCESS":
            result_data = {
                'role': self.role,
                'verification_status': 'SUCCESS',
                'verified_key_string': self.reconciled_key_string,
                'verified_key_length': len(self.reconciled_key_string),
                'key_crc': f"{self.my_crc:08x}",
                'peer_mac': self.peer_mac,
                'timestamp': time.time()
            }
        else:
            result_data = {
                'role': self.role,
                'verification_status': 'FAILED',
                'verified_key_string': None,
                'verified_key_length': 0,
                'key_crc': f"{self.my_crc:08x}",
                'peer_mac': self.peer_mac,
                'timestamp': time.time()
            }
        
        with open(output_file, 'w') as f:
            json.dump(result_data, f, indent=2)
        
        print(f"Verification result saved to {output_file}")
    
    def verify(self):
        """Main verification process"""
        try:
            print("\n" + "=" * 60)
            print("Starting Bit Verification Protocol")
            print("=" * 60)
            print(f"My MAC: {self.mac_addr}")
            print(f"My key CRC: {self.my_crc:08x}")
            print("=" * 60)
            
            # Start listening thread
            listen_thread = threading.Thread(target=self.verification_listen_thread, daemon=True)
            listen_thread.start()
            
            # Phase 1: Listen
            heard_talker = self.listen_phase()
            
            if heard_talker:
                # We heard someone talking - become responder
                self.send_acks()
                
                # Wait for CRC checks and respond
                if self.verification_complete.wait(timeout=30):
                    print(f"\n[Verification] Complete! Result: {self.verification_result}")
                else:
                    print(f"\n[Verification] Timeout waiting for CRC checks")
                    self.verification_result = "TIMEOUT"
                    
            else:
                # We didn't hear anyone - become talker
                if self.talk_phase():
                    # Send CRC checks
                    self.send_crc_checks()
                    
                    # Wait for response
                    if self.verification_complete.wait(timeout=15):
                        print(f"\n[Verification] Complete! Result: {self.verification_result}")
                    else:
                        print(f"\n[Verification] Timeout waiting for response")
                        self.verification_result = "TIMEOUT"
                else:
                    print(f"\n[Verification] Failed to establish communication")
                    self.verification_result = "NO_PEER"
            
            # Save result
            if self.verification_result:
                self.save_verification_result()
                
                if self.verification_result == "SUCCESS":
                    print(f"\nKey verification SUCCESSFUL!")
                    print(f"Both devices have matching reconciled keys")
                    return True
                else:
                    print(f"\nKey verification FAILED!")
                    print(f"Devices have different reconciled keys")
                    return False
            else:
                print(f"\nVerification incomplete")
                return False
                
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            return False
        finally:
            self.running = False


def main():
    parser = argparse.ArgumentParser(description='RSSI-based Key Bit Verification')
    parser.add_argument('--interface', type=str, default=INTERFACE,
                        help=f'Monitor mode interface (default: {INTERFACE})')
    parser.add_argument('--reconciled-key', type=str, default='key_data_reconciled.json',
                        help='Input reconciled key JSON file')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    
    print("\nRSSI-Based Key Generation - Bit Verification")
    print("=" * 60)
    
    # Get MAC address
    try:
        mac_addr = get_if_hwaddr(args.interface)
    except:
        import random
        mac_addr = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
    
    print(f"Interface: {args.interface}")
    print(f"My MAC: {mac_addr}")
    print(f"Reconciled key file: {args.reconciled_key}")
    print("=" * 60 + "\n")
    
    # Create verifier
    verifier = BitVerifier(args.interface, mac_addr, args.reconciled_key)
    
    # Perform verification
    success = verifier.verify()
    
    if success:
        print("\nVerification completed successfully!")
        sys.exit(0)
    else:
        print("\nVerification failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()