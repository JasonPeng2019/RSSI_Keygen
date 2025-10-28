#!/usr/bin/env python3
"""
key_exchange.py - Proximity-based key exchange using RSSI
"""

import sys
import time
import random
import hashlib
import subprocess
import numpy as np
from scapy.all import *

class KeyExchange:
    def __init__(self, interface, channel):
        self.interface = interface
        self.channel = channel
        self.role = None  # 'initiator' or 'responder'
        self.session_id = random.randint(10000, 99999)
        self.rssi_measurements = {}  # index -> rssi
        self.indices_used = set()  # indices where RSSI was significant
        self.key_bits = []
        self.partner_mac = None
        
    def set_monitor_mode(self):
        """Set interface to monitor mode"""
        print(f"Setting {self.interface} to monitor mode on channel {self.channel}...")
        subprocess.run(['bash', 'set_monitor.sh', self.interface, str(self.channel)], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
    
    def get_my_mac(self):
        """Get MAC address of interface"""
        try:
            # Read MAC from interface
            with open(f'/sys/class/net/{self.interface}/address', 'r') as f:
                return f.read().strip()
        except:
            return f"02:00:00:00:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
    
    def create_ready_frame(self):
        """Create 'ready to begin' frame"""
        radiotap = RadioTap()
        src_mac = self.get_my_mac()
        dst_mac = "ff:ff:ff:ff:ff:ff"
        
        dot11 = Dot11(type=0, subtype=4, addr1=dst_mac, addr2=src_mac, addr3=src_mac)
        payload = f"KEYEX_READY|{self.session_id}"
        
        packet = radiotap / dot11 / Raw(load=payload)
        return packet
    
    def create_exchange_frame(self, index, is_reply=False, reply_to_index=None):
        """Create frame for key exchange"""
        radiotap = RadioTap()
        src_mac = self.get_my_mac()
        dst_mac = self.partner_mac if self.partner_mac else "ff:ff:ff:ff:ff:ff"
        
        dot11 = Dot11(type=2, subtype=0, addr1=dst_mac, addr2=src_mac, addr3=src_mac)
        
        if is_reply:
            payload = f"KEYEX_REPLY|{self.session_id}|{index}|{reply_to_index}"
        else:
            payload = f"KEYEX_DATA|{self.session_id}|{index}"
        
        packet = radiotap / dot11 / Raw(load=payload)
        return packet
    
    def listen_for_ready(self, timeout=5):
        """Listen for 'ready to begin' frames"""
        start_time = time.time()
        
        def packet_handler(packet):
            try:
                if packet.haslayer(Dot11) and packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if payload.startswith("KEYEX_READY"):
                        parts = payload.split('|')
                        if len(parts) >= 2:
                            session_id = int(parts[1])
                            if session_id != self.session_id:
                                return packet[Dot11].addr2
            except:
                pass
            return None
        
        print("Listening for other devices...")
        while time.time() - start_time < timeout:
            packets = sniff(iface=self.interface, timeout=1, count=10)
            for packet in packets:
                result = packet_handler(packet)
                if result:
                    return result
        
        return None
    
    def determine_role(self):
        """Determine if this device is initiator or responder"""
        print("\n=== DETERMINING ROLE ===")
        
        # Listen for other devices first
        other_device = self.listen_for_ready(timeout=3)
        
        if other_device:
            # Another device is transmitting, we are responder
            self.role = 'responder'
            self.partner_mac = other_device
            print(f"Role: RESPONDER (detected initiator at {other_device})")
            
            # Send ready response
            print("Sending ready response...")
            for _ in range(5):
                sendp(self.create_ready_frame(), iface=self.interface, verbose=False)
                time.sleep(0.1)
            
        else:
            # No other device found, we are initiator
            self.role = 'initiator'
            print("Role: INITIATOR (no other device detected)")
            
            # Transmit ready frames and wait for responder
            print("Transmitting ready frames, waiting for responder...")
            start_time = time.time()
            
            while time.time() - start_time < 10:
                sendp(self.create_ready_frame(), iface=self.interface, verbose=False)
                
                # Check for responder
                packets = sniff(iface=self.interface, timeout=0.5, count=5)
                for packet in packets:
                    try:
                        if packet.haslayer(Dot11) and packet.haslayer(Raw):
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            if payload.startswith("KEYEX_READY"):
                                parts = payload.split('|')
                                if len(parts) >= 2 and int(parts[1]) != self.session_id:
                                    self.partner_mac = packet[Dot11].addr2
                                    print(f"Responder found at {self.partner_mac}")
                                    return True
                    except:
                        pass
            
            if not self.partner_mac:
                print("ERROR: No responder found!")
                return False
        
        return True
    
    def exchange_frames_initiator(self, num_frames=300):
        """Initiator: send frames and measure replies"""
        print(f"\n=== INITIATOR: Exchanging {num_frames} frames ===")
        print("Wave your hand between devices NOW!")
        time.sleep(2)
        
        for index in range(num_frames):
            # Send frame
            packet = self.create_exchange_frame(index)
            sendp(packet, iface=self.interface, verbose=False)
            
            # Wait for reply and measure RSSI
            start_time = time.time()
            while time.time() - start_time < 0.05:  # 50ms timeout
                packets = sniff(iface=self.interface, timeout=0.01, count=1)
                for pkt in packets:
                    try:
                        if pkt.haslayer(RadioTap) and pkt.haslayer(Dot11) and pkt.haslayer(Raw):
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            
                            if payload.startswith("KEYEX_REPLY"):
                                parts = payload.split('|')
                                if len(parts) >= 4:
                                    reply_index = int(parts[3])
                                    
                                    if reply_index == index:
                                        # Extract RSSI
                                        if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                                            rssi = pkt[RadioTap].dBm_AntSignal
                                        else:
                                            rssi = -70  # Default if can't extract
                                        
                                        self.rssi_measurements[index] = rssi
                                        
                                        if index % 30 == 0:
                                            print(f"Frame {index}/{num_frames} - RSSI: {rssi} dBm")
                                        break
                    except:
                        pass
            
            time.sleep(0.005)  # Small delay between frames
        
        print(f"\nExchange complete. Measured {len(self.rssi_measurements)} frames.")
    
    def exchange_frames_responder(self, num_frames=300):
        """Responder: receive frames, measure RSSI, and reply"""
        print(f"\n=== RESPONDER: Exchanging {num_frames} frames ===")
        print("Wave your hand between devices NOW!")
        
        received_count = 0
        start_time = time.time()
        
        while received_count < num_frames and time.time() - start_time < 120:
            packets = sniff(iface=self.interface, timeout=1, count=10)
            
            for packet in packets:
                try:
                    if packet.haslayer(RadioTap) and packet.haslayer(Dot11) and packet.haslayer(Raw):
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        
                        if payload.startswith("KEYEX_DATA"):
                            parts = payload.split('|')
                            if len(parts) >= 3:
                                index = int(parts[2])
                                
                                # Extract RSSI
                                if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                                    rssi = packet[RadioTap].dBm_AntSignal
                                else:
                                    rssi = -70
                                
                                self.rssi_measurements[index] = rssi
                                
                                # Send reply
                                reply = self.create_exchange_frame(index, is_reply=True, reply_to_index=index)
                                sendp(reply, iface=self.interface, verbose=False)
                                
                                received_count += 1
                                
                                if received_count % 30 == 0:
                                    print(f"Frame {received_count}/{num_frames} - RSSI: {rssi} dBm")
                except:
                    pass
        
        print(f"\nExchange complete. Measured {len(self.rssi_measurements)} frames.")
    
    def calculate_key(self, z=1.0):
        """Calculate key from RSSI measurements"""
        print(f"\n=== CALCULATING KEY (z={z} std deviations) ===")
        
        if len(self.rssi_measurements) < 10:
            print("ERROR: Not enough measurements!")
            return
        
        # Get RSSI values
        indices = sorted(self.rssi_measurements.keys())
        rssi_values = [self.rssi_measurements[i] for i in indices]
        
        # Calculate statistics
        mean_rssi = np.mean(rssi_values)
        std_rssi = np.std(rssi_values)
        
        print(f"RSSI Statistics:")
        print(f"  Mean: {mean_rssi:.2f} dBm")
        print(f"  Std Dev: {std_rssi:.2f} dBm")
        print(f"  Threshold: ±{z * std_rssi:.2f} dBm")
        
        # Generate key bits
        self.key_bits = []
        self.indices_used = set()
        
        for index in indices:
            rssi = self.rssi_measurements[index]
            deviation = rssi - mean_rssi
            
            if deviation > z * std_rssi:
                self.key_bits.append(1)
                self.indices_used.add(index)
            elif deviation < -z * std_rssi:
                self.key_bits.append(0)
                self.indices_used.add(index)
        
        print(f"\nGenerated {len(self.key_bits)} key bits from {len(indices)} measurements")
        print(f"Indices used: {sorted(list(self.indices_used))[:20]}..." if len(self.indices_used) > 20 else f"Indices used: {sorted(list(self.indices_used))}")
    
    def send_indices_used(self):
        """Send list of indices used to partner"""
        indices_str = ','.join(map(str, sorted(self.indices_used)))
        
        # Split into chunks if too large
        chunk_size = 200
        chunks = [indices_str[i:i+chunk_size] for i in range(0, len(indices_str), chunk_size)]
        
        print(f"\nSending {len(chunks)} chunks of indices...")
        
        for i, chunk in enumerate(chunks):
            packet = self.create_exchange_frame(9999)
            payload = f"KEYEX_INDICES|{self.session_id}|{i}|{len(chunks)}|{chunk}"
            packet[Raw].load = payload
            
            for _ in range(3):  # Send multiple times for reliability
                sendp(packet, iface=self.interface, verbose=False)
                time.sleep(0.05)
    
    def receive_indices_used(self, timeout=10):
        """Receive list of indices used from partner"""
        print("\nReceiving partner's indices...")
        
        chunks = {}
        total_chunks = None
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            packets = sniff(iface=self.interface, timeout=1, count=20)
            
            for packet in packets:
                try:
                    if packet.haslayer(Dot11) and packet.haslayer(Raw):
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        
                        if payload.startswith("KEYEX_INDICES"):
                            parts = payload.split('|')
                            if len(parts) >= 5:
                                chunk_num = int(parts[2])
                                total_chunks = int(parts[3])
                                chunk_data = parts[4]
                                chunks[chunk_num] = chunk_data
                                
                                if len(chunks) == total_chunks:
                                    # Reconstruct indices
                                    full_str = ''.join(chunks[i] for i in range(total_chunks))
                                    partner_indices = set(map(int, full_str.split(',')))
                                    return partner_indices
                except:
                    pass
        
        return set()
    
    def reconcile_keys(self):
        """Keep only bits where both devices used the index"""
        print("\n=== RECONCILING KEYS ===")
        
        # Exchange indices
        if self.role == 'initiator':
            time.sleep(1)
            self.send_indices_used()
            time.sleep(1)
            partner_indices = self.receive_indices_used()
        else:
            self.send_indices_used()
            time.sleep(1)
            partner_indices = self.receive_indices_used()
        
        print(f"My indices: {len(self.indices_used)}")
        print(f"Partner indices: {len(partner_indices)}")
        
        # Find common indices
        common_indices = self.indices_used.intersection(partner_indices)
        print(f"Common indices: {len(common_indices)}")
        
        if len(common_indices) == 0:
            print("ERROR: No common indices!")
            return
        
        # Rebuild key with only common indices
        sorted_common = sorted(common_indices)
        new_key_bits = []
        
        for index in sorted_common:
            # Find position in original indices_used
            sorted_indices = sorted(self.indices_used)
            if index in sorted_indices:
                pos = sorted_indices.index(index)
                if pos < len(self.key_bits):
                    new_key_bits.append(self.key_bits[pos])
        
        self.key_bits = new_key_bits
        print(f"Final key length: {len(self.key_bits)} bits")
    
    def commit_to_key(self):
        """Create hash commitment to key"""
        key_str = ''.join(map(str, self.key_bits))
        key_hash = hashlib.sha256(key_str.encode()).hexdigest()
        return key_hash
    
    def send_commitment(self):
        """Send key commitment"""
        commitment = self.commit_to_key()
        print(f"\nSending commitment: {commitment[:16]}...")
        
        packet = self.create_exchange_frame(9998)
        payload = f"KEYEX_COMMIT|{self.session_id}|{commitment}"
        packet[Raw].load = payload
        
        for _ in range(5):
            sendp(packet, iface=self.interface, verbose=False)
            time.sleep(0.1)
    
    def receive_commitment(self, timeout=10):
        """Receive partner's commitment"""
        print("\nReceiving partner's commitment...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            packets = sniff(iface=self.interface, timeout=1, count=10)
            
            for packet in packets:
                try:
                    if packet.haslayer(Dot11) and packet.haslayer(Raw):
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        
                        if payload.startswith("KEYEX_COMMIT"):
                            parts = payload.split('|')
                            if len(parts) >= 3:
                                return parts[2]
                except:
                    pass
        
        return None
    
    def verify_key_match(self):
        """Verify both devices have the same key"""
        print("\n=== VERIFYING KEY MATCH ===")
        
        my_commitment = self.commit_to_key()
        
        if self.role == 'initiator':
            self.send_commitment()
            time.sleep(1)
            partner_commitment = self.receive_commitment()
        else:
            time.sleep(1)
            partner_commitment = self.receive_commitment()
            time.sleep(1)
            self.send_commitment()
        
        if partner_commitment:
            print(f"My commitment:      {my_commitment[:32]}...")
            print(f"Partner commitment: {partner_commitment[:32]}...")
            
            if my_commitment == partner_commitment:
                print("\n✓ SUCCESS: Keys match!")
                return True
            else:
                print("\n✗ FAILURE: Keys do not match!")
                return False
        else:
            print("\n✗ ERROR: Could not receive partner's commitment")
            return False
    
    def display_key(self):
        """Display the generated key"""
        print("\n=== GENERATED KEY ===")
        key_str = ''.join(map(str, self.key_bits))
        print(f"Key (binary): {key_str[:64]}..." if len(key_str) > 64 else f"Key (binary): {key_str}")
        print(f"Key length: {len(self.key_bits)} bits")
        
        # Convert to hex for readability
        if len(key_str) >= 8:
            # Pad to multiple of 8
            padded = key_str + '0' * (8 - len(key_str) % 8) if len(key_str) % 8 else key_str
            hex_key = hex(int(padded, 2))[2:]
            print(f"Key (hex): {hex_key[:32]}..." if len(hex_key) > 32 else f"Key (hex): {hex_key}")
        
        key_hash = self.commit_to_key()
        print(f"Key hash (SHA256): {key_hash}")

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 key_exchange.py <interface> <channel>")
        print("Example: sudo python3 key_exchange.py wlan0 6")
        sys.exit(1)
    
    interface = sys.argv[1]
    channel = int(sys.argv[2])
    
    kex = KeyExchange(interface, channel)
    kex.set_monitor_mode()
    
    print("=" * 60)
    print("PROXIMITY-BASED KEY EXCHANGE")
    print("=" * 60)
    
    # Determine role
    if not kex.determine_role():
        print("Failed to establish connection. Exiting.")
        sys.exit(1)
    
    time.sleep(2)
    
    # Exchange frames
    try:
        if kex.role == 'initiator':
            kex.exchange_frames_initiator(num_frames=300)
        else:
            kex.exchange_frames_responder(num_frames=300)
        
        # Calculate key
        kex.calculate_key(z=1.0)
        
        # Reconcile keys
        kex.reconcile_keys()
        
        # Display key
        kex.display_key()
        
        # Verify match
        kex.verify_key_match()
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
    
    print("\n" + "=" * 60)
    print("KEY EXCHANGE COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
