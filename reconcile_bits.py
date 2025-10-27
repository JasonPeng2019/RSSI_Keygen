#!/usr/bin/env python3

import threading
import time
import json
import argparse
import random
import sys
import zlib
from scapy.all import *
from collections import defaultdict

# Configuration
INTERFACE = "wlan0mon"  
HANDSHAKE_TIMEOUT = 30  # Maximum time for handshake in seconds
MAX_HANDSHAKE_ATTEMPTS = 3  # Maximum handshake retry attempts
ACK_COUNT = 5  # Number of ACKs to send/expect
PACKET_TIMEOUT = 5  # Timeout for individual packet ACKs
MAX_PACKET_SIZE = 1000  # Maximum payload size per packet

# Custom frame types for reconciliation
FRAME_TYPE_IM_TRANSMITTING = 0xAA  # "I'm transmitting" signal
FRAME_TYPE_HANDSHAKE_ACK = 0xAB   # ACK response to "I'm transmitting"
FRAME_TYPE_KEYBITS_REQUEST = 0xAC # Request peer key bits (indices and values)
FRAME_TYPE_KEYBITS_PACKET = 0xAD # Send key bits packet with CRC
FRAME_TYPE_PACKET_ACK = 0xAE # ACK for received packet
FRAME_TYPE_EXCHANGE_COMPLETE = 0xAF # Signal exchange complete

# Magic number to identify our reconciliation protocol
MAGIC_BYTES = b"RSSI_RECONCILE"

class BitReconciler:
    def __init__(self, interface, mac_addr, peer_mac, key_data_file):
        self.interface = interface
        self.mac_addr = mac_addr
        self.peer_mac = peer_mac
        self.key_data_file = key_data_file
        
        self.my_key_bits, self.my_indices, self.role = self.load_key_data()
        
        self.handshake_complete = False
        self.handshake_established = threading.Event()
        self.acks_received = 0
        self.acks_sent = 0
        self.running = True
        
        self.peer_indices = None
        self.peer_key_bits = None
        self.keybits_received = threading.Event()
        
        self.received_packets = {}  # {packet_index: data}
        self.expected_packets = 0
        self.packet_acks = {}  # {packet_index: ack_received_event}
        self.exchange_complete_received = threading.Event()
        
        self.state_lock = threading.Lock()
        
    def load_key_data(self):
        try:
            with open(self.key_data_file, 'r') as f:
                data = json.load(f)
            
            key_bits = {int(k): v for k, v in data['key_bits'].items()}
            indices_used = data['indices_used']
            role = data['role']
            
            print(f"Loaded key data: {len(key_bits)} bits from {len(indices_used)} indices")
            return key_bits, indices_used, role
            
        except FileNotFoundError:
            print(f"Error: Key data file {self.key_data_file} not found")
            print("Run calc_key.py first to generate key data")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {self.key_data_file}")
            sys.exit(1)
    
    def create_handshake_frame(self, frame_type, payload_data=b""):
        dot11 = Dot11(
            type=2,  # Data frame
            subtype=frame_type,
            addr1=self.peer_mac,  # Destination
            addr2=self.mac_addr,  # Source
            addr3=self.mac_addr   # BSSID
        )
        
        payload = Raw(load=MAGIC_BYTES + b"|" + payload_data)
        frame = RadioTap() / dot11 / payload
        return frame
    
    def extract_handshake_info(self, pkt):
        if not pkt.haslayer(Dot11):
            return None, None
        
        if pkt[Dot11].addr2 != self.peer_mac:
            return None, None
        
        frame_type = pkt[Dot11].subtype
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
        
        return frame_type, payload_data
    
    def calculate_crc(self, data):
        return zlib.crc32(data) & 0xffffffff
    
    def create_packet_with_crc(self, packet_index, data):
        data_bytes = data.encode() if isinstance(data, str) else data
        crc = self.calculate_crc(data_bytes)
        packet_payload = f"{packet_index}|".encode() + data_bytes + f"|{crc}".encode()
        return packet_payload
    
    def parse_packet_with_crc(self, payload_data):
        try:
            # Split on first and last |
            parts = payload_data.split(b"|")
            if len(parts) < 3:
                return None, None, False
            
            packet_index = int(parts[0].decode())
            crc_received = int(parts[-1].decode())
            
            # Reconstruct data (everything between first and last |)
            data = b"|".join(parts[1:-1])
            
            # Verify CRC
            crc_calculated = self.calculate_crc(data)
            is_valid = (crc_received == crc_calculated)
            
            return packet_index, data, is_valid
            
        except (ValueError, UnicodeDecodeError, IndexError):
            return None, None, False
    
    def split_data_into_packets(self, data):
        data_bytes = data.encode() if isinstance(data, str) else data
        packets = []
        
        for i in range(0, len(data_bytes), MAX_PACKET_SIZE):
            packet_data = data_bytes[i:i + MAX_PACKET_SIZE]
            packets.append(packet_data)
        
        return packets
    
    def perform_handshake(self):
        print("\n" + "=" * 60)
        print("Starting Bit Reconciliation Handshake")
        print("=" * 60)
        
        for attempt in range(MAX_HANDSHAKE_ATTEMPTS):
            print(f"\n[Handshake] Attempt {attempt + 1}/{MAX_HANDSHAKE_ATTEMPTS}")
            
            if self.attempt_handshake():
                print(f"[Handshake] Handshake established successfully!")
                return True
            
            print(f"[Handshake] Attempt {attempt + 1} failed")
            if attempt < MAX_HANDSHAKE_ATTEMPTS - 1:
                print(f"[Handshake] Retrying...")
                time.sleep(1)
        
        print(f"\n[Handshake] Failed to establish handshake after {MAX_HANDSHAKE_ATTEMPTS} attempts")
        return False
    
    def attempt_handshake(self):
        self.handshake_established.clear()
        self.acks_received = 0
        self.acks_sent = 0
        
        listen_thread = threading.Thread(target=self.handshake_listen_thread, daemon=True)
        listen_thread.start()
        
        backoff_time = random.uniform(0, 10)
        print(f"[Handshake] Random backoff: {backoff_time:.2f} seconds")
        
        # Wait for backoff or incoming "I'm transmitting"
        if self.handshake_established.wait(timeout=backoff_time):
            print(f"[Handshake] Heard peer transmission during backoff - entering responder mode")
            return self.wait_for_handshake_completion()
        
        print(f"[Handshake] Backoff expired - sending 'I'm transmitting'")
        return self.initiate_handshake()
    
    def handshake_listen_thread(self):
        def packet_handler(pkt):
            if not self.running:
                return
            
            frame_type, payload_data = self.extract_handshake_info(pkt)
            
            if frame_type == FRAME_TYPE_IM_TRANSMITTING:
                print(f"[Handshake] Received 'I'm transmitting' from peer")
                self.handle_im_transmitting()
                
            elif frame_type == FRAME_TYPE_HANDSHAKE_ACK:
                print(f"[Handshake] Received ACK from peer")
                self.handle_handshake_ack()
                
            elif frame_type == FRAME_TYPE_KEYBITS_REQUEST:
                print(f"[Exchange] Received key bits request from peer")
                self.handle_keybits_request()
                
            elif frame_type == FRAME_TYPE_KEYBITS_PACKET:
                print(f"[Exchange] Received key bits packet from peer")
                self.handle_keybits_packet(payload_data)
                
            elif frame_type == FRAME_TYPE_PACKET_ACK:
                print(f"[Exchange] Received packet ACK from peer")
                self.handle_packet_ack(payload_data)
                
            elif frame_type == FRAME_TYPE_EXCHANGE_COMPLETE:
                print(f"[Exchange] Received exchange complete signal")
                self.exchange_complete_received.set()
        
        # Sniff for handshake frames
        sniff(iface=self.interface, prn=packet_handler,
              stop_filter=lambda x: not self.running,
              timeout=HANDSHAKE_TIMEOUT, store=0)
    
    def handle_im_transmitting(self):
        with self.state_lock:
            if not self.handshake_established.is_set():
                print(f"[Handshake] → Responding with {ACK_COUNT} ACKs")
                
                for i in range(ACK_COUNT):
                    ack_frame = self.create_handshake_frame(FRAME_TYPE_HANDSHAKE_ACK)
                    sendp(ack_frame, iface=self.interface, verbose=False)
                    self.acks_sent += 1
                    time.sleep(0.1)
                
                print(f"[Handshake] Sent {self.acks_sent} ACKs - waiting for peer ACKs")
                self.handshake_established.set()
    
    def handle_handshake_ack(self):
        with self.state_lock:
            self.acks_received += 1
            print(f"[Handshake] ACK {self.acks_received}/{ACK_COUNT} received")
            
            if self.acks_received >= ACK_COUNT:
                print(f"[Handshake] Received all {ACK_COUNT} ACKs - handshake complete!")
                self.handshake_complete = True
                self.handshake_established.set()
    
    def initiate_handshake(self):
        print(f"[Handshake] → Sending 'I'm transmitting'")
        
        transmit_frame = self.create_handshake_frame(FRAME_TYPE_IM_TRANSMITTING)
        sendp(transmit_frame, iface=self.interface, verbose=False)
        
        start_time = time.time()
        while time.time() - start_time < 5:  # Wait up to 5 seconds for ACKs
            if self.acks_received >= ACK_COUNT:
                print(f"[Handshake] → Sending {ACK_COUNT} ACKs back to peer")
                
                for i in range(ACK_COUNT):
                    ack_frame = self.create_handshake_frame(FRAME_TYPE_HANDSHAKE_ACK)
                    sendp(ack_frame, iface=self.interface, verbose=False)
                    time.sleep(0.1)
                
                self.handshake_complete = True
                return True
            
            time.sleep(0.1)
        
        print(f"[Handshake] No ACKs received - handshake failed")
        return False
    
    def wait_for_handshake_completion(self):
        start_time = time.time()
        while time.time() - start_time < 10:  # Wait up to 10 seconds
            if self.acks_received >= ACK_COUNT:
                self.handshake_complete = True
                return True
            time.sleep(0.1)
        
        print(f"[Handshake] Didn't receive expected ACKs from peer")
        return False
    
    def handle_keybits_request(self):
        print(f"[Exchange] → Starting reliable transmission of key bits ({len(self.my_key_bits)} bits)")
        
        keybits_json = json.dumps(self.my_key_bits)
        
        packets = self.split_data_into_packets(keybits_json)
        print(f"[Exchange] Split data into {len(packets)} packets")
        
        for packet_index, packet_data in enumerate(packets):
            success = self.send_packet_reliably(packet_index, packet_data)
            if not success:
                print(f"[Exchange] Failed to send packet {packet_index} - aborting")
                return
        
        complete_frame = self.create_handshake_frame(FRAME_TYPE_EXCHANGE_COMPLETE)
        sendp(complete_frame, iface=self.interface, verbose=False)
        print(f"[Exchange] Sent exchange complete signal")
    
    def send_packet_reliably(self, packet_index, packet_data):
        ack_event = threading.Event()
        self.packet_acks[packet_index] = ack_event
        
        packet_payload = self.create_packet_with_crc(packet_index, packet_data)
        
        start_time = time.time()
        attempt = 0
        
        while time.time() - start_time < PACKET_TIMEOUT:
            attempt += 1
            print(f"[Exchange] Sending packet {packet_index}, attempt {attempt}")
            
            packet_frame = self.create_handshake_frame(FRAME_TYPE_KEYBITS_PACKET, packet_payload)
            sendp(packet_frame, iface=self.interface, verbose=False)
            
            if ack_event.wait(timeout=1.0):
                print(f"[Exchange] Packet {packet_index} ACK received")
                del self.packet_acks[packet_index]
                return True
            
            print(f"[Exchange] Packet {packet_index} ACK timeout, retrying...")
        
        print(f"[Exchange] Packet {packet_index} failed after {PACKET_TIMEOUT} seconds")
        if packet_index in self.packet_acks:
            del self.packet_acks[packet_index]
        return False
    
    def handle_keybits_packet(self, payload_data):
        if not payload_data:
            print(f"[Exchange] Empty packet received")
            return
        
        packet_index, data, is_valid = self.parse_packet_with_crc(payload_data)
        
        if packet_index is None:
            print(f"[Exchange] Invalid packet format")
            return
        
        if is_valid:
            print(f"[Exchange] Packet {packet_index} CRC valid - sending ACK")
            self.received_packets[packet_index] = data
            
            ack_payload = str(packet_index).encode()
            ack_frame = self.create_handshake_frame(FRAME_TYPE_PACKET_ACK, ack_payload)
            sendp(ack_frame, iface=self.interface, verbose=False)
        else:
            print(f"[Exchange] Packet {packet_index} CRC invalid - not sending ACK")
    
    def handle_packet_ack(self, payload_data):
        try:
            if payload_data:
                packet_index = int(payload_data.decode())
                if packet_index in self.packet_acks:
                    print(f"[Exchange] ACK received for packet {packet_index}")
                    self.packet_acks[packet_index].set()
        except (ValueError, UnicodeDecodeError):
            print(f"[Exchange] Invalid ACK format")
    
    def reassemble_received_data(self):
        if not self.received_packets:
            return None
        
        sorted_indices = sorted(self.received_packets.keys())
        reassembled_data = b""
        
        for i, expected_index in enumerate(sorted_indices):
            if expected_index != i:
                print(f"[Exchange] Missing packet {i} - reassembly failed")
                return None
            reassembled_data += self.received_packets[expected_index]
        
        try:
            keybits_json = reassembled_data.decode()
            peer_key_bits_raw = json.loads(keybits_json)
            peer_key_bits = {int(k): v for k, v in peer_key_bits_raw.items()}
            return peer_key_bits
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"[Exchange] Error parsing reassembled data: {e}")
            return None
    
    def exchange_indices(self):
        print("\n[Exchange] Starting reliable key bits exchange...")
        
        self.received_packets.clear()
        self.exchange_complete_received.clear()
        
        print(f"[Exchange] → Requesting peer key bits")
        request_frame = self.create_handshake_frame(FRAME_TYPE_KEYBITS_REQUEST)
        sendp(request_frame, iface=self.interface, verbose=False)
        
        if self.exchange_complete_received.wait(timeout=30):
            print(f"[Exchange] Received complete signal - reassembling data")
            
            self.peer_key_bits = self.reassemble_received_data()
            if self.peer_key_bits:
                self.peer_indices = list(self.peer_key_bits.keys())
                print(f"[Exchange] Successfully received {len(self.peer_key_bits)} key bits")
                self.keybits_received.set()
                return True
            else:
                print(f"[Exchange] Failed to reassemble peer key bits")
                return False
        else:
            print(f"[Exchange] Timeout waiting for peer key bits exchange")
            return False
    
    def find_common_indices(self):
        if not self.peer_key_bits:
            print("[Reconciliation] No peer key bits available")
            return []
        
        # Find indices that both devices used
        common_indices_set = set(self.my_key_bits.keys()) & set(self.peer_key_bits.keys())
        
        # Check which of these common indices have matching bit values
        matching_indices = []
        mismatched_indices = []
        
        for idx in common_indices_set:
            my_bit = self.my_key_bits[idx]
            peer_bit = self.peer_key_bits[idx]
            
            if my_bit == peer_bit:
                matching_indices.append(idx)
            else:
                mismatched_indices.append(idx)
        
        print(f"[Reconciliation] Index analysis:")
        print(f"  My indices: {len(self.my_key_bits)}")
        print(f"  Peer indices: {len(self.peer_key_bits)}")
        print(f"  Common indices: {len(common_indices_set)}")
        print(f"  Matching bit values: {len(matching_indices)}")
        print(f"  Mismatched bit values: {len(mismatched_indices)}")
        
        if mismatched_indices:
            print(f"[Reconciliation] Discarding {len(mismatched_indices)} indices with mismatched bits:")
            for idx in sorted(mismatched_indices)[:10]:  # Show first 10
                my_bit = self.my_key_bits[idx]
                peer_bit = self.peer_key_bits[idx]
                print(f"    Index {idx}: My bit={my_bit}, Peer bit={peer_bit}")
            if len(mismatched_indices) > 10:
                print(f"    ... and {len(mismatched_indices) - 10} more")
        
        return sorted(matching_indices)
    
    def generate_reconciled_key(self, common_indices):
        reconciled_key_bits = {}
        reconciled_key_string = ""
        
        for idx in common_indices:
            if idx in self.my_key_bits:
                bit_value = self.my_key_bits[idx]
                reconciled_key_bits[idx] = bit_value
                reconciled_key_string += str(bit_value)
        
        print(f"\n[Reconciliation] Generated reconciled key:")
        print(f"  Original key length: {len(self.my_key_bits)} bits")
        print(f"  Reconciled key length: {len(reconciled_key_string)} bits")
        print(f"  Retention rate: {len(reconciled_key_string)/len(self.my_key_bits)*100:.1f}%")
        
        return reconciled_key_bits, reconciled_key_string
    
    def save_reconciled_key(self, reconciled_key_bits, reconciled_key_string):
        output_file = self.key_data_file.replace('.json', '_reconciled.json')
        
        reconciled_data = {
            'role': self.role,
            'original_key_length': len(self.my_key_bits),
            'reconciled_key_length': len(reconciled_key_string),
            'reconciled_key_string': reconciled_key_string,
            'reconciled_key_bits': {str(k): v for k, v in reconciled_key_bits.items()},
            'retention_rate': len(reconciled_key_string) / len(self.my_key_bits) if self.my_key_bits else 0
        }
        
        with open(output_file, 'w') as f:
            json.dump(reconciled_data, f, indent=2)
        
        print(f"Reconciled key saved to {output_file}")
    
    def reconcile(self):
        try:
            # Step 1: Perform handshake
            if not self.perform_handshake():
                print("\nFailed to establish handshake - aborting reconciliation")
                return False
            
            # Step 2: Exchange indices (placeholder for now)
            if not self.exchange_indices():
                print("\nFailed to exchange indices - aborting reconciliation")
                return False
            
            # Step 3: Find common indices
            common_indices = self.find_common_indices()
            if not common_indices:
                print("\nNo common indices found - cannot reconcile keys")
                return False
            
            # Step 4: Generate reconciled key
            reconciled_key_bits, reconciled_key_string = self.generate_reconciled_key(common_indices)
            
            # Step 5: Save reconciled key
            self.save_reconciled_key(reconciled_key_bits, reconciled_key_string)
            
            print(f"\nBit reconciliation completed successfully!")
            return True
            
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            self.running = False
            return False
        finally:
            self.running = False


def main():
    parser = argparse.ArgumentParser(description='RSSI-based Key Bit Reconciliation')
    parser.add_argument('--peer-mac', type=str, required=True,
                        help='MAC address of peer device')
    parser.add_argument('--interface', type=str, default=INTERFACE,
                        help=f'Monitor mode interface (default: {INTERFACE})')
    parser.add_argument('--key-data', type=str, default='key_data.json',
                        help='Input key data JSON file')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    
    print("\nRSSI-Based Key Generation - Bit Reconciliation")
    print("=" * 60)
    
    try:
        mac_addr = get_if_hwaddr(args.interface)
    except:
        import random
        mac_addr = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
    
    print(f"Interface: {args.interface}")
    print(f"My MAC: {mac_addr}")
    print(f"Peer MAC: {args.peer_mac}")
    print(f"Key data file: {args.key_data}")
    print("=" * 60 + "\n")
    
    reconciler = BitReconciler(args.interface, mac_addr, args.peer_mac, args.key_data)
    
    success = reconciler.reconcile()
    
    if success:
        print("\nReconciliation completed successfully!")
    else:
        print("\nReconciliation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()