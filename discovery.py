#!/usr/bin/env python3
"""
RSSI-based Key Generation - Role Determination
each device to first listen for a "broadcast" 
message that says, "I am the initaitor!". 
if there is no message heard after 5 seconds, 
start screaming a "broadcast" message that says 
"i am the inititator and am ready to begin" 
every 0.25 seconds. This device also runs a thread to sniff
 when not screaming. When a device hears the initiator, 
 it runs a thread to sniff as well, and 
 then responds every 0.25 seconds, "i am the  responder".
These should both timeout after 30 seconds if no response
is heard.  Then, each device should set itself as an initiator
or responder"""

import threading
import time
from scapy.all import *
import sys
import json

# Configuration
INTERFACE = "wlan0"  # monitor mode interface - change this to match your interface
CHANNEL = 6  # WiFi channel to use
LISTEN_TIMEOUT = 5  # Initial listen period in seconds
TRANSMIT_TIMEOUT = 30  # timeout
TRANSMIT_INTERVAL = 0.1  # Time between transmissions in seconds (faster)

# Custom frame types (using subtype field) - Use valid data frame subtypes
FRAME_TYPE_READY_BEGIN = 0x0  # Standard data frame
FRAME_TYPE_RESPONDER_ACK = 0x4  # Null data frame

# Magic number to identify protocol
MAGIC_BYTES = b"RSSI_KEY_GEN_2025"
PAYLOAD_READY_BEGIN = MAGIC_BYTES + b"|READY_BEGIN"
PAYLOAD_RESPONDER_ACK = MAGIC_BYTES + b"|RESPONDER_ACK"

class RoleManager:
    def __init__(self, interface, mac_addr):
        self.interface = interface
        self.mac_addr = mac_addr
        self.role = None
        self.role_lock = threading.Lock()
        self.running = True
        self.peer_found = threading.Event()
        self.peer_mac = None
        
    def create_custom_frame(self, frame_type):
        # Create a basic 802.11 data frame
        dot11 = Dot11(
            type=2,  # Data frame
            subtype=frame_type,
            addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
            addr2=self.mac_addr,  # Source (my MAC)
            addr3=self.mac_addr   # BSSID
        )
        
        # Use different payloads to distinguish frame types
        if frame_type == FRAME_TYPE_READY_BEGIN:
            payload = Raw(load=PAYLOAD_READY_BEGIN)
        else:  # RESPONDER_ACK
            payload = Raw(load=PAYLOAD_RESPONDER_ACK)
        
        frame = RadioTap() / dot11 / payload
        return frame
    
    def is_our_frame(self, pkt):
        if not pkt.haslayer(Dot11):
            return False, None
        
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            src_mac = pkt[Dot11].addr2
            
            print(f"[Debug] Checking payload from {src_mac}: {payload[:30]}...")
            
            # Check for our specific payloads (handle both with and without LLC layer)
            if payload == PAYLOAD_READY_BEGIN or PAYLOAD_READY_BEGIN in payload:
                print(f"[Debug] Found READY_BEGIN from {src_mac}")
                return True, ("READY_BEGIN", src_mac)
            elif payload == PAYLOAD_RESPONDER_ACK or PAYLOAD_RESPONDER_ACK in payload:
                print(f"[Debug] Found RESPONDER_ACK from {src_mac}")
                return True, ("RESPONDER_ACK", src_mac)
            else:
                print(f"[Debug] Payload doesn't match our protocol")
        
        return False, None
    
    def sniff_thread(self):
        """Continuously sniff for frames from other device"""
        print("[Sniffer] Started sniffing thread")
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            # Only debug 802.11 data frames (our type)
            if pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
                print(f"[Debug] Data frame from {pkt[Dot11].addr2}: {pkt.summary()}")
            
            is_ours, info = self.is_our_frame(pkt)
            if not is_ours:
                return
            
            frame_type, src_mac = info
            print("Found frame type:", frame_type, "from", src_mac)
            
            with self.role_lock:
                if frame_type == "READY_BEGIN" and self.role is None:
                    # become responder
                    print(f"[Sniffer] Heard READY_BEGIN from {src_mac}")
                    self.role = "RESPONDER"
                    self.peer_mac = src_mac
                    print("[Role] I am the RESPONDER")
                    
                elif frame_type == "RESPONDER_ACK" and self.role == "INITIATOR":
                    # Initiator heard responder
                    print(f"[Sniffer] Heard RESPONDER_ACK from {src_mac}")
                    self.peer_mac = src_mac
                    self.peer_found.set()
                    print("[Role] Responder found! Role negotiation complete.")
        
        # Sniff continuously
        sniff(iface=self.interface, prn=packet_handler, 
              stop_filter=lambda x: not self.running, store=0)
        
        print("[Sniffer] Sniffing thread stopped")
    
    def transmit_thread(self):
        """Continuously transmit role announcement frames"""
        print("[Transmitter] Started transmit thread")
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < TRANSMIT_TIMEOUT:
            with self.role_lock:
                current_role = self.role
            
            if current_role == "INITIATOR":
                # Send READY_BEGIN frames
                frame = self.create_custom_frame(FRAME_TYPE_READY_BEGIN)
                print(f"[Transmitter] Sending READY_BEGIN frame: {frame.summary()}")
                print(f"[Transmitter] Frame payload: {bytes(frame[Raw]) if frame.haslayer(Raw) else 'No Raw layer'}")
                sendp(frame, iface=self.interface, verbose=True)  # Enable verbose to see transmission
                print("[Transmitter] Sent READY_BEGIN")
                
                # Check if found a responder
                if self.peer_found.is_set():
                    print("[Transmitter] Peer found, stopping transmission")
                    self.running = False
                    break
                    
            elif current_role == "RESPONDER":
                # Send RESPONDER_ACK frames
                frame = self.create_custom_frame(FRAME_TYPE_RESPONDER_ACK)
                print(f"[Transmitter] Sending RESPONDER_ACK frame: {frame.summary()}")
                print(f"[Transmitter] Frame payload: {bytes(frame[Raw]) if frame.haslayer(Raw) else 'No Raw layer'}")
                sendp(frame, iface=self.interface, verbose=True)  # Enable verbose to see transmission
                print("[Transmitter] Sent RESPONDER_ACK")
                
                if (time.time() - start_time) > 5:  # Send ACKs for 5 seconds
                    print("[Transmitter] Sent enough ACKs, stopping")
                    self.running = False
                    break
            
            time.sleep(TRANSMIT_INTERVAL)
        
        if (time.time() - start_time) >= TRANSMIT_TIMEOUT:
            print("[Transmitter] Timeout reached!")
        
        print("[Transmitter] Transmit thread stopped")
    
    def determine_role(self):
        """Main role determination logic"""
        print("=" * 60)
        print("Starting Role Determination")
        print("=" * 60)
        
        # Phase 1: Initial listen period (no transmission)
        print(f"\n[Phase 1] Listening for {LISTEN_TIMEOUT} seconds...")
        
        def initial_listen_handler(pkt):
            is_ours, info = self.is_our_frame(pkt)
            if is_ours:
                frame_type, src_mac = info
                if frame_type == FRAME_TYPE_READY_BEGIN:
                    with self.role_lock:
                        if self.role is None:
                            self.role = "RESPONDER"
                            self.peer_mac = src_mac
                            print(f"[Phase 1] Heard READY_BEGIN from {src_mac}")
                            print("[Role] I am the RESPONDER")
                            return True  # Stop sniffing
            return False
        
        sniff(iface=self.interface, 
              timeout=LISTEN_TIMEOUT,
              stop_filter=initial_listen_handler,
              store=0)
        
        # Check if we heard an initiator
        with self.role_lock:
            if self.role == "RESPONDER":
                print("\n[Phase 1] Found initiator during listen phase")
            else:
                # No one heard, become initiator
                self.role = "INITIATOR"
                print("\n[Phase 1] No initiator heard - I am the INITIATOR")
        
        # Phase 2: Start continuous transmission and sniffing
        print(f"\n[Phase 2] Starting transmission and continuous sniffing...")
        
        sniffer = threading.Thread(target=self.sniff_thread, daemon=True)
        sniffer.start()
        
        # Start transmitter thread
        transmitter = threading.Thread(target=self.transmit_thread, daemon=True)
        transmitter.start()
        
        # Wait for threads to complete
        transmitter.join()
        self.running = False
        sniffer.join(timeout=2)
        
        print("\n" + "=" * 60)
        print("Role Determination Complete")
        print("=" * 60)
        print(f"Final Role: {self.role}")
        print(f"Peer MAC: {self.peer_mac}")
        print("=" * 60)
        
        return self.role, self.peer_mac


def setup_monitor_mode(interface):
    """Helper to set up monitor mode (requires root)"""
    print(f"Setting up monitor mode on {interface}...")
    # Note: may need to configure this manually beforehand:
    # sudo ip link set wlan0 down
    # sudo iw wlan0 set monitor none
    # sudo ip link set wlan0 up
    # sudo iw dev wlan0 set channel 6
    pass


def get_mac_address(interface):
    """Get MAC address of interface"""
    try:
        # Try to get from system
        mac = get_if_hwaddr(interface)
        return mac
    except:
        # Fallback to random MAC for testing
        import random
        return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])


def main():
    if os.geteuid() != 0:
        print("This script must be run as root!")
        sys.exit(1)
    
    print("RSSI-Based Key Generation - Role Determination")
    print("Multi-threaded implementation\n")
    
    # Get MAC address
    mac_addr = get_mac_address(INTERFACE)
    print(f"Using interface: {INTERFACE}")
    print(f"MAC Address: {mac_addr}")
    print(f"Channel: {CHANNEL}\n")
    
    # Create role manager
    manager = RoleManager(INTERFACE, mac_addr)
    
    try:
        role, peer_mac = manager.determine_role()
        
        if role and peer_mac:
            print(f"\n SUCCESS: I am the {role}")
            print(f" Peer device: {peer_mac}")
            
            # Save role and peer MAC to JSON file
            config_data = {
                'role': role,
                'peer_mac': peer_mac
            }
            
            try:
                with open('role_config.json', 'w') as f:
                    json.dump(config_data, f, indent=2)
                print("Role configuration saved to role_config.json")
            except Exception as e:
                print(f"Warning: Could not save role config: {e}")
            
            print("\nReady to proceed with frame exchange...")
        else:
            print("\n FAILED: Could not determine role or find peer")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        manager.running = False
        sys.exit(0)


if __name__ == "__main__":
    main()