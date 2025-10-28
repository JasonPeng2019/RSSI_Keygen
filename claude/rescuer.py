#!/usr/bin/env python3
"""
rescuer.py - Detect survivor beacons and display RSSI information
"""

import sys
import time
import curses
import subprocess
import threading
from collections import defaultdict
from scapy.all import *

class RescuerDetector:
    def __init__(self, interface, channel):
        self.interface = interface
        self.channel = channel
        self.survivors = defaultdict(lambda: {'rssi': [], 'last_seen': 0, 'sequence': 0})
        self.running = True
        self.lock = threading.Lock()
        
    def set_monitor_mode(self):
        """Set interface to monitor mode"""
        print(f"Setting {self.interface} to monitor mode on channel {self.channel}...")
        subprocess.run(['bash', 'set_monitor.sh', self.interface, str(self.channel)])
        time.sleep(2)
        
    def packet_handler(self, packet):
        """Process captured packets looking for survivor beacons"""
        try:
            # Check if packet has RadioTap and Dot11 layers
            if packet.haslayer(RadioTap) and packet.haslayer(Dot11):
                # Check for beacon frames
                if packet.type == 0 and packet.subtype == 8:
                    # Check for our rescue SSID pattern
                    if packet.haslayer(Dot11Elt):
                        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                        
                        if ssid.startswith("RESCUE-"):
                            # Extract survivor ID
                            survivor_id = ssid.replace("RESCUE-", "")
                            
                            # Get RSSI from RadioTap
                            if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                                rssi = packet[RadioTap].dBm_AntSignal
                            else:
                                # Alternative RSSI extraction
                                rssi = -(256 - packet[RadioTap].notdecoded[-4]) if packet[RadioTap].notdecoded else -100
                            
                            # Extract sequence if available
                            sequence = 0
                            elt = packet[Dot11Elt]
                            while elt:
                                if elt.ID == 221:  # Vendor Specific
                                    info = elt.info.decode('utf-8', errors='ignore')
                                    if 'SEQ:' in info:
                                        try:
                                            sequence = int(info.split('SEQ:')[1].split('|')[0])
                                        except:
                                            pass
                                elt = elt.payload.getlayer(Dot11Elt)
                            
                            # Update survivor data
                            with self.lock:
                                self.survivors[survivor_id]['rssi'].append(rssi)
                                # Keep only last 10 RSSI values for averaging
                                if len(self.survivors[survivor_id]['rssi']) > 10:
                                    self.survivors[survivor_id]['rssi'].pop(0)
                                self.survivors[survivor_id]['last_seen'] = time.time()
                                self.survivors[survivor_id]['sequence'] = sequence
        except Exception as e:
            pass  # Silently ignore packet processing errors
    
    def sniff_packets(self):
        """Sniff packets in a separate thread"""
        sniff(iface=self.interface, prn=self.packet_handler, store=False, stop_filter=lambda x: not self.running)
    
    def draw_gui(self, stdscr):
        """Draw the ncurses GUI"""
        curses.curs_set(0)  # Hide cursor
        stdscr.nodelay(1)   # Non-blocking input
        stdscr.timeout(100) # Refresh every 100ms
        
        # Start sniffing thread
        sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        sniffer_thread.start()
        
        try:
            while self.running:
                stdscr.clear()
                height, width = stdscr.getmaxyx()
                
                # Title
                title = "=== SEARCH AND RESCUE - SURVIVOR DETECTOR ==="
                stdscr.addstr(0, (width - len(title)) // 2, title, curses.A_BOLD)
                
                # Info line
                info = f"Interface: {self.interface} | Channel: {self.channel} | Press 'q' to quit"
                stdscr.addstr(1, 0, info)
                stdscr.addstr(2, 0, "=" * min(width - 1, 80))
                
                current_time = time.time()
                
                with self.lock:
                    # Remove stale survivors (not seen in 10 seconds)
                    stale = [sid for sid, data in self.survivors.items() 
                            if current_time - data['last_seen'] > 10]
                    for sid in stale:
                        del self.survivors[sid]
                    
                    if not self.survivors:
                        stdscr.addstr(4, 0, "No survivors detected...", curses.A_DIM)
                    else:
                        # Header
                        stdscr.addstr(4, 0, "SURVIVOR ID", curses.A_BOLD)
                        stdscr.addstr(4, 15, "RSSI (dBm)", curses.A_BOLD)
                        stdscr.addstr(4, 30, "AVG RSSI", curses.A_BOLD)
                        stdscr.addstr(4, 42, "SIGNAL", curses.A_BOLD)
                        stdscr.addstr(4, 55, "LAST SEEN", curses.A_BOLD)
                        stdscr.addstr(4, 70, "SEQ", curses.A_BOLD)
                        
                        row = 5
                        for survivor_id, data in sorted(self.survivors.items()):
                            if row >= height - 2:
                                break
                                
                            # Calculate average RSSI
                            avg_rssi = sum(data['rssi']) / len(data['rssi']) if data['rssi'] else -100
                            current_rssi = data['rssi'][-1] if data['rssi'] else -100
                            
                            # Time since last seen
                            elapsed = current_time - data['last_seen']
                            time_str = f"{elapsed:.1f}s ago"
                            
                            # Signal strength indicator
                            if avg_rssi > -50:
                                signal = "VERY STRONG"
                                attr = curses.A_BOLD
                            elif avg_rssi > -60:
                                signal = "STRONG"
                                attr = curses.A_NORMAL
                            elif avg_rssi > -70:
                                signal = "MODERATE"
                                attr = curses.A_NORMAL
                            elif avg_rssi > -80:
                                signal = "WEAK"
                                attr = curses.A_DIM
                            else:
                                signal = "VERY WEAK"
                                attr = curses.A_DIM
                            
                            # Display survivor info
                            stdscr.addstr(row, 0, survivor_id[:12])
                            stdscr.addstr(row, 15, f"{current_rssi:4.0f}")
                            stdscr.addstr(row, 30, f"{avg_rssi:4.1f}")
                            stdscr.addstr(row, 42, signal, attr)
                            stdscr.addstr(row, 55, time_str)
                            stdscr.addstr(row, 70, f"{data['sequence']}")
                            
                            # RSSI trend (last 5 measurements)
                            if len(data['rssi']) >= 2:
                                recent = data['rssi'][-5:]
                                if len(recent) >= 2:
                                    trend = recent[-1] - recent[0]
                                    if trend > 2:
                                        trend_str = "↑ APPROACHING"
                                        trend_attr = curses.A_BOLD
                                    elif trend < -2:
                                        trend_str = "↓ MOVING AWAY"
                                        trend_attr = curses.A_DIM
                                    else:
                                        trend_str = "→ STABLE"
                                        trend_attr = curses.A_NORMAL
                                    
                                    if row < height - 2:
                                        stdscr.addstr(row + 1, 15, trend_str, trend_attr)
                            
                            row += 2
                
                # Instructions
                if height > 10:
                    stdscr.addstr(height - 2, 0, "Move toward INCREASING RSSI to find survivors", curses.A_BOLD)
                
                stdscr.refresh()
                
                # Check for quit command
                key = stdscr.getch()
                if key == ord('q') or key == ord('Q'):
                    self.running = False
                    break
                    
        except KeyboardInterrupt:
            self.running = False
        finally:
            self.running = False

def main():
    if len(sys.argv) < 3:
        print("Usage: sudo python3 rescuer.py <interface> <channel>")
        print("Example: sudo python3 rescuer.py wlan0 6")
        sys.exit(1)
    
    interface = sys.argv[1]
    channel = int(sys.argv[2])
    
    detector = RescuerDetector(interface, channel)
    detector.set_monitor_mode()
    
    print("Starting rescuer detection system...")
    print("Initializing interface...")
    time.sleep(2)
    
    # Run GUI
    curses.wrapper(detector.draw_gui)
    
    print("\nRescuer system stopped.")

if __name__ == "__main__":
    main()
