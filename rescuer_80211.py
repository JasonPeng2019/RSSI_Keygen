import threading
import time
from dataclasses import dataclass
from typing import Dict
from scapy.all import sniff
import curses

@dataclass
class SurvivorInfo:
    survivor_id: str
    rssi: float
    last_seen: float
    sequence: int
    mac_address: str
    
    def age(self) -> float:
        # How long since we last heard from this survivor
        return time.time() - self.last_seen
    
    def is_stale(self, threshold: float = 5.0) -> bool:
        # Is this survivor's data stale?
        return self.age() > threshold

survivors: Dict[str, SurvivorInfo] = {}
data_lock = threading.Lock()

def sniffer_thread(interface: str):
    
    def packet_handler(pkt):
        survivor_id, rssi, sequence, mac = parse_beacon(pkt)
        
        if survivor_id is not None:
            with data_lock:
                survivors[survivor_id] = SurvivorInfo(
                    survivor_id=survivor_id,
                    rssi=rssi,
                    last_seen=time.time(),
                    sequence=sequence,
                    mac_address=mac
                )
    
    sniff(iface=interface, prn=packet_handler, store=False)

def gui_thread():
    # Update GUI every 0.5 seconds
    
    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()
    stdscr.nodelay(1)  
    
    try:
        while True:
            time.sleep(0.5)
            
            #theoretically: mutex should block here
            with data_lock:
                current_survivors = survivors.copy()
            
            stdscr.clear()
            stdscr.addstr(0, 0, "=== RESCUE BEACON MONITOR ===", curses.A_BOLD)
            stdscr.addstr(1, 0, f"Time: {time.strftime('%H:%M:%S')}")
            stdscr.addstr(2, 0, f"Survivors detected: {len(current_survivors)}")
            stdscr.addstr(3, 0, "=" * 60)
            
            row = 5
            for sid, info in sorted(current_survivors.items()):
                distance = estimate_distance(info.rssi)
                
                if info.is_stale(5.0):
                    status = "STALE"
                    attr = curses.A_DIM
                elif info.rssi > -50:
                    status = "VERY CLOSE"
                    attr = curses.A_BOLD | curses.color_pair(1)  # Green
                elif info.rssi > -70:
                    status = "CLOSE"
                    attr = curses.A_NORMAL
                else:
                    status = "FAR"
                    attr = curses.A_DIM
                
                line1 = f"Survivor ID: {sid}"
                line2 = f"  RSSI: {info.rssi:6.1f} dBm | Distance: ~{distance:5.1f}m | {status}"
                line3 = f"  Last seen: {info.age():.1f}s ago | Seq: {info.sequence}"
                
                stdscr.addstr(row, 0, line1, curses.A_BOLD)
                stdscr.addstr(row + 1, 0, line2, attr)
                stdscr.addstr(row + 2, 0, line3)
                row += 4
            
            stdscr.addstr(row + 1, 0, "=" * 60)
            stdscr.addstr(row + 2, 0, "Press 'q' to quit")
            
            stdscr.refresh()
            
            key = stdscr.getch()
            if key == ord('q'):
                break
                
    finally:
        curses.endwin()

def estimate_distance(rssi: float) -> float:
    """
    Estimate distance from RSSI using path loss model
    Distance (m) = 10 ^ ((TxPower - RSSI) / (10 * n))
    where n = path loss exponent (2-4, typically 2 for free space)
    """
    tx_power = -20 # Assumed transmit power in dBm
    n = 2.5  # Path loss exponent
    
    if rssi == 0:
        return 999.9
    
    distance = 10 ** ((tx_power - rssi) / (10 * n))
    return distance

def parse_beacon(pkt):
    from scapy.all import Dot11Beacon, Dot11Elt, Dot11, RadioTap
    
    if pkt.haslayer(Dot11Beacon):
        # Extract SSID
        ssid = None
        if pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
        
        if ssid and ssid.startswith("RESCUE-"):
            parts = ssid.split('-')
            if len(parts) == 3:
                survivor_id = parts[1]
                sequence = int(parts[2])
                
                # RSSI
                rssi = -100  # Default
                if pkt.haslayer(RadioTap):
                    if hasattr(pkt[RadioTap], 'dBm_AntSignal'):
                        rssi = pkt[RadioTap].dBm_AntSignal
                
                # MAC
                mac = pkt[Dot11].addr2
                
                return survivor_id, rssi, sequence, mac
    
    return None, None, None, None

def main(interface: str):
    sniffer = threading.Thread(
        target=sniffer_thread, 
        args=(interface,), 
        daemon=True
    )
    sniffer.start()
    
    time.sleep(0.5)
    
    gui_thread() #doesnt need to be a thread because sniffer will run as a thread

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 rescuer.py <interface>")
        sys.exit(1)
    
    main(sys.argv[1])