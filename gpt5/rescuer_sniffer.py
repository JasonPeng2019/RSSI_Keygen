#!/usr/bin/env python3
# rescuer_sniffer.py
# Usage: sudo python3 rescuer_sniffer.py --iface wlan0 --channel 6

import argparse
import threading
import time
import re
from collections import defaultdict, deque
from scapy.all import sniff, RadioTap, Dot11
import curses
import os
import math

# Per-survivor data structure
class Survivor:
    def __init__(self, sid):
        self.id = sid
        self.rssi_history = deque(maxlen=20)
        self.last_seen = 0
        self.last_seq = None

survivors = {}
survivors_lock = threading.Lock()

def parse_ssid(pkt):
    # try to get SSID element from Dot11Elt in scapy
    if pkt.haslayer(Dot11):
        try:
            # Dot11Elt layers are chained; find SSID layer
            elt = pkt.getlayer("Dot11Elt")
            while elt:
                if elt.ID == 0:
                    ssid = elt.info.decode(errors="ignore")
                    return ssid
                elt = elt.payload.getlayer("Dot11Elt")
        except Exception:
            return None
    return None

def get_rssi(pkt):
    # scapy RadioTap might have dBm_AntSignal
    try:
        if pkt.haslayer(RadioTap):
            r = pkt[RadioTap].dBm_AntSignal
            return int(r)
    except Exception:
        pass
    # fallback attempts
    try:
        # some drivers present an "dBm_AntSig" variant
        return int(pkt.notdecoded[-1])
    except Exception:
        return None

def packet_handler(pkt):
    ssid = parse_ssid(pkt)
    if not ssid:
        return
    if not ssid.startswith("SRV:"):
        return
    # parse SRV:<ID>:SEQ:<seq>...
    m = re.match(r"SRV:([^:]+):SEQ:([0-9]+)", ssid)
    if not m:
        return
    sid = m.group(1)
    seq = int(m.group(2))
    rssi = get_rssi(pkt)
    now = time.time()
    with survivors_lock:
        if sid not in survivors:
            survivors[sid] = Survivor(sid)
        s = survivors[sid]
        s.last_seen = now
        s.rssi_history.append((now, rssi))
        s.last_seq = seq

def sniffer_thread(iface):
    sniff(iface=iface, prn=packet_handler, store=False)

def draw_ui(stdscr, iface):
    curses.curs_set(0)
    stdscr.nodelay(True)
    while True:
        stdscr.erase()
        stdscr.addstr(0,0,f"Rescuer RSSI monitor on {iface} — press q to quit")
        stdscr.addstr(1,0,f"{'ID':6} {'LastRSSI':8} {'Trend':6} {'Age(s)':7} {'Samples':7}")
        with survivors_lock:
            rows = list(survivors.values())
        rows.sort(key=lambda s: s.id)
        y = 2
        for s in rows:
            age = time.time() - s.last_seen
            last_rssi = None
            trend = "—"
            samples = len(s.rssi_history)
            if samples>0:
                last_rssi = s.rssi_history[-1][1]
                # compute trend by comparing average of last 3 to previous 3
                if samples >= 6:
                    recent = [r for (_,r) in list(s.rssi_history)[-3:]]
                    prev = [r for (_,r) in list(s.rssi_history)[-6:-3]]
                    if None not in recent+prev:
                        recent_avg = sum(recent)/len(recent)
                        prev_avg = sum(prev)/len(prev)
                        if recent_avg - prev_avg > 2:
                            trend = "▲"
                        elif prev_avg - recent_avg > 2:
                            trend = "▼"
                        else:
                            trend = "—"
            rssi_str = f"{last_rssi}" if last_rssi is not None else "N/A"
            stdscr.addstr(y, 0, f"{s.id:6} {rssi_str:8} {trend:6} {age:7.1f} {samples:7}")
            y += 1
            if y >= curses.LINES-1:
                break
        stdscr.refresh()
        try:
            c = stdscr.getch()
            if c == ord('q'):
                break
        except Exception:
            pass
        time.sleep(0.25)

def set_monitor(iface, channel, script="./set_monitor_mode.sh"):
    if os.path.exists(script):
        os.system(f"sudo {script} {iface} {channel}")
    else:
        print("[!] monitor script not found; assume already in monitor mode")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--channel", required=True, type=int)
    parser.add_argument("--monitor-script", default="./set_monitor_mode.sh")
    args = parser.parse_args()

    set_monitor(args.iface, args.channel, args.monitor_script)

    t = threading.Thread(target=sniffer_thread, args=(args.iface,), daemon=True)
    t.start()
    curses.wrapper(draw_ui, args.iface)

if __name__ == "__main__":
    main()
