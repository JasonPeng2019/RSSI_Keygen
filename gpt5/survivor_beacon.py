#!/usr/bin/env python3
# survivor_beacon.py
# Usage: sudo python3 survivor_beacon.py --iface wlan0 --channel 6 --id S1 --rate 10
# Sends custom beacon frames with SSID containing SRV:<id>:SEQ:<n>

import argparse
import time
import os
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, LLC, SNAP, Raw, sendp, get_if_hwaddr

def set_monitor(iface, channel, script="./set_monitor_mode.sh"):
    if os.path.exists(script):
        os.system(f"sudo {script} {iface} {channel}")
    else:
        print("[!] monitor script not found; assume already in monitor mode")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--channel", required=True, type=int)
    parser.add_argument("--id", default="S1")
    parser.add_argument("--rate", default=10, type=float, help="beacons per second")
    parser.add_argument("--monitor-script", default="./set_monitor_mode.sh")
    args = parser.parse_args()
    
    hw = get_if_hwaddr(args.iface)

    set_monitor(args.iface, args.channel, args.monitor_script)

    seq = 0
    interval = 1.0 / args.rate
    print(f"[+] Sending beacons on {args.iface} chan {args.channel} id {args.id} @ {args.rate}Hz")

    try:
        while True:
            ssid = f"SRV:{args.id}:SEQ:{seq}:INFO:OK"
            beacon = (
                RadioTap() /
                Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=hw, addr3=hw) /
                Dot11Beacon() /
                Dot11Elt(ID="SSID", info=ssid.encode()) /
                LLC() / SNAP() / Raw(load="")  # Windows expects LLC/SNAP encapsulation
            )
            sendp(beacon, iface=args.iface, verbose=False)
            seq = (seq + 1) % 65536
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[+] Stopped")

if __name__ == "__main__":
    main()
