#!/usr/bin/env python3
# key_exchange.py
# Usage: sudo python3 key_exchange.py --iface wlan0 --channel 6 --id A --n 300
# Runs same program on both devices. Automatically negotiates roles.

import argparse
import os
import time
import threading
import re
import json
import hashlib
from collections import defaultdict
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, LLC, SNAP, Raw, sendp, get_if_hwaddr

# Global storage
rx_lock = threading.Lock()
rx_data = {}  # index -> (timestamp, rssi, from_role)

def set_monitor(iface, channel, script="./set_monitor_mode.sh"):
    if os.path.exists(script):
        os.system(f"sudo {script} {iface} {channel}")
    else:
        print("[!] monitor script not found; assume already in monitor mode")

def make_beacon(ssid_str, src_mac):
    return (RadioTap() /
            Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2=src_mac, addr3=src_mac) /
            Dot11Beacon() /
            Dot11Elt(ID="SSID", info=ssid_str.encode()) /
            LLC() / SNAP() / Raw(load=""))

def send_beacon(iface, ssid):
    pkt = make_beacon(ssid, get_if_hwaddr(iface))
    sendp(pkt, iface=iface, verbose=False)

def parse_ssid(pkt):
    if not pkt.haslayer(Dot11):
        return None
    try:
        elt = pkt.getlayer("Dot11Elt")
        while elt:
            if elt.ID == 0:
                return elt.info.decode(errors="ignore")
            elt = elt.payload.getlayer("Dot11Elt")
    except Exception:
        return None
    return None

def get_rssi(pkt):
    try:
        return int(pkt[RadioTap].dBm_AntSignal)
    except Exception:
        try:
            return int(pkt[RadioTap].dBm_AntSig)
        except Exception:
            return None

# Sniffer thread - collect READY / IDX frames from peer
def sniffer(iface, stop_event, role_hint=None):
    def handler(pkt):
        ssid = parse_ssid(pkt)
        if not ssid:
            return
        rssi = get_rssi(pkt)
        ts = time.time()
        with rx_lock:
            # store raw receptions for analysis later
            # we keep a list per ssid tag for debugging
            rx_data.setdefault("raw", []).append((ts, ssid, rssi))
    sniff(iface=iface, prn=handler, store=False, stop_filter=lambda p: stop_event.is_set())

def detect_peer_ready(iface, listen_seconds=1.0):
    # listen for KEYX_READY on channel for a short time
    stop_event = threading.Event()
    t = threading.Thread(target=sniffer, args=(iface, stop_event), daemon=True)
    t.start()
    time.sleep(listen_seconds)
    stop_event.set()
    t.join(timeout=1.0)
    with rx_lock:
        raw = rx_data.get("raw", [])
    for (_, ssid, _) in raw:
        if ssid.startswith("KEYX_READY:"):
            return ssid.split(":",1)[1]  # sender id
    return None

# Higher-level role negotiation & exchange
def run_key_exchange(iface, myid, n_frames=300, z=0.8, channel=6, monitor_script="./set_monitor_mode.sh"):
    set_monitor(iface, channel, monitor_script)
    print("[*] Detecting whether peer is present...")
    peer = detect_peer_ready(iface, listen_seconds=1.0)
    if peer:
        print(f"[+] Heard READY from {peer}; I am responder")
        role = "responder"
    else:
        print("[+] No READY heard; I will be initiator")
        role = "initiator"

    src_mac = get_if_hwaddr(iface)

    # For receiver, we will run a sniff thread to capture `IDX` frames and record rssi
    stop_event = threading.Event()
    def recv_handler(pkt):
        ssid = parse_ssid(pkt)
        if not ssid:
            return
        rssi = get_rssi(pkt)
        ts = time.time()
        # Ready/ack handling
        if ssid.startswith("KEYX_READY:"):
            # someone else initiating
            peerid = ssid.split(":",1)[1]
            with rx_lock:
                rx_data.setdefault("ready", set()).add(peerid)
            return
        if ssid.startswith("KEYX_ACK:"):
            with rx_lock:
                rx_data.setdefault("ack", set()).add(ssid.split(":",1)[1])
            return
        m = re.match(r"IDX:([0-9]+):FROM:([^:]+)", ssid)
        if m:
            idx = int(m.group(1))
            fromid = m.group(2)
            with rx_lock:
                rx_data.setdefault("idx", {}).setdefault(idx, {})[fromid] = (ts, rssi)
            return
    t_sniff = threading.Thread(target=lambda: sniff(iface=iface, prn=recv_handler, store=False, stop_filter=lambda p: stop_event.is_set()), daemon=True)
    t_sniff.start()

    # Role behaviors
    if role == "initiator":
        # send READY for a short period, wait for ACK from a responder
        print("[*] Sending READY beacons...")
        start = time.time()
        responder_id = None
        while time.time() - start < 2.0:  # 2 seconds to find a responder
            ss = f"KEYX_READY:{myid}"
            send_beacon(iface, ss)
            time.sleep(0.05)
            with rx_lock:
                acks = rx_data.get("ack", set())
            if acks:
                responder_id = list(acks)[0]
                break
        if not responder_id:
            # maybe responder already sent READY and we detected earlier
            with rx_lock:
                readyset = rx_data.get("ready", set())
            if readyset:
                responder_id = list(readyset)[0]
        if not responder_id:
            print("[!] No responder found. Exiting.")
            stop_event.set()
            t_sniff.join(timeout=1.0)
            return
        print(f"[+] Responder: {responder_id}. Beginning exchange of {n_frames} frames.")
        # send indices 0..n_frames-1 rapidly; expect responder to echo each
        for i in range(n_frames):
            ss = f"IDX:{i}:FROM:{myid}"
            send_beacon(iface, ss)
            # small pause to let replies happen quickly
            time.sleep(0.01)
        # allow some time for lingering replies
        time.sleep(1.0)
    else:
        # responder: send ACK and respond to index frames with echo
        print("[*] I am responder; sending ACKs and waiting for idx frames")
        # send an explicit ack (so initiator hears)
        for _ in range(5):
            send_beacon(iface, f"KEYX_ACK:{myid}")
            time.sleep(0.05)
        # listen and upon each IDX from initiator, reply immediately with same index marker
        # implementing reply loop by repeatedly checking rx_data raw items
        start_time = time.time()
        timeout = 30
        seen_idxs = set()
        # We'll run for up to timeout seconds to capture indices
        while time.time() - start_time < timeout:
            # scan raw recently seen frames
            with rx_lock:
                idxs = rx_data.get("idx", {})
                # idxs is index->{fromid: (ts,rssi)}
                for idx, entry in idxs.items():
                    # if it's from initiator (we can't know initiator id easily) but reply anyway
                    if idx not in seen_idxs:
                        seen_idxs.add(idx)
                        # reply
                        ss = f"IDX:{idx}:FROM:{myid}"
                        send_beacon(iface, ss)
                        # immediate back-to-back occasionally
                        time.sleep(0.005)
            time.sleep(0.05)
        print("[*] Responder done listening for IDX frames (timeout).")
        time.sleep(0.5)

    # after exchange, collate indices and RSSIs
    stop_event.set()
    t_sniff.join(timeout=1.0)

    # Build index->rssi list from rx_data['idx']
    with rx_lock:
        idxmap = rx_data.get("idx", {})
    # We want the device's *received* RSSI values for indices; it will have entries where key=index and fromid in mapping.
    # For this program, we will extract all RSSI readings we received and associate with index.
    local_rssi = {}  # idx -> rssi
    for idx, entry in idxmap.items():
        # entry maps fromid -> (ts, rssi)
        # If this device is initiator, it's looking for replies from responder (which will appear as fromid=responder_id)
        # If responder, it's looking for initiator transmissions (fromid=initiator)
        # We don't strictly rely on the fromid field because other devices could interfere; pick the first rssi value present
        for fromid, (ts, rssi) in entry.items():
            if rssi is not None:
                local_rssi[int(idx)] = rssi
                break

    indices = sorted(local_rssi.keys())
    rssi_values = [local_rssi[i] for i in indices]
    print(f"[*] Collected {len(rssi_values)} RSSI samples (indices {indices[:3]} ... {indices[-3:] if indices else []})")

    if len(rssi_values) == 0:
        print("[!] No samples collected; aborting.")
        return

    # Compute mean and stddev
    import math
    mean = sum(rssi_values)/len(rssi_values)
    var = sum((x-mean)**2 for x in rssi_values)/len(rssi_values)
    std = math.sqrt(var) if var>0 else 1.0
    print(f"[*] mean={mean:.2f}, std={std:.2f}")

    # Derive bits per index
    bits = {}  # idx -> bit
    for i, val in zip(indices, rssi_values):
        if abs(val-mean) > z * std:
            bits[i] = 1 if val > mean else 0
    print(f"[*] Derived bits at {len(bits)} indices (z={z})")

    # Share indices used (not bit values) with peer to find intersection.
    # For lab simplicity we send our indices as a JSON-encoded short string via beacons using tag LIST:...
    # Break into small chunks of up to ~60 chars to fit SSID
    my_indices = sorted(bits.keys())
    chunk = ",".join(map(str,my_indices))
    # send 3 times
    for _ in range(3):
        send_beacon(iface, f"KEYX_INDICES:{myid}:{chunk[:60]}")
        time.sleep(0.05)
    time.sleep(0.5)

    # Now collect peer indices (we previously captured rx_data raw). Search rx_data['raw'] for KEYX_INDICES
    peer_indices = set()
    with rx_lock:
        raw = rx_data.get("raw", [])
    for (_, ssid, _) in raw:
        if ssid.startswith("KEYX_INDICES:"):
            parts = ssid.split(":",2)
            if len(parts) >= 3:
                other_chunk = parts[2]
                for s in other_chunk.split(","):
                    if s.strip().isdigit():
                        peer_indices.add(int(s.strip()))
    common = set(my_indices).intersection(peer_indices)
    if not common:
        print("[!] No common indices identified. Trying fallback: intersection of observed indices in idxmap")
        # fallback: if peer didn't send indices, try intersection of indices seen locally and those we heard labeled from peer
        common = set(idxmap.keys()).intersection(set(idxmap.keys()))
    common = sorted(common)
    print(f"[*] Common indices count: {len(common)}")

    # Build final key bits
    key_bits = []
    for idx in common:
        key_bits.append(str(bits[idx]))
    key_str = "".join(key_bits)
    print(f"[*] Key bits (len {len(key_str)}): {key_str}")

    # Confirm the key by hashing
    key_digest = hashlib.sha256(key_str.encode()).hexdigest()
    print(f"[*] Key digest (sha256): {key_digest[:12]}...")

    # Send key digest (commit)
    # Send short digest in multiple beacons
    for _ in range(3):
        send_beacon(iface, f"KEYX_DIGEST:{myid}:{key_digest[:16]}")
        time.sleep(0.05)
    # Wait to collect peer digest
    time.sleep(1.0)
    peer_digest = None
    with rx_lock:
        raw = rx_data.get("raw", [])
    for (_, ssid, _) in raw:
        if ssid.startswith("KEYX_DIGEST:"):
            parts = ssid.split(":",2)
            if len(parts) >= 3:
                peer_digest = parts[2]
                break
    print(f"[*] Peer digest observed: {peer_digest}")
    if peer_digest and peer_digest.startswith(key_digest[:len(peer_digest)]):
        print("[+] Key confirmed: digests match (likely both have same key)")
    else:
        print("[!] Key digests do not match or no digest observed. Keys likely differ.")

    # Print final result summary
    print("=== SUMMARY ===")
    print(f"role: {role}")
    print(f"collected_samples: {len(rssi_values)}")
    print(f"derived_bits: {len(key_str)}")
    print(f"key_bits: {key_str}")
    print(f"sha256_prefix: {key_digest[:16]}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--channel", required=True, type=int)
    parser.add_argument("--id", required=True)
    parser.add_argument("--n", default=300, type=int, help="number of frames to try exchange")
    parser.add_argument("--z", default=0.8, type=float, help="z threshold in stddevs")
    parser.add_argument("--monitor-script", default="./set_monitor_mode.sh")
    args = parser.parse_args()
    run_key_exchange(args.iface, args.id, n_frames=args.n, z=args.z, channel=args.channel, monitor_script=args.monitor_script)
