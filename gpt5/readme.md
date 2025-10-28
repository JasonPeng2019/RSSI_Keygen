survivor: sudo python3 survivor_beacon.py --iface wlan0 --channel 6 --id S1 --rate 10
rescuer: sudo python3 rescuer_sniffer.py --iface wlan0 --channel 6

key exchange device A: sudo python3 key_exchange.py --iface wlan0 --channel 6 --id A --n 300
key exchange device B: sudo python3 key_exchange.py --iface wlan0 --channel 6 --id B --n 300

print(f"[*] Common indices count: {len(common_indices)}")
key_bits = []
for idx in common_indices:
    if idx in bits:              # ✅ only append existing bits
        key_bits.append(str(bits[idx]))

if not key_bits:
    print("[!] No overlapping bits found; aborting key generation.")
    return
