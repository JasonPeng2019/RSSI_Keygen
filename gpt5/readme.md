survivor: sudo python3 survivor_beacon.py --iface wlan0 --channel 6 --id S1 --rate 10
rescuer: sudo python3 rescuer_sniffer.py --iface wlan0 --channel 6

key exchange device A: sudo python3 key_exchange.py --iface wlan0 --channel 6 --id A --n 300
key exchange device B: sudo python3 key_exchange.py --iface wlan0 --channel 6 --id B --n 300
