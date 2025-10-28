#!/usr/bin/env bash
# set_monitor_mode.sh
# usage: ./set_monitor_mode.sh <iface> <channel>
# Example: sudo ./set_monitor_mode.sh wlan0 6

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <iface> <channel>"
  exit 1
fi

IFACE="$1"
CHAN="$2"

echo "[*] Bringing $IFACE down..."
sudo ip link set "$IFACE" down || { echo "ip link set down failed"; exit 2; }

echo "[*] Setting $IFACE type monitor..."
# try using iw to set monitor type
sudo iw "$IFACE" set monitor control || {
  # fallback: create monitor interface mon0 if direct set fails
  echo "[*] fallback: creating monitor interface mon0"
  sudo ip link set "$IFACE" down
  sudo iw dev "$IFACE" interface add mon0 type monitor || { echo "failed to create mon0"; exit 3; }
  IFACE="mon0"
}

echo "[*] Bringing $IFACE up..."
sudo ip link set "$IFACE" up || { echo "ip link set up failed"; exit 4; }

echo "[*] Setting channel to $CHAN..."
# Use iw to set channel (works for nl80211 drivers)
sudo iw dev "$IFACE" set channel "$CHAN" || {
  echo "[!] iw set channel failed; try 'iwconfig' fallback..."
  sudo iwconfig "$IFACE" channel "$CHAN" || { echo "setting channel failed"; }
}

echo "[*] Interface status:"
sudo iw dev "$IFACE" info
echo
echo "[*] ifconfig output (brief):"
ip addr show "$IFACE" | sed -n '1,8p'
