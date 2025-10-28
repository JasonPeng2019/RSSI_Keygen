#!/bin/bash
# set_monitor.sh - Set Wi-Fi adapter to monitor mode
# Usage: ./set_monitor.sh <interface> <channel>

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <interface> <channel>"
    echo "Example: $0 wlan0 6"
    exit 1
fi

IFACE=$1
CHANNEL=$2

echo "Setting $IFACE to monitor mode on channel $CHANNEL..."

# Bring interface down
sudo ip link set $IFACE down

# Set monitor mode
sudo iw $IFACE set monitor control

# Bring interface up
sudo ip link set $IFACE up

# Set channel
sudo iw dev $IFACE set channel $CHANNEL

echo ""
echo "Monitor mode configured. Interface status:"
echo "=========================================="
iwconfig $IFACE
echo ""
echo "Interface details:"
iw dev $IFACE info
