#!/bin/bash
# setup.sh - Setup script for wireless security lab

echo "=========================================="
echo "Wireless Security Lab - Setup Script"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./setup.sh)"
    exit 1
fi

echo "[1/5] Updating package lists..."
apt-get update

echo ""
echo "[2/5] Installing system dependencies..."
apt-get install -y python3 python3-pip wireless-tools iw net-tools

echo ""
echo "[3/5] Installing Python packages..."
pip3 install -r requirements.txt

echo ""
echo "[4/5] Making scripts executable..."
chmod +x set_monitor.sh
chmod +x survivor.py
chmod +x rescuer.py
chmod +x key_exchange.py

echo ""
echo "[5/5] Checking wireless interfaces..."
echo ""
echo "Available wireless interfaces:"
iw dev | grep Interface | awk '{print "  - " $2}'

echo ""
echo "=========================================="
echo "Setup complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Identify your wireless interface (e.g., wlan0)"
echo "2. Check if it supports monitor mode:"
echo "   iw list | grep monitor"
echo ""
echo "3. For Part 1 (Search and Rescue):"
echo "   Survivor:  sudo python3 survivor.py <interface> <channel>"
echo "   Rescuer:   sudo python3 rescuer.py <interface> <channel>"
echo ""
echo "4. For Part 2 (Key Exchange):"
echo "   Both devices: sudo python3 key_exchange.py <interface> <channel>"
echo ""
echo "See README.md for detailed instructions."
