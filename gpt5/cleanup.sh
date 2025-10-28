#!/bin/bash
# Reset wlan0 to monitor mode on channel 6
sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
sudo ip link show wlan0