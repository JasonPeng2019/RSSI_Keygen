# Quick Reference Guide

## Setup

```bash
# Install dependencies
sudo ./setup.sh

# OR manually:
sudo apt-get install python3-pip wireless-tools iw
pip3 install scapy numpy
```

## Part 1: Search and Rescue

### Survivor (Device 1)
```bash
# Basic usage
sudo python3 survivor.py wlan0 6

# With custom ID
sudo python3 survivor.py wlan0 6 ALICE

# What it does:
# - Sets wlan0 to monitor mode on channel 6
# - Transmits beacon every 500ms
# - Shows transmission count
# - Press Ctrl+C to stop
```

### Rescuer (Device 2)
```bash
# Basic usage
sudo python3 rescuer.py wlan0 6

# What it does:
# - Sets wlan0 to monitor mode on channel 6
# - Shows ncurses GUI with all detected survivors
# - Displays RSSI, trends, and timing
# - Press 'q' to quit
```

### Making the Video
```bash
# 1. Survivor starts program and hides
sudo python3 survivor.py wlan0 6 SURVIVOR1

# 2. Rescuer starts program and searches
sudo python3 rescuer.py wlan0 6

# 3. Record screen while moving around
# 4. Show RSSI increasing as you get closer
# 5. Successfully find the survivor
```

## Part 2: Key Exchange

### Both Devices
```bash
# Device 1 (will become initiator or responder automatically)
sudo python3 key_exchange.py wlan0 6

# Device 2 (start within 30 seconds of Device 1)
sudo python3 key_exchange.py wlan0 6

# What happens:
# 1. Automatic role determination (~5 seconds)
# 2. Prompt to wave hand between devices
# 3. 300 frames exchanged (~20 seconds)
# 4. Key calculation and reconciliation
# 5. Verification and display of results
```

### Procedure
1. Place devices ~0.5 meters apart
2. Start program on Device 1
3. Start program on Device 2 (within 30 seconds)
4. Wait for "wave your hand" message
5. Wave vigorously between devices for 15-20 seconds
6. Wait for results
7. Both should show matching keys

## Common Commands

### Check Wireless Interfaces
```bash
# List all interfaces
iw dev

# Check if interface exists
ifconfig wlan0
# or
ip link show wlan0
```

### Check Monitor Mode Support
```bash
# See supported modes
iw list | grep -A 10 "Supported interface modes"

# Should show "monitor" in the list
```

### Manually Set Monitor Mode
```bash
# Using the script
sudo ./set_monitor.sh wlan0 6

# OR manually:
sudo ip link set wlan0 down
sudo iw wlan0 set monitor control
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
```

### Check Current Mode and Channel
```bash
# Check mode
iwconfig wlan0

# Check detailed info
iw dev wlan0 info
```

### Kill Interfering Processes
```bash
# Some processes can interfere with monitor mode
sudo airmon-ng check kill

# Restart NetworkManager after testing
sudo service NetworkManager restart
```

### Test Packet Capture
```bash
# Capture 10 packets to verify monitor mode works
sudo tcpdump -i wlan0 -c 10

# Or with scapy
sudo python3 -c "from scapy.all import *; sniff(iface='wlan0', count=5, prn=lambda x: x.summary())"
```

## Troubleshooting

### "Permission denied" errors
```bash
# Always use sudo
sudo python3 survivor.py wlan0 6

# OR set capabilities (less secure)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### "No such device" error
```bash
# Check interface name
iw dev | grep Interface

# Common names: wlan0, wlan1, wlp2s0, wlx...
```

### Monitor mode not working
```bash
# Check if adapter supports monitor mode
iw list | grep monitor

# Try different adapter if available
# USB Wi-Fi adapters with Atheros/Ralink chipsets work best
```

### No packets captured
```bash
# Verify monitor mode is set
iwconfig wlan0
# Should show "Mode:Monitor"

# Verify interface is up
ip link show wlan0
# Should show "UP"

# Check you're on the right channel
iw dev wlan0 info
# Should match the channel you're using
```

### Rescuer not seeing survivor
```bash
# 1. Verify both on same channel
# 2. Check survivor is transmitting (should see output)
# 3. Try increasing power: sudo iw wlan0 set txpower fixed 2000
# 4. Move devices closer
# 5. Check for interference: sudo airodump-ng wlan0
```

### Key exchange fails
```bash
# 1. Ensure devices are close (0.5m)
# 2. Wave hand more vigorously
# 3. Increase frame count (edit script: num_frames=500)
# 4. Adjust z parameter (edit script: z=0.8)
# 5. Both devices on same channel
# 6. Start second device faster (within 10 seconds)
```

## Channel Selection

### 2.4 GHz Channels
```
Channel 1:  2412 MHz (non-overlapping)
Channel 2:  2417 MHz
Channel 3:  2422 MHz
Channel 4:  2427 MHz
Channel 5:  2432 MHz
Channel 6:  2437 MHz (non-overlapping, recommended)
Channel 7:  2442 MHz
Channel 8:  2447 MHz
Channel 9:  2452 MHz
Channel 10: 2457 MHz
Channel 11: 2462 MHz (non-overlapping)
```

**Recommendation**: Use channel 6 (least interference in most areas)

### Finding Best Channel
```bash
# Scan for networks
sudo iwlist wlan0 scan | grep -E 'Channel|ESSID'

# Use channel with fewest networks
```

## RSSI Values Guide

```
-30 to -50 dBm:  Excellent signal (very close)
-50 to -60 dBm:  Good signal (close)
-60 to -70 dBm:  Fair signal (medium distance)
-70 to -80 dBm:  Weak signal (far or through obstacles)
-80 to -90 dBm:  Very weak signal (very far)
Below -90 dBm:   Barely usable
```

## File Descriptions

```
set_monitor.sh     - Set monitor mode script
survivor.py        - Part 1: Beacon transmitter
rescuer.py         - Part 1: Beacon receiver with GUI
key_exchange.py    - Part 2: Complete key exchange
requirements.txt   - Python dependencies
setup.sh          - Automated setup script
README.md         - Full documentation
WRITEUP.md        - Assignment answers and analysis
```

## Tips for Success

### Part 1 (Search and Rescue)
- Start survivor first, let it transmit for a few seconds
- Keep rescuer laptop screen visible while moving
- Move slowly to observe RSSI changes
- Follow increasing RSSI (approaching) arrows
- Average RSSI more reliable than instantaneous

### Part 2 (Key Exchange)
- Place devices close but not touching (~50cm)
- Start second device quickly (within 30 seconds)
- Wave hand vigorously throughout exchange
- Move hand in various patterns (not just back/forth)
- Don't block both antennas simultaneously
- More hand motion = better results

## Getting Help

1. Check README.md for detailed explanations
2. Check WRITEUP.md for technical analysis
3. Read error messages carefully
4. Verify all prerequisites (monitor mode support, correct channel, etc.)
5. Test with basic packet capture first (tcpdump)

## Video Recording Tips

### For Part 1
- Use screen recording software (OBS, SimpleScreenRecorder)
- Show rescuer's screen clearly
- Narrate what you're doing
- Show RSSI changing as you move
- Include final "found survivor" moment
- Keep video under 3 minutes

### Recording Commands
```bash
# Install recorder
sudo apt-get install simplescreenrecorder

# Or use OBS Studio
sudo apt-get install obs-studio

# Command line option
ffmpeg -f x11grab -s 1920x1080 -i :0.0 -f alsa -i default output.mp4
```
