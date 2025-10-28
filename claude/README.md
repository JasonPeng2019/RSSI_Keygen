# Wireless Security Lab - Search and Rescue & Key Exchange

This repository contains implementations for two wireless security exercises:
1. Search and Rescue Locator using Wi-Fi beacons and RSSI
2. Proximity-based Key Exchange using RSSI measurements

## Requirements

### Hardware
- Two laptops or devices with Wi-Fi adapters that support monitor mode
- Wi-Fi USB dongles (if built-in adapters don't support monitor mode)
- Recommended: Adapters with Atheros, Ralink, or Realtek chipsets

### Software
- Linux (Ubuntu/Debian recommended)
- Python 3.7+
- Required Python packages:
  ```bash
  sudo apt-get update
  sudo apt-get install python3-pip wireless-tools iw
  pip3 install scapy numpy
  ```

## Part 1: Search and Rescue Locator

### Overview
A system where survivors transmit Wi-Fi beacon frames, and rescuers detect these beacons using RSSI (Received Signal Strength Indicator) measurements to locate survivors.

### Files
- `set_monitor.sh` - Script to configure Wi-Fi adapter in monitor mode
- `survivor.py` - Transmit beacon frames
- `rescuer.py` - Detect beacons and display RSSI information

### Monitor Mode

#### What is Monitor Mode?
Monitor mode (also called RFMON mode) allows a wireless network adapter to capture all wireless packets in the air, regardless of their destination. Unlike managed mode where the adapter only captures packets destined for its MAC address, monitor mode captures:
- All beacon frames
- All data frames
- All management and control frames
- Packets from all networks on the channel

This is essential for:
- Measuring RSSI of arbitrary packets
- Network analysis and security auditing
- Implementing custom wireless protocols

#### Why Set the Channel?
Setting the channel is critical because:
1. **Frequency Isolation**: Wi-Fi operates on specific channels (e.g., 2.4 GHz: channels 1-11, 5 GHz: many more channels). The adapter can only listen to one channel at a time.
2. **Signal Detection**: If the survivor transmits on channel 6 but the rescuer listens on channel 11, no beacons will be detected.
3. **Reduced Interference**: By selecting a specific channel, we avoid interference from other networks and can focus on our target signals.
4. **Synchronization**: Both survivor and rescuer must be on the same channel for communication.

### Usage

#### 1. Setup Monitor Mode (Both Devices)
```bash
chmod +x set_monitor.sh
sudo ./set_monitor.sh wlan0 6
```

This script:
- Takes interface name (e.g., wlan0) and channel number as parameters
- Brings the interface down
- Sets monitor mode
- Brings the interface back up
- Sets the specified channel
- Displays confirmation of monitor mode status

#### 2. Survivor Program
```bash
sudo python3 survivor.py wlan0 6 [optional_survivor_id]
```

The survivor device:
- Transmits custom beacon frames every 500ms
- Each beacon contains:
  - Unique survivor ID (auto-generated or specified)
  - Sequence number (to track beacons)
  - Timestamp
- Uses SSID format: "RESCUE-{ID}"
- Includes RadioTap header for proper injection

#### 3. Rescuer Program
```bash
sudo python3 rescuer.py wlan0 6
```

The rescuer device:
- Displays real-time ncurses GUI
- Shows all detected survivors with:
  - Current RSSI (dBm)
  - Average RSSI (10-sample moving average)
  - Signal strength indicator
  - Time since last beacon
  - Trend indicator (approaching/moving away/stable)
- Updates continuously
- Removes stale survivors (not seen in 10 seconds)

### Beacon Design

#### Frame Structure
```
[RadioTap Header] [802.11 Management Frame] [Beacon] [SSID] [Custom IE]
```

**Components:**
1. **RadioTap Header**: Required for packet injection, contains metadata
2. **802.11 Management Frame (Type 0, Subtype 8)**: Standard beacon frame
3. **SSID Element**: "RESCUE-{survivor_id}" for easy identification
4. **Custom Information Element**: Contains sequence number and timestamp

#### Transmission Strategy
- **Frequency**: Every 500ms (2 Hz)
  - Fast enough for real-time tracking
  - Slow enough to avoid congestion
- **Power**: Maximum transmit power for range
- **Broadcast**: Sent to FF:FF:FF:FF:FF:FF (all devices)

#### Multiple Survivors
Each survivor gets a unique ID (UUID-based), allowing the rescuer to:
- Track multiple survivors simultaneously
- Differentiate between different survivors
- Navigate to the closest or prioritized survivor

### RSSI as Distance Proxy

#### Theory
RSSI (Received Signal Strength Indicator) is measured in dBm (decibels relative to 1 milliwatt). The relationship between RSSI and distance follows the log-distance path loss model:

```
RSSI = RSSI₀ - 10n·log₁₀(d/d₀)
```

Where:
- RSSI₀ is the signal strength at reference distance d₀
- n is the path loss exponent (typically 2-4)
- d is the distance

In theory, higher RSSI = closer proximity.

#### Where RSSI Can Go Wrong

**1. Multipath Effects**
- Signals reflect off walls, floors, furniture
- Constructive/destructive interference
- Can cause RSSI to fluctuate wildly even at same distance

**2. Obstacles**
- Walls (especially concrete/metal) significantly attenuate signal
- Person behind a wall may show weaker RSSI than person farther away in open space
- Human bodies also absorb 2.4 GHz signals

**3. Antenna Orientation**
- Directional antennas have different gain patterns
- RSSI varies based on relative orientation of devices
- Movement can cause rapid RSSI changes

**4. Interference**
- Other Wi-Fi networks on same/adjacent channels
- Bluetooth, microwaves, other 2.4 GHz devices
- Can temporarily degrade RSSI

**5. Environmental Factors**
- Temperature and humidity affect signal propagation
- Metal objects cause reflections
- Water (including people) absorbs signals

#### Is RSSI Good for Rescue?

**YES, with caveats:**

**Advantages:**
- No infrastructure required
- Works in GPS-denied environments (inside buildings)
- Provides directional guidance (getting closer/farther)
- Better than random search
- Can differentiate between multiple survivors

**Disadvantages:**
- Not accurate for absolute distance
- Can be misleading in complex environments
- Requires multiple measurements (averaging)
- May lead rescuer in wrong direction temporarily

**Best Practices for Rescue Use:**
1. Use trend (increasing/decreasing) not absolute values
2. Average multiple measurements
3. Move slowly and observe RSSI changes
4. Use multiple rescuers to triangulate
5. Combine with other search techniques
6. In practice: RSSI-based search is significantly better than random search, especially in open areas

## Part 2: Proximity-Based Key Exchange

### Overview
Two devices in close proximity generate a shared cryptographic key by measuring RSSI fluctuations caused by hand-waving between them. Uses the principle of channel reciprocity.

### File
- `key_exchange.py` - Complete key exchange implementation

### How It Works

#### 1. Channel Reciprocity
When two devices exchange signals rapidly, the wireless channel characteristics (including interference patterns) are approximately the same in both directions. This is because:
- Electromagnetic reciprocity principle
- Time-division duplex (TDI) assumption
- Small time scale compared to channel coherence time

#### 2. Key Generation Process

**Phase 1: Role Determination (Automatic)**
- Both devices run the same program
- First device to start transmits "ready" frames
- Becomes the initiator
- Second device detects these frames
- Becomes the responder

**Phase 2: Frame Exchange**
- Initiator sends frame with index i
- Responder receives, measures RSSI, stores (index, RSSI)
- Responder immediately replies with same index
- Initiator measures RSSI of reply, stores (index, RSSI)
- Process repeats for n=300 frames
- Hand waving causes RSSI fluctuations

**Phase 3: Key Derivation**
Each device independently:
1. Calculates mean (μ) and standard deviation (σ) of RSSI values
2. For each measurement:
   - If RSSI > μ + z·σ: append bit '1'
   - If RSSI < μ - z·σ: append bit '0'
   - Otherwise: skip this index
3. Results in a bit string (the key)

**Phase 4: Reconciliation**
- Devices exchange lists of indices they used
- Keep only bits where both devices used that index
- Ensures keys are based on common measurements

**Phase 5: Verification**
- Each device computes SHA256 hash of its key
- Devices exchange hash commitments
- If hashes match, keys are identical
- No key bits are revealed in this process

### Usage

#### Setup (Both Devices)
```bash
sudo python3 key_exchange.py wlan0 6
```

#### Procedure
1. Start program on both devices (within 30 seconds)
2. Wait for role determination
3. When prompted, wave your hand between devices
4. Continue waving for ~15-20 seconds
5. Wait for key calculation and verification
6. Observe the results

### Parameter Selection

#### Standard Deviation Threshold (z)

**Recommended: z = 1.0 to 1.5**

**Reasoning:**
- **z = 0.5**: Too sensitive, includes too much noise, keys may not match
- **z = 1.0**: Good balance, ~32% of measurements used (outside ±1σ)
- **z = 1.5**: More conservative, ~13% of measurements used
- **z = 2.0**: Very conservative, only ~5% used, may not generate enough bits

**Trade-offs:**
- Lower z: More bits, but less reliable (more disagreement)
- Higher z: Fewer bits, but more reliable (better agreement)
- z = 1.0 is empirically tested to work well

#### Number of Frames (n)

**Recommended: n = 300**

**Reasoning:**
- With z = 1.0, expect ~100 usable measurements
- After reconciliation, expect ~50-70 common bits
- 50+ bits is sufficient for cryptographic purposes
- More frames = more reliable but slower

### Cryptographic Considerations

#### Key Length
For cryptographic use, a key should have:
- **Minimum**: 128 bits for AES encryption
- **Recommended**: 256 bits for strong security
- **This lab**: 50-70 bits typically generated

#### Extending to Secure Communication

To use this for long-term secure communication:

1. **Key Expansion**: Use a KDF (Key Derivation Function)
   ```
   Long_Key = HKDF(Short_Key, context_info)
   ```

2. **Generate Multiple Keys**: From one exchange, derive:
   - Encryption key
   - Authentication key
   - Session ID

3. **Freshness**: Include timestamps to prevent replay

4. **Multiple Rounds**: Repeat exchange to accumulate more bits

5. **Error Correction**: Use fuzzy extractors or error-correcting codes

### Security Analysis

#### Threat Model

**Secure Against:**
- **Passive Eavesdropper**: Cannot observe RSSI at victim's location
- **Distant Attacker**: Must be in immediate proximity
- **MITM (Partial)**: Attacker cannot inject frames with correct RSSI pattern

**Vulnerable To:**
- **Close Proximity Attacker**: If attacker is also within ~1m
- **Active Jamming**: Can disrupt key exchange
- **No Authentication**: Doesn't authenticate device identity

#### Why This Works

1. **Physical Layer Security**: Based on physical proximity
2. **Reciprocity**: Hard to replicate from a distance
3. **Randomness**: Hand motion provides unpredictability
4. **Temporal**: Must happen in real-time
5. **Location-Specific**: RSSI pattern is unique to that location

## Testing and Demonstration

### Part 1: Search and Rescue Video

**Scenario:**
1. Partner 1 (Survivor):
   - Start survivor.py on laptop
   - Hide in a location (different room, behind obstacles)
   - Leave laptop running

2. Partner 2 (Rescuer):
   - Start rescuer.py on laptop
   - Walk around searching
   - Observe RSSI increasing as you get closer
   - Follow the RSSI gradient to find survivor
   - Record the entire process

**Video Should Show:**
- Rescuer's screen with ncurses GUI
- RSSI values changing as rescuer moves
- Successful location of survivor
- Narration explaining the process

### Part 2: Key Exchange Demonstration

**Scenario:**
1. Place devices ~0.5m apart
2. Start program on both devices
3. Wait for role determination
4. Wave hand between devices vigorously
5. Continue for 15-20 seconds
6. Observe key generation and verification

**Evidence to Capture:**
- Terminal output from both devices showing:
  - Role determination
  - Frame exchange progress
  - RSSI statistics (mean, std dev)
  - Number of bits generated
  - Indices used
  - Key reconciliation
  - Hash comparison
  - Success/failure message

## Troubleshooting

### Monitor Mode Issues
```bash
# Check if adapter supports monitor mode
iw list | grep monitor

# Kill interfering processes
sudo airmon-ng check kill

# Restart NetworkManager after testing
sudo service NetworkManager restart
```

### Permission Denied
```bash
# Run with sudo
sudo python3 <script>.py ...

# Or add capabilities
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### No Packets Captured
- Verify monitor mode: `iwconfig wlan0`
- Check channel matches: `iw dev wlan0 info`
- Verify interface is up: `ip link show wlan0`
- Try different channel (less congested)

### Key Exchange Fails
- Ensure devices are close (~0.5m)
- Wave hand more vigorously
- Increase number of frames (n=500)
- Adjust z parameter (try z=0.8)
- Check both devices are on same channel

## Technical Details

### Dependencies
```bash
# Scapy - Packet manipulation
pip3 install scapy

# NumPy - Statistical calculations
pip3 install numpy

# Built-in: threading, curses, hashlib, subprocess
```

### Wi-Fi Channels
**2.4 GHz Band:**
- Channels 1-11 (US)
- Channels 1, 6, 11 are non-overlapping
- Recommended: Use channel 6 or 11

**5 GHz Band:**
- Many more channels available
- Less congestion
- May require regulatory domain setting

### Frame Types Used

**802.11 Management Frames (Type 0):**
- Subtype 4: Probe Request (used for "ready" frames)
- Subtype 8: Beacon (used for survivor beacons)

**802.11 Data Frames (Type 2):**
- Subtype 0: Data (used for key exchange)

## Academic Context

This lab demonstrates concepts from:
- **Wireless Security**: Physical layer security primitives
- **Cryptography**: Key exchange without pre-shared secrets
- **Networking**: 802.11 protocol, monitor mode, RSSI
- **Distributed Systems**: Automatic role negotiation
- **Signal Processing**: Using environmental measurements

### Related Research
- **Mathur et al. (2008)**: "Radio-telepathy: extracting a secret key from an unauthenticated wireless channel"
- **Dartmouth Patent**: US Patent for proximity-based device pairing
- **IEEE 802.11**: Wireless LAN standard

## Conclusion

This lab demonstrates practical applications of:
1. **RSSI-based localization**: Real-world search and rescue
2. **Physical layer security**: Key generation from wireless channel
3. **Wireless protocol design**: Custom frame structures
4. **System implementation**: Multi-threaded applications with real-time GUI

Both systems show how wireless signal characteristics can be leveraged for security and safety applications beyond traditional data communication.

## Authors
[Your names here]

## License
Educational use only - Dartmouth College

## Acknowledgments
- Dartmouth CS Department
- Scapy development team
- Wireless security research community
