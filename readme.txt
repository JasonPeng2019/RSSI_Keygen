
RSSI-Based Key Generation - Complete Command Sequence
========================================================

PREREQUISITES:
- Two WiFi devices with monitor mode capability
- Root/sudo access on both devices
- Scapy installed: pip install scapy

STEP 1: Setup Monitor Mode
--------------------------
# Make airmon-ng script executable
chmod +x airmon-ng.sh

# Set up monitor mode on interface wlan0, channel 6
sudo ./airmon-ng.sh wlan0 6

# Verify monitor interface is active (should show wlan0mon)
sudo iwconfig

STEP 2: Device Discovery & Role Assignment
------------------------------------------
# On both devices (run simultaneously)
sudo python3 discovery.py

# This will:
# - Discover peer device via broadcast
# - Automatically assign INITIATOR/RESPONDER roles
# - Save role_config.json for subsequent steps

STEP 3: Frame Exchange & RSSI Measurement
------------------------------------------
# On both devices (run after role assignment)
sudo python3 frame_xc.py

# OR specify manually if needed:
# sudo python3 frame_xc.py --role INITIATOR --peer-mac aa:bb:cc:dd:ee:ff
# sudo python3 frame_xc.py --role RESPONDER --peer-mac aa:bb:cc:dd:ee:ff

# This will:
# - Exchange 300 frames between devices
# - Measure RSSI for each received frame
# - Save results to rssi_measurements.json and rssi_measurements.txt

STEP 4: Key Generation from RSSI Measurements
----------------------------------------------
# On both devices (analyze threshold impact - optional)
python3 calc_key.py --input rssi_measurements.json --analyze

# Generate key with chosen z-threshold (recommended: 1.0)
python3 calc_key.py --input rssi_measurements.json --z 1.0 --output key_data.json

# This will:
# - Apply statistical thresholding to RSSI values
# - Generate binary key (1s and 0s)
# - Save key_data.json and key_data_indices.json/txt
# - Show key quality assessment

STEP 5: Bit Reconciliation
---------------------------
# On both devices (run after key generation)
sudo python3 reconcile_bits.py --peer-mac aa:bb:cc:dd:ee:ff --key-data key_data.json

# This will:
# - Perform handshake with random backoff
# - Exchange key bits using reliable CRC-protected packets
# - Find common indices with matching bit values
# - Generate reconciled key with only common bits
# - Save key_data_reconciled.json

STEP 6: Key Verification
------------------------
# On both devices (run after reconciliation)
sudo python3 check_bits.py --reconciled-key key_data_reconciled.json

# This will:
# - Listen/talk protocol to establish communication
# - Exchange CRC checksums of reconciled keys
# - Verify both devices have identical keys
# - Save verification result to key_data_reconciled_verified.json

FINAL OUTPUT FILES:
===================
- rssi_measurements.json: Raw RSSI measurements
- key_data.json: Generated key with statistics
- key_data_indices.txt: Key bits used (index,bit_value format)
- key_data_reconciled.json: Reconciled key (common bits only)
- key_data_reconciled_verified.json: Final verified key

TROUBLESHOOTING:
================
- Ensure both devices are on same WiFi channel
- Check monitor mode is active: iwconfig
- Verify peer MAC addresses are correct
- Run with --help on any script for options
- Check file permissions for JSON files

EXAMPLE SUCCESSFUL RUN:
=======================
Device A: INITIATOR role, 45 key bits → 35 reconciled bits → VERIFIED
Device B: RESPONDER role, 42 key bits → 35 reconciled bits → VERIFIED
Final key length: 35 bits (identical on both devices)

