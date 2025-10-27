
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <interface> <channel>"
    echo "Example: $0 wlan0 6"
    exit 1
fi

INTERFACE=$1
CHANNEL=$2

echo "Setting $INTERFACE to monitor mode on channel $CHANNEL..."

sudo ip link set $INTERFACE down

sudo iwconfig $INTERFACE mode monitor

sudo ip link set $INTERFACE up

sudo iwconfig $INTERFACE channel $CHANNEL

echo ""
echo "Configuration complete. Current status:"
echo "========================================"

iwconfig $INTERFACE

echo ""
echo "========================================"
echo "Verify that Mode is 'Monitor' and the channel is $CHANNEL"
```
