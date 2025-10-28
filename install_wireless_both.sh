#!/bin/bash

#Tim Pierson, Dartmouth CS60, Fall 2025
#update TP-Link drivers to put realtek wi-fi dongles into monitor mode
#instructions from: https://github.com/aircrack-ng/rtl8188eus   (802.11n)
#         and from: https://github.com/lwfinger/rtw88           (802.11ac)

#should be run as sudo
if (( $EUID != 0 )); then
    echo "This script must be run with sudo."
    exit 1
fi
#change directory to home and make folder for drivers
cd $HOME
mkdir wlansetup
cd wlansetup

#download drivers from git for older 802.11n adapter
git clone https://github.com/aircrack-ng/rtl8188eus.git
cd rtl8188eus
make
make install
echo 'blacklist r8188eu' | sudo tee -a '/etc/modprobe.d/realtek.conf'
#$echo 'blacklist rtl8xxxu' | sudo tee -a '/etc/modprobe.d/realtek.conf'


#download drivers from git for newer 802.11ac adapter
cd $HOME
cd wlansetup
git clone https://github.com/lwfinger/rtw88
cd rtw88
make
make install
make install_fw
cp rtw88.conf /etc/modprobe.d/




#reboot to save changes
read -n 1 -s -r -p "Press any key to reboot..."
reboot