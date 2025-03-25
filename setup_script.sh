#!/bin/bash
# Setup script for Wi-Fi Probe Request Sniffer
# This script installs all required dependencies on a Kali Linux system

set -e  # Exit on error

echo "[+] Setting up Wi-Fi Probe Request Sniffer..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
  echo "[-] Please run this script as root"
  exit 1
fi

# Update package list
echo "[+] Updating package list..."
apt-get update

# Install required packages
echo "[+] Installing required system packages..."
apt-get install -y python3 python3-pip aircrack-ng git

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip3 install scapy requests

# Make the main script executable
chmod +x wifi_probe_sniffer.py

echo "[+] Setup complete!"
echo "[+] You can now run the tool using: sudo python3 wifi_probe_sniffer.py -i <interface>"
echo "[+] Example: sudo python3 wifi_probe_sniffer.py -i wlan0"
