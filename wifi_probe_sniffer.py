#!/usr/bin/env python3
"""
Wi-Fi Probe Request Sniffer

This script captures and analyzes Wi-Fi probe requests from nearby devices.
It extracts SSID names, MAC addresses, and provides real-time logging of detected probe requests.

Requirements:
- Linux system with Wi-Fi card supporting monitor mode
- Python 3.6+
- Scapy
- Requests (for MAC vendor lookup)

Usage:
    sudo python3 wifi_probe_sniffer.py -i <interface> [options]
"""

import argparse
import csv
import json
import os
import signal
import sys
import time
from datetime import datetime
from typing import Dict, List, Set, Tuple

try:
    from scapy.all import Dot11, Dot11ProbeReq, RadioTap, sniff
    import requests
except ImportError:
    print("Required packages not found. Please install dependencies:")
    print("pip install scapy requests")
    sys.exit(1)

# Global variables
seen_macs: Dict[str, float] = {}  # MAC addresses and their last seen timestamp
detected_probes: List[Dict] = []   # List to store all detected probe requests
running = True                     # Flag to control sniffing loop

class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Wi-Fi Probe Request Sniffer')
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface to use (must be in monitor mode)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Time in seconds to consider a duplicate (default: 5)')
    parser.add_argument('-o', '--output', help='Output file to save results (CSV or JSON based on extension)')
    parser.add_argument('-v', '--vendor', action='store_true', help='Lookup MAC vendor information')
    parser.add_argument('-f', '--filter', action='store_true', help='Filter out duplicate probe requests')
    return parser.parse_args()

def signal_handler(sig, frame):
    """Handle keyboard interrupts to gracefully exit the program."""
    global running
    print(f"\n{Colors.YELLOW}[!] Stopping packet capture...{Colors.END}")
    running = False

def check_monitor_mode(interface: str) -> bool:
    """Check if the specified interface is in monitor mode."""
    try:
        with open(f"/sys/class/net/{interface}/type", 'r') as f:
            if f.read().strip() == '803':  # 803 is the type for monitor mode
                return True
        return False
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Interface {interface} not found{Colors.END}")
        return False

def lookup_vendor(mac_address: str) -> str:
    """Look up the vendor of a MAC address using macvendors.com API."""
    try:
        # Format MAC address to match API requirements (first 6 characters)
        mac_prefix = mac_address.replace(':', '').upper()[:6]
        response = requests.get(f"https://api.macvendors.com/{mac_prefix}", timeout=2)
        
        if response.status_code == 200:
            return response.text
        return "Unknown"
    except Exception:
        return "Lookup failed"

def process_packet(packet) -> Tuple[bool, Dict]:
    """Process a packet and extract probe request information."""
    if packet.haslayer(Dot11ProbeReq):
        # Extract MAC address
        mac_address = packet.addr2
        if not mac_address:
            return False, {}
        
        # Extract timestamp
        timestamp = time.time()
        
        # Extract SSID from the probe request
        ssid = ""
        if packet.haslayer(Dot11):
            if packet[Dot11].info:
                ssid = packet[Dot11].info.decode('utf-8', errors='replace')
        
        # Get signal strength if available
        rssi = None
        if packet.haslayer(RadioTap):
            if hasattr(packet[RadioTap], 'dBm_AntSignal'):
                rssi = packet[RadioTap].dBm_AntSignal
        
        # Create a record of the probe request
        probe_data = {
            'timestamp': timestamp,
            'datetime': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            'mac_address': mac_address,
            'ssid': ssid,
            'rssi': rssi
        }
        
        return True, probe_data
    
    return False, {}

def packet_handler(packet, args):
    """Handle captured packets and display/store probe request information."""
    global seen_macs, detected_probes
    
    success, probe_data = process_packet(packet)
    if not success:
        return
    
    mac_address = probe_data['mac_address']
    ssid = probe_data['ssid']
    timestamp = probe_data['timestamp']
    
    # Skip duplicate check if filtering is disabled
    if not args.filter or mac_address not in seen_macs or (timestamp - seen_macs[mac_address]) > args.timeout:
        seen_macs[mac_address] = timestamp
        
        # Look up vendor if requested
        if args.vendor:
            probe_data['vendor'] = lookup_vendor(mac_address)
        
        # Store the detected probe
        detected_probes.append(probe_data)
        
        # Print to console
        if args.vendor and 'vendor' in probe_data:
            print(f"{Colors.GREEN}[+] {probe_data['datetime']} {Colors.BLUE}{mac_address}{Colors.END} "
                  f"({Colors.YELLOW}{probe_data['vendor']}{Colors.END}) "
                  f"searching for: {Colors.BOLD}{ssid or '<Broadcast>'}{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] {probe_data['datetime']} {Colors.BLUE}{mac_address}{Colors.END} "
                  f"searching for: {Colors.BOLD}{ssid or '<Broadcast>'}{Colors.END}")

def save_results(output_file: str, data: List[Dict]):
    """Save detected probe requests to a file (CSV or JSON)."""
    if not data:
        print(f"{Colors.YELLOW}[!] No data to save{Colors.END}")
        return
    
    file_ext = os.path.splitext(output_file)[1].lower()
    
    try:
        if file_ext == '.json':
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=4)
        elif file_ext == '.csv':
            with open(output_file, 'w', newline='') as f:
                # Determine all possible fields from the data
                fieldnames = set()
                for entry in data:
                    fieldnames.update(entry.keys())
                
                writer = csv.DictWriter(f, fieldnames=list(fieldnames))
                writer.writeheader()
                writer.writerows(data)
        else:
            print(f"{Colors.RED}[!] Unsupported file format. Use .csv or .json{Colors.END}")
            return
        
        print(f"{Colors.GREEN}[+] Results saved to {output_file}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving results: {e}{Colors.END}")

def main():
    """Main function to capture and process probe requests."""
    global running
    
    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Check if interface exists and is in monitor mode
    if not check_monitor_mode(args.interface):
        print(f"{Colors.RED}[!] Interface {args.interface} is not in monitor mode or doesn't exist{Colors.END}")
        print(f"{Colors.YELLOW}[i] Use 'sudo airmon-ng start {args.interface}' to enable monitor mode{Colors.END}")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[+] Starting Wi-Fi probe request sniffer on {args.interface}{Colors.END}")
    print(f"{Colors.YELLOW}[i] Press Ctrl+C to stop{Colors.END}")
    
    try:
        # Start packet sniffing
        sniff(
            iface=args.interface,
            prn=lambda packet: packet_handler(packet, args),
            store=0,
            stop_filter=lambda _: not running
        )
    except Exception as e:
        print(f"{Colors.RED}[!] Error during packet capture: {e}{Colors.END}")
    
    # Save results if an output file was specified
    if args.output and detected_probes:
        save_results(args.output, detected_probes)
    
    print(f"{Colors.GREEN}[+] Captured {len(detected_probes)} unique probe requests{Colors.END}")

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{Colors.RED}[!] This script must be run as root (sudo){Colors.END}")
        sys.exit(1)
    
    main()
