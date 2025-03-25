#!/usr/bin/env python3
"""
Wi-Fi Probe Request Sniffer

A tool for capturing and analyzing Wi-Fi probe requests from nearby devices.
"""

import argparse
import csv
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.all import (
        Dot11, Dot11ProbeReq, Dot11Elt, 
        RadioTap, sniff, conf
    )
except ImportError:
    print("Error: Scapy library not found. Please install it using: pip install scapy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("probe_sniffer")

# Global variables
detected_devices = {}  # Store MAC addresses and their probe requests
should_stop = False    # Signal handler flag


class ProbeRequestSniffer:
    """Main class for capturing and processing Wi-Fi probe requests."""

    def __init__(self, interface: str, output_file: Optional[str] = None,
                 output_format: str = "csv", vendor_lookup: bool = False,
                 capture_duration: Optional[int] = None) -> None:
        """
        Initialize the probe request sniffer.
        
        Args:
            interface: Wireless interface to use (must support monitor mode)
            output_file: Optional file to save results
            output_format: Format for saving results (csv or json)
            vendor_lookup: Whether to perform MAC vendor lookups
            capture_duration: How long to capture (in seconds, None for indefinite)
        """
        self.interface = interface
        self.output_file = output_file
        self.output_format = output_format
        self.vendor_lookup = vendor_lookup
        self.capture_duration = capture_duration
        self.mac_vendors = {}  # Cache for MAC vendor lookups
        self.unique_macs = set()  # For deduplication
        self.capture_all = False  # Default to not capturing empty SSIDs
        
        # Validate parameters
        if output_format not in ["csv", "json"]:
            raise ValueError("Output format must be 'csv' or 'json'")
            
        if self.vendor_lookup:
            try:
                import requests
                self.requests = requests
            except ImportError:
                logger.warning("Requests library not installed. Vendor lookup disabled.")
                self.vendor_lookup = False

    def enable_monitor_mode(self) -> bool:
        """
        Put the wireless interface into monitor mode.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if interface exists
            if self.interface not in conf.ifaces:
                logger.error(f"Interface {self.interface} not found")
                return False
                
            # Use airmon-ng to enable monitor mode (system call approach)
            logger.info(f"Enabling monitor mode on {self.interface}")
            os.system(f"sudo airmon-ng start {self.interface}")
            
            # Alternative: use iwconfig directly if airmon-ng is not available
            # os.system(f"sudo ifconfig {self.interface} down")
            # os.system(f"sudo iwconfig {self.interface} mode monitor")
            # os.system(f"sudo ifconfig {self.interface} up")
            
            # Verify monitor mode is enabled (implementation specific)
            # This is a simplified check and may need adaptation
            time.sleep(1)  # Give the system time to apply changes
            return True
        except Exception as e:
            logger.error(f"Failed to enable monitor mode: {e}")
            return False

    def disable_monitor_mode(self) -> None:
        """Disable monitor mode and restore the interface to managed mode."""
        try:
            logger.info(f"Disabling monitor mode on {self.interface}")
            os.system(f"sudo airmon-ng stop {self.interface}")
            # Alternative: use iwconfig directly
            # os.system(f"sudo ifconfig {self.interface} down")
            # os.system(f"sudo iwconfig {self.interface} mode managed")
            # os.system(f"sudo ifconfig {self.interface} up")
        except Exception as e:
            logger.error(f"Error disabling monitor mode: {e}")

    def lookup_vendor(self, mac_address: str) -> str:
        """
        Look up the vendor of a MAC address.
        
        Args:
            mac_address: MAC address to look up
            
        Returns:
            str: Vendor name or "Unknown"
        """
        if not self.vendor_lookup:
            return "Vendor lookup disabled"
            
        # Check cache first
        if mac_address in self.mac_vendors:
            return self.mac_vendors[mac_address]
            
        # Format MAC address (first 3 bytes/6 chars are the OUI)
        oui = mac_address.replace(':', '').upper()[:6]
        
        try:
            # API-based lookup with rate limiting
            url = f"https://api.macvendors.com/{mac_address}"
            response = self.requests.get(url, timeout=2)
            
            if response.status_code == 200:
                vendor = response.text
                self.mac_vendors[mac_address] = vendor
                return vendor
            elif response.status_code == 429:  # Rate limited
                logger.warning("Rate limited by MAC vendor API")
                time.sleep(1)  # Respect rate limiting
                return "Rate limited"
            else:
                # Unknown vendor
                self.mac_vendors[mac_address] = "Unknown"
                return "Unknown"
        except Exception as e:
            logger.debug(f"Vendor lookup failed: {e}")
            return "Lookup failed"

    def process_packet(self, packet) -> None:
        """
        Process a captured packet and extract probe request information.
        
        Args:
            packet: Scapy packet object
        """
        if not packet.haslayer(Dot11ProbeReq):
            return
            
        # Extract MAC address (source)
        mac_address = packet[Dot11].addr2
        if not mac_address:
            return
            
        # Normalize MAC address format
        mac_address = mac_address.lower()
        
        # Extract SSID (if present)
        ssid = ""
        if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='replace')
        
        # Skip empty SSIDs (some devices send these when scanning)
        if not ssid and not self.capture_all:
            return
            
        # Signal strength (RSSI)
        rssi = None
        if packet.haslayer(RadioTap):
            rssi = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else None
        
        # Timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get vendor information if enabled
        vendor = self.lookup_vendor(mac_address) if self.vendor_lookup else "N/A"
        
        # Store information (deduplication with update)
        if mac_address not in detected_devices:
            detected_devices[mac_address] = {
                'first_seen': timestamp,
                'last_seen': timestamp,
                'ssids': set(),
                'vendor': vendor,
                'rssi': rssi
            }
        else:
            detected_devices[mac_address]['last_seen'] = timestamp
            if rssi is not None:
                detected_devices[mac_address]['rssi'] = rssi
        
        # Add SSID to the set (automatically deduplicates)
        if ssid:
            detected_devices[mac_address]['ssids'].add(ssid)
            
        # Only display/log if this is a new MAC or new SSID
        is_new = False
        mac_ssid_pair = (mac_address, ssid)
        if mac_ssid_pair not in self.unique_macs:
            self.unique_macs.add(mac_ssid_pair)
            is_new = True
            
        if is_new:
            # Print to console
            ssid_str = f'"{ssid}"' if ssid else "[No SSID]"
            rssi_str = f"{rssi} dBm" if rssi is not None else "N/A"
            print(f"[{timestamp}] MAC: {mac_address} | SSID: {ssid_str} | RSSI: {rssi_str} | Vendor: {vendor}")

    def start_capture(self) -> None:
        """Start capturing probe requests."""
        global should_stop
        
        # Setup signal handler for clean exit
        def signal_handler(sig, frame):
            global should_stop
            logger.info("Stopping capture...")
            should_stop = True
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        logger.info(f"Starting capture on interface {self.interface}")
        logger.info("Press Ctrl+C to stop")
        
        # Setup capture filter
        capture_filter = "type mgt subtype probe-req"
        
        # Start time
        start_time = time.time()
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                filter=capture_filter,
                store=0,  # Don't store packets in memory
                stop_filter=lambda _: should_stop,
                timeout=self.capture_duration
            )
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
        finally:
            end_time = time.time()
            duration = int(end_time - start_time)
            
            logger.info(f"Capture complete. Duration: {duration} seconds")
            logger.info(f"Detected {len(detected_devices)} unique devices")
            
            # Save results if output file specified
            if self.output_file:
                self.save_results()

    def save_results(self) -> None:
        """Save captured data to file in specified format."""
        if not self.output_file:
            return
            
        try:
            if self.output_format == "csv":
                self._save_csv()
            else:  # JSON
                self._save_json()
                
            logger.info(f"Results saved to {self.output_file}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")

    def _save_csv(self) -> None:
        """Save results in CSV format."""
        with open(self.output_file, 'w', newline='') as csvfile:
            fieldnames = ['mac_address', 'first_seen', 'last_seen', 
                         'ssids', 'vendor', 'rssi']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for mac, data in detected_devices.items():
                writer.writerow({
                    'mac_address': mac,
                    'first_seen': data['first_seen'],
                    'last_seen': data['last_seen'],
                    'ssids': ', '.join(data['ssids']),
                    'vendor': data['vendor'],
                    'rssi': data['rssi'] if data['rssi'] is not None else 'N/A'
                })

    def _save_json(self) -> None:
        """Save results in JSON format."""
        # Convert sets to lists for JSON serialization
        json_data = {}
        for mac, data in detected_devices.items():
            json_data[mac] = {
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'ssids': list(data['ssids']),
                'vendor': data['vendor'],
                'rssi': data['rssi']
            }
            
        with open(self.output_file, 'w') as jsonfile:
            json.dump(json_data, jsonfile, indent=4)


def main():
    """Main entry point for the program."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Wi-Fi Probe Request Sniffer")
    
    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface to use (must support monitor mode)")
    parser.add_argument("-o", "--output", 
                        help="Output file to save results")
    parser.add_argument("-f", "--format", choices=["csv", "json"], default="csv",
                        help="Output format (csv or json)")
    parser.add_argument("-d", "--duration", type=int,
                        help="Capture duration in seconds")
    parser.add_argument("-v", "--vendor-lookup", action="store_true",
                        help="Enable MAC address vendor lookup")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Capture all probe requests (including empty SSIDs)")
    
    args = parser.parse_args()
    
    # Create and start sniffer
    try:
        sniffer = ProbeRequestSniffer(
            interface=args.interface,
            output_file=args.output,
            output_format=args.format,
            vendor_lookup=args.vendor_lookup,
            capture_duration=args.duration
        )
        
        # Pass the capture_all parameter
        sniffer.capture_all = args.all
        
        # Enable monitor mode
        if not sniffer.enable_monitor_mode():
            logger.error("Failed to enable monitor mode. Exiting.")
            return 1
            
        # Start capturing
        sniffer.start_capture()
        
        # Disable monitor mode when done
        sniffer.disable_monitor_mode()
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        if 'sniffer' in locals():
            sniffer.disable_monitor_mode()
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
