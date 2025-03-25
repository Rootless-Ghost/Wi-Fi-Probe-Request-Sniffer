# Wi-Fi Probe Request Sniffer

A Python tool for capturing and analyzing Wi-Fi probe requests from nearby devices.


[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet_Manipulation-E10098)](https://scapy.net/)
[![Linux](https://img.shields.io/badge/Linux-Compatible-333333?logo=linux&logoColor=white)](https://www.linux.org/)
[![Monitor Mode](https://img.shields.io/badge/Monitor_Mode-Enabled-4CAF50)](https://en.wikipedia.org/wiki/Monitor_mode)
[![Aircrack-ng](https://img.shields.io/badge/Aircrack--ng-Wireless_Tools-F44336)](https://www.aircrack-ng.org/)
[![802.11](https://img.shields.io/badge/802.11-Wi--Fi_Protocol-2196F3)](https://en.wikipedia.org/wiki/IEEE_802.11)
[![MAC Lookup](https://img.shields.io/badge/MAC-Vendor_Lookup-9C27B0)](https://macvendors.com/)
[![Data Export](https://img.shields.io/badge/Export-CSV%7CJSON-FF9800)](https://en.wikipedia.org/wiki/Comma-separated_values)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Compatible-1A1A1A?logo=kali-linux&logoColor=white)](https://www.kali.org/)


## Overview

When wireless devices search for networks, they broadcast probe request frames containing information about previously connected networks. This tool captures these frames, extracts valuable data (SSIDs, MAC addresses), and displays/logs this information in real-time.

## Features

- Captures and analyzes wireless probe request frames
- Extracts network names (SSIDs) from these probe requests
- Identifies and logs device MAC addresses
- Displays real-time detection information in the terminal
- Runs on Linux systems with monitor-mode capable wireless adapters
- Deduplicates repeated requests from the same device
- Saves data to CSV or JSON format
- MAC address vendor lookup functionality

## Requirements

### System Requirements

- Linux system (Ubuntu, Kali, etc.)
- A wireless adapter that supports monitor mode
- Administrative privileges (sudo access)

### Python Requirements

- Python 3.x
- Scapy library
- Requests library (for vendor lookup)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/wifi-probe-sniffer.git
   cd wifi-probe-sniffer
   ```

2. Install the required packages:
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3-pip aircrack-ng
   pip3 install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
sudo python3 wifi_probe_sniffer.py -i wlan0
```

### Command Line Options

- `-i, --interface`: Wireless interface to use (must support monitor mode) [required]
- `-o, --output`: Output file to save results
- `-f, --format`: Output format (csv or json) [default: csv]
- `-d, --duration`: Capture duration in seconds
- `-v, --vendor-lookup`: Enable MAC address vendor lookup
- `-a, --all`: Capture all probe requests (including empty SSIDs)

### Examples

1. **Basic capture** - Show all probe requests on interface wlan0:
   ```bash
   sudo python3 wifi_probe_sniffer.py -i wlan0
   ```

2. **Save results to CSV file**:
   ```bash
   sudo python3 wifi_probe_sniffer.py -i wlan0 -o probe_data.csv
   ```

3. **Save results to JSON with vendor lookup**:
   ```bash
   sudo python3 wifi_probe_sniffer.py -i wlan0 -o probe_data.json -f json -v
   ```

4. **Capture for specific duration (5 minutes)**:
   ```bash
   sudo python3 wifi_probe_sniffer.py -i wlan0 -d 300
   ```

5. **Capture all probe requests (including empty SSIDs)**:
   ```bash
   sudo python3 wifi_probe_sniffer.py -i wlan0 -a
   ```

## Output Format

### Console Output

```
[2025-03-25 12:34:56] MAC: aa:bb:cc:dd:ee:ff | SSID: "Home_Network" | RSSI: -65 dBm | Vendor: Samsung Electronics
```

### CSV Format

```
mac_address,first_seen,last_seen,ssids,vendor,rssi
aa:bb:cc:dd:ee:ff,2025-03-25 12:34:56,2025-03-25 12:35:12,Home_Network,Samsung Electronics,-65
```

### JSON Format

```json
{
    "aa:bb:cc:dd:ee:ff": {
        "first_seen": "2025-03-25 12:34:56",
        "last_seen": "2025-03-25 12:35:12",
        "ssids": [
            "Home_Network"
        ],
        "vendor": "Samsung Electronics",
        "rssi": -65
    }
}
```

## Technical Notes

1. **Monitor Mode**: This tool requires your wireless adapter to be in monitor mode, which will be automatically enabled and disabled when you run the script.

2. **MAC Vendor Lookup**: The vendor lookup feature uses the macvendors.com API, which has rate limits. For extensive scanning, consider downloading an OUI database file.

3. **Compatible Adapters**: Not all wireless adapters support monitor mode. Popular compatible adapters include those with Atheros AR9271 and Realtek RTL8812AU chipsets.

## Legal and Privacy Considerations

- Capturing wireless traffic may be subject to legal restrictions in some jurisdictions. Only use this tool on networks you own or have permission to monitor.
- This tool captures MAC addresses which can potentially be used to track individuals. Consider anonymizing this data for ethical use.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
