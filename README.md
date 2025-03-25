# Wi-Fi Probe Request Sniffer

A Python script for capturing and analyzing Wi-Fi probe requests from nearby devices. This tool allows security researchers and network administrators to monitor devices that are actively searching for Wi-Fi networks in the vicinity.

## Features

- Captures probe requests from nearby wireless devices
- Extracts SSID names being searched for
- Identifies MAC addresses of probing devices
- Provides real-time logging of detected probe requests
- Filters out duplicate probe requests (optional)
- Looks up vendor information for MAC addresses (optional)
- Saves logs to CSV or JSON files

## Requirements

- Linux system with a Wi-Fi card that supports monitor mode
- Python 3.6+
- Root privileges (needed for packet capture)
- Required Python packages:
  - Scapy
  - Requests (for vendor lookup)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/your-username/wifi-probe-sniffer.git
   cd wifi-probe-sniffer
   ```

2. Install the required Python packages:
   ```
   pip install scapy requests
   ```

3. Make the script executable:
   ```
   chmod +x wifi_probe_sniffer.py
   ```

## Usage

Before running the script, you need to put your wireless interface into monitor mode. You can use airmon-ng for this:

```
sudo airmon-ng start <interface>
```

This will create a monitor mode interface (usually named `wlan0mon` or similar).

Then run the script with:

```
sudo python3 wifi_probe_sniffer.py -i <monitor_interface> [options]
```

### Command Line Options

- `-i, --interface`: Wireless interface to use (must be in monitor mode) [required]
- `-t, --timeout`: Time in seconds to consider a duplicate (default: 5)
- `-o, --output`: Output file to save results (CSV or JSON based on extension)
- `-v, --vendor`: Lookup MAC vendor information
- `-f, --filter`: Filter out duplicate probe requests

### Examples

Capture probe requests on interface wlan0mon:
```
sudo python3 wifi_probe_sniffer.py -i wlan0mon
```

Capture probe requests with vendor information and save to JSON:
```
sudo python3 wifi_probe_sniffer.py -i wlan0mon -v -o results.json
```

Capture probe requests, filter duplicates, and save to CSV:
```
sudo python3 wifi_probe_sniffer.py -i wlan0mon -f -o results.csv
```

## Sample Output

```
[+] 2025-03-25 14:23:45 AA:BB:CC:DD:EE:FF (Apple, Inc.) searching for: HomeWiFi
[+] 2025-03-25 14:23:47 11:22:33:44:55:66 (Samsung Electronics Co.,Ltd) searching for: <Broadcast>
[+] 2025-03-25 14:23:50 AA:BB:CC:11:22:33 (Intel Corporate) searching for: PublicWiFi
```

## Important Notes

- This tool is meant for educational and security research purposes only
- Be mindful of privacy concerns when capturing network traffic
- Always obtain proper authorization before monitoring networks you don't own

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and legitimate security research purposes only. The author is not responsible for any misuse or damage caused by this program. Use responsibly and ethically.
