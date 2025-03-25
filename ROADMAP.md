# Wi-Fi Probe Request Sniffer Roadmap

This document outlines the planned features and improvements for future releases.

## Short-term Goals (v1.1.0)

- [ ] Add channel hopping to scan across multiple Wi-Fi channels
- [ ] Implement MAC address filtering (whitelist/blacklist)
- [ ] Add geolocation support for logging
- [ ] Improve signal strength visualization
- [ ] Add basic statistics (devices per network, common SSIDs)

## Medium-term Goals (v1.2.0 - v1.3.0)

- [ ] Create a basic web interface for real-time monitoring
- [ ] Implement device fingerprinting based on probe request patterns
- [ ] Add SQLite database storage option
- [ ] Develop heatmap generation for signal strength
- [ ] Add support for GPS integration (for wardriving)
- [ ] Implement PCAP file export/import

## Long-term Goals (v2.0.0+)

- [ ] Develop a full GUI application
- [ ] Add machine learning for device type identification
- [ ] Implement distributed sensor support
- [ ] Create visualization tools for network relationships
- [ ] Add timeline view for historical data
- [ ] Develop API for integration with other security tools

## Completed

- [x] Initial release with core functionality (v1.0.0)
- [x] Real-time terminal output
- [x] MAC vendor lookup
- [x] Data export in CSV and JSON formats
- [x] Configurable duplicate filtering
