# Detailed Installation Guide for Kali Linux VM

This guide provides step-by-step instructions for setting up the Wi-Fi Probe Request Sniffer on a Kali Linux virtual machine.

## 1. Prerequisites

- Kali Linux VM installed and running
- External USB Wi-Fi adapter that supports monitor mode
  - Recommended: Alfa AWUS036ACH, Panda PAU09, or TP-Link TL-WN722N (v1)
- User account with sudo privileges

## 2. Installation Steps

### Step 1: Update Kali Linux

Open a terminal and run:

```bash
sudo apt update
sudo apt upgrade -y
```

### Step 2: Create a Project Directory

```bash
mkdir -p ~/tools/wifi-probe-sniffer
cd ~/tools/wifi-probe-sniffer
```

### Step 3: Download the Project Files

Create each file in the project directory:

1. Create wifi_probe_sniffer.py:
   ```bash
   nano wifi_probe_sniffer.py
   ```
   Copy and paste the content from the wifi_probe_sniffer.py file.
   
2. Create requirements.txt:
   ```bash
   nano requirements.txt
   ```
   Copy and paste the content from the requirements.txt file.
   
3. Create setup_script.sh:
   ```bash
   nano setup_script.sh
   ```
   Copy and paste the content from the setup_script.sh file.
   
4. Make the setup script executable:
   ```bash
   chmod +x setup_script.sh
   ```

### Step 4: Run the Setup Script

```bash
sudo ./setup_script.sh
```

This will install all required dependencies.

## 3. Connecting Your Wi-Fi Adapter

### Step 3.1: Connect Your USB Wi-Fi Adapter

Connect your USB Wi-Fi adapter to your host machine and pass it through to the Kali VM.

- If using VirtualBox:
  1. Go to Devices → USB
  2. Select your Wi-Fi adapter from the list

- If using VMware:
  1. Go to VM → Removable Devices
  2. Find your Wi-Fi adapter
  3. Select Connect (Disconnect from Host)

### Step 3.2: Verify the Adapter is Recognized

```bash
iwconfig
```

You should see your wireless interface (often wlan0 or wlan1) listed.

### Step 3.3: Check if Monitor Mode is Supported

```bash
sudo airmon-ng
```

Your Wi-Fi adapter should be listed in the output.

## 4. Running the Wi-Fi Probe Request Sniffer

### Basic Usage

```bash
sudo python3 wifi_probe_sniffer.py -i wlan0
```

Replace `wlan0` with your wireless interface name if different.

### Saving Results to CSV

```bash
sudo python3 wifi_probe_sniffer.py -i wlan0 -o results.csv
```

### Using Vendor Lookup

```bash
sudo python3 wifi_probe_sniffer.py -i wlan0 -v
```

### Capture for a Specific Duration (5 minutes)

```bash
sudo python3 wifi_probe_sniffer.py -i wlan0 -d 300
```

## 5. Troubleshooting

### Issue: "Interface not found" Error

If you receive an error about the interface not being found:

1. Verify your interface name:
   ```bash
   iwconfig
   ```

2. Make sure the adapter is properly connected and recognized by the VM.

3. Try a different USB port.

### Issue: Monitor Mode Fails to Enable

If monitor mode doesn't enable properly:

1. Manually enable monitor mode:
   ```bash
   sudo airmon-ng check kill
   sudo airmon-ng start wlan0
   ```
   
2. Then use the created monitor interface (often wlan0mon):
   ```bash
   sudo python3 wifi_probe_sniffer.py -i wlan0mon
   ```

### Issue: Python Dependencies

If you encounter issues with Python dependencies:

```bash
pip3 install --upgrade scapy requests
```

## 6. GitHub Repository Setup

### Step 6.1: Initialize Git Repository

```bash
cd ~/tools/wifi-probe-sniffer
git init
```

### Step 6.2: Add Project Files

```bash
git add wifi_probe_sniffer.py requirements.txt setup_script.sh
```

### Step 6.3: Create README and LICENSE Files

Create README.md and LICENSE files with the provided content.

```bash
git add README.md LICENSE
```

### Step 6.4: Commit the Changes

```bash
git commit -m "Initial commit: Wi-Fi Probe Request Sniffer"
```

### Step 6.5: Connect to GitHub

1. Create a new repository on GitHub (https://github.com/new)
2. Connect your local repository to GitHub:

```bash
git remote add origin https://github.com/YOUR_USERNAME/wifi-probe-sniffer.git
git branch -M main
git push -u origin main
```

Replace `YOUR_USERNAME` with your actual GitHub username.

## 7. Legal Considerations

- Only use this tool on networks you own or have explicit permission to monitor.
- Be aware of privacy implications when capturing and storing wireless data.
- Different jurisdictions have different laws regarding wireless packet capturing.
