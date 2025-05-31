# Network Packet Analyzer

A simple and user-friendly network packet analyzer tool that captures and displays network traffic information. This tool is designed for educational purposes to help understand network protocols and packet structures.

## 🌟 Features

- Real-time packet capture
- Displays source and destination IP addresses
- Shows protocol information (TCP, UDP, ICMP)
- Displays port numbers for TCP and UDP packets
- Timestamp for each captured packet
- Emoji-based output for better readability
- Simple and easy to use interface

## 📋 Requirements

- Python 3.6 or higher
- Npcap (for Windows) or libpcap (for Linux)
- Required Python packages:
  - scapy
  - colorama

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/mdzaid-alam/network-packet-analyzer.git
cd network-packet-analyzer
```

2. Install Npcap (Windows) or libpcap (Linux):
   - Windows: Download and install from [Npcap](https://npcap.com/#download)
   - Linux: `sudo apt-get install libpcap-dev` (Ubuntu/Debian)
   - Mac: `brew install libpcap` (using Homebrew)

3. Install Python requirements:
```bash
pip install -r requirements.txt
```

## 💻 Usage

1. Run the script with administrator/root privileges:
```bash
# Windows (Run PowerShell as Administrator):
python network.py

# Linux/Mac:
sudo python3 network.py
```

2. The program will capture and display network packets
3. Press Ctrl+C to stop the capture

## 📊 Output Example

```
🔍 Starting Basic Network Packet Analyzer...
Capturing 1 packet only...

📦 New Packet Captured
⏰ Time: 2024-03-14 15:30:45
➡️ Source IP: 192.168.1.***
⬅️ Destination IP: 8.8.*.*
📡 Protocol: 6
🔌 Source Port: 543*1
🔌 Destination Port: 80
==================================================
```

## ⚠️ Important Notes

- This tool should only be used for educational purposes
- Only use on networks you own or have permission to analyze
- Running packet sniffers without permission may be illegal
- Some antivirus software might flag this tool as suspicious

## 🔧 Troubleshooting

### Common Issues:

1. "No libpcap provider available" error:
   - Make sure Npcap is installed (Windows)
   - Restart your computer after installing Npcap
   - Run the script as administrator

2. "Permission denied" error:
   - Make sure you're running the script as administrator/root
   - Check if your antivirus is blocking the script

3. No packets being captured:
   - Check if your network interface is active
   - Try selecting a different network interface
   - Ensure you have network traffic

## ⚠️ Disclaimer

This tool is for educational purposes only. The user is responsible for ensuring they have permission to monitor the network they are analyzing. The author is not responsible for any misuse of this tool. 
