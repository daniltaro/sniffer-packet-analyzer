# Sniffer Packet Analyzer
A network packet capture and analysis tool written in C++ using libpcap.
## Features

- 🔍 Captures packets from selected network interfaces
- 🎛 Supports TCP, UDP, ICMP protocols
- 💾 Saves captured packets to PCAP and statistics to JSON files
- 📡 Handles Ethernet and Loopback link types

## Installation
### Prerequisites

- CMake (version 3.30 or higher)
- libpcap - Packet capture library
- nlohmann_json - JSON library for C++

### Building the Project

1. Clone the repository:
```bash
git clone https://github.com/daniltaro/sniffer-packet-analyzer.git
cd sniffer-packet-analyzer
```

2. Create a build directory and compile:
```bash
mkdir build && cd build
cmake ..
make
```



## Usage

1. Run the program:
```bash
./Sniffer
```

2. Follow the prompts to:

- Select a network device (e.g., eth0, lo).
- Choose protocols to monitor (TCP, UDP, ICMP, or ALL).
- (Optional) Specify a PCAP file to save captured packets.
- (Optional) Specify a JSON file for general statistics.
- Specify a JSON file for detailed statistics (required).

3. Press s to stop capturing packets.

## Notes

- Ensure libpcap and nlohmann_json are installed.
- The detailed JSON statistics file is mandatory.
- Only Ethernet and Loopback link types are supported.
