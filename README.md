# 🕵️ Basic Network Sniffer (Python + Scapy)

A simple yet useful **network sniffer** written in Python with [Scapy](https://scapy.net).  
It captures live packets and displays key information: **time, size, src/dst IP & ports, protocol, DNS queries, and optional payload previews**.

---

## ✨ Features

- Capture packets from a chosen **interface** (`--iface`)
- Apply a **BPF filter** (`--filter`) like in Wireshark/tcpdump
- Limit capture to **N packets** or run unlimited (`--count`)
- Toggle **payload previews** (`--no-payload`)
- Save traffic to a **PCAP file** (`--pcap`)
- Print simple **statistics** at the end (`--stats`)

---

## 🚀 Installation

### 1) Clone the repository
```bash
git clone https://github.com/yourusername/network-sniffer.git
cd network-sniffer
```
### 2) Install Scapy
```bash
python3 -m pip install scapy
```
Note:
	- On macOS/Linux you must run the script with sudo to capture packets.
	- On Windows, install Npcap (WinPcap API compatible) and run the terminal as Administrator.

### Usage

Minimal (20 packets):
```bash
sudo python3 sniffer.py
```

Choose interface & filter:
```bash
sudo python3 sniffer.py -i en0 -f "tcp or udp"
```

Unlimited capture + stats:
```bash
sudo python3 sniffer.py -i en0 -f "not broadcast and not multicast" -c 0 --stats
```

Hide payloads (metadata only):
```bash
sudo python3 sniffer.py -i en0 --no-payload
```

📊 Example output:
```bash
15:52:20   90B TCP 192.168.0.127:50123 → 142.250.187.14:443  Payload: ....
15:52:21   72B UDP 192.168.0.127:54821 → 8.8.8.8:53  DNS? example.com
15:52:21   60B ICMP 192.168.0.127 → 192.168.0.1
```

With --stats:
```
📊 Stats
  Top src IP  192.168.0.127: 38 pkt
  Proto TCP: 28 pkt
  Proto UDP: 9 pkt
  Proto ICMP: 1 pkt
```

