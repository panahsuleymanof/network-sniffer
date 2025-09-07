# 🕵️ Basic Network Sniffer (Python + Scapy)

A simple yet useful **network sniffer** written in Python with [Scapy](https://scapy.net).  
It captures live packets and displays key information: **time, size, src/dst IP & ports, protocol, DNS queries, and optional payload previews**.

---

## ✨ Features

This sniffer supports the following options:

- `-i, --iface` → capture from a specific interface (e.g., `en0`, `wlan0`, `eth0`)
- `-f, --filter` → apply a BPF filter (e.g., `"tcp or udp"`, `"port 53"`)
- `-c, --count` → number of packets to capture (`0` = unlimited)
- `--no-payload` → hide payload previews
- `--pcap FILE` → save captured packets into a PCAP file
- `--stats` → print simple statistics (top source IPs & protocol counts) at the end

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

### 3) Usage

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

