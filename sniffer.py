import argparse
from datetime import datetime
from collections import Counter
from scapy.all import sniff, Ether, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw

stats_ip = Counter()
stats_proto = Counter()
captured = []

def payload_preview(pkt, limit=60):
    if Raw not in pkt or not pkt[Raw].load:
        return ""
    raw = pkt[Raw].load
    try:
        txt = raw.decode(errors="ignore")
    except Exception:
        txt = str(raw)
    txt = txt.replace("\r", "\\r").replace("\n", "\\n")
    return txt[:limit] + ("…" if len(txt) > limit else "")

def describe(pkt, show_payload=True):
    ts = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S")
    length = len(pkt)

    mac_src = mac_dst = None
    if Ether in pkt:
        mac_src, mac_dst = pkt[Ether].src, pkt[Ether].dst

    src = dst = None
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst

    proto, sport, dport = "OTHER", None, None
    if ARP in pkt:
        proto = "ARP"; src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    elif TCP in pkt:
        proto = "TCP"; sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"; sport, dport = pkt[UDP].sport, pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"

    dns_qname = None
    if DNS in pkt and pkt[DNS].qd:
        try:
            dns_qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        except Exception:
            pass

    left = f"{ts} {length:>5}B {proto}"
    if src and dst:
        mid = f" {src}:{sport}" if sport else f" {src}"
        mid += " → "
        mid += f"{dst}:{dport}" if dport else f"{dst}"
    elif mac_src and mac_dst:
        mid = f" {mac_src} → {mac_dst}"
    else:
        mid = ""

    right = []
    if dns_qname:
        right.append(f"DNS? {dns_qname}")
    if show_payload:
        prev = payload_preview(pkt)
        if prev:
            right.append(f"Payload: {prev}")

    if src:
        stats_ip[src] += 1
    stats_proto[proto] += 1

    return left + mid + ("  " + " | ".join(right) if right else "")

def main():
    ap = argparse.ArgumentParser(description="Basic Network Sniffer (Scapy)")
    ap.add_argument("-i", "--iface", help="Interface (e.g., en0, wlan0, eth0)")
    ap.add_argument("-f", "--filter", default="", help="BPF filter (e.g., 'tcp or udp', 'port 53')")
    ap.add_argument("-c", "--count", type=int, default=20, help="How many packets (0 = unlimited)")
    ap.add_argument("--no-payload", action="store_true", help="Do not show payload preview")
    ap.add_argument("--pcap", help="Write packets to PCAP file")
    ap.add_argument("--stats", action="store_true", help="Print simple stats at the end")
    args = ap.parse_args()

    def cb(pkt):
        if args.pcap:
            captured.append(pkt)
        print(describe(pkt, show_payload=not args.no_payload))

    try:
        sniff(
            iface=args.iface,
            filter=args.filter if args.filter else None,
            prn=cb,
            store=False,
            count=args.count if args.count > 0 else 0
        )
    finally:
        if args.pcap and captured:
            from scapy.utils import wrpcap
            wrpcap(args.pcap, captured)
            print(f"💾 Wrote PCAP: {args.pcap} ({len(captured)} packets)")
        if args.stats:
            print("\n📊 Stats")
            for ip, n in stats_ip.most_common(5):
                print(f"  Top src IP  {ip}: {n} pkt")
            for p, n in stats_proto.most_common():
                print(f"  Proto {p}: {n} pkt")

if __name__ == "__main__":
    main()