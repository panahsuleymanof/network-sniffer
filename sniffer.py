from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, DNS, DNSQR, ARP, Ether
from datetime import datetime

def payload_preview(pkt, limit=60):
    if Raw in pkt and pkt[Raw].load:
        raw = pkt[Raw].load
        try:
            txt = raw.decode(errors="ignore")
        except Exception:
            txt = str(raw)
        txt = txt.replace("\r", "\\r").replace("\n", "\\n")
        return txt[:limit] + ("…" if len(txt) > limit else "")
    return ""

def packet_callback(pkt):
    ts = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S")
    length = len(pkt)

    # L2
    mac_src = mac_dst = None
    if Ether in pkt:
        mac_src = pkt[Ether].src
        mac_dst = pkt[Ether].dst

    # L3
    src = dst = None
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst

    # L4
    proto, sport, dport = "OTHER", None, None
    if ARP in pkt:
        proto = "ARP"; src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    elif TCP in pkt:
        proto = "TCP"; sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"; sport, dport = pkt[UDP].sport, pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"

    # DNS sorğusu
    extra = ""
    if DNS in pkt and pkt[DNS].qd:
        try:
            q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            extra = f" DNS? {q}"
        except Exception:
            pass

    prev = payload_preview(pkt)

    left = f"{ts} {length:>5}B {proto}"
    if src and dst:
        mid = f" {src}:{sport}" if sport else f" {src}"
        mid += " → "
        mid += f"{dst}:{dport}" if dport else f"{dst}"
    elif mac_src and mac_dst:
        mid = f" {mac_src} → {mac_dst}"
    else:
        mid = ""

    right = ""
    if extra: right += extra
    if prev:  right += (" | " if right else "") + f"Payload: {prev}"

    print(left + mid + (("  " + right) if right else ""))


sniff(prn=packet_callback, count=20, store=False)