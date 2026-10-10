from datetime import datetime, timezone
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

def packet_to_record(pkt):
    ts = getattr(pkt, "time", None)
    try:
        timestamp = datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat() if ts is not None else datetime.now(timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        timestamp = datetime.now(timezone.utc).isoformat()

    src_ip = dst_ip = None
    if IP in pkt:
        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

    protocol = "OTHER"
    src_port = dst_port = None
    tcp_flags = None
    if TCP in pkt:
        protocol = "TCP"
        src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
        tcp_flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        protocol = "UDP"
        src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif ICMP in pkt:
        protocol = "ICMP"
    elif IPv6 in pkt:
        protocol = "IPv6"
    elif Ether in pkt:
        protocol = "ETHERNET"

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": len(pkt),
        "tcp_flags": tcp_flags,
    }

def packets_to_dataframe(packets):
    return pd.DataFrame([packet_to_record(p) for p in packets])
