from scapy.all import sniff, rdpcap

def capture_live_packets(count=100, timeout=8, iface=None):
    """Capture a bounded number of packets for an authorized lab only."""
    kwargs = {"count": int(count), "timeout": int(timeout), "store": True}
    if iface:
        kwargs["iface"] = iface
    return sniff(**kwargs)

def read_pcap_file(path, max_packets=1000):
    packets = rdpcap(path, count=int(max_packets))
    return list(packets)
