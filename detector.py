import pandas as pd

def detect_suspicious_patterns(df, port_scan_threshold=10, packet_rate_threshold=50, window_seconds=10):
    """Simple explainable heuristics; alerts are leads for review, not proof of compromise."""
    if df is None or df.empty:
        return []
    data = df.copy()
    if "timestamp" not in data:
        return []
    data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce", utc=True)
    data = data.dropna(subset=["timestamp"])
    alerts = []

    # Possible scan: one source attempts many distinct destination ports on one target.
    tcpudp = data[data["protocol"].isin(["TCP", "UDP"])].dropna(subset=["src_ip", "dst_ip", "dst_port"])
    if not tcpudp.empty:
        counts = tcpudp.groupby(["src_ip", "dst_ip"])["dst_port"].nunique()
        for (src, dst), nports in counts.items():
            if nports >= port_scan_threshold:
                alerts.append({
                    "time": data["timestamp"].max().isoformat(),
                    "severity": "Medium",
                    "type": "Possible port scan",
                    "source": src,
                    "destination": dst,
                    "details": f"{nports} distinct destination ports observed (threshold: {port_scan_threshold}).",
                    "recommendation": "Review the time window and expected scanner/admin activity."
                })

    # High packet count per source in the observed capture interval.
    counts = data.dropna(subset=["src_ip"]).groupby("src_ip").size()
    duration = max((data["timestamp"].max() - data["timestamp"].min()).total_seconds(), 1.0)
    for src, count in counts.items():
        rate = count / duration
        if rate >= packet_rate_threshold:
            alerts.append({
                "time": data["timestamp"].max().isoformat(),
                "severity": "Low",
                "type": "High packet rate",
                "source": src,
                "destination": "multiple/unknown",
                "details": f"{rate:.1f} packets/sec averaged over capture (threshold: {packet_rate_threshold}).",
                "recommendation": "Compare against a baseline; backups and video calls can be high-volume."
            })
    return alerts
