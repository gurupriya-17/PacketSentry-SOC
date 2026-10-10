import pandas as pd
from detector import detect_suspicious_patterns

def test_detects_many_ports():
    base = pd.Timestamp("2026-10-10T10:00:00Z")
    df = pd.DataFrame([{
        "timestamp": base + pd.Timedelta(seconds=i),
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1",
        "protocol": "TCP", "dst_port": 20+i
    } for i in range(12)])
    alerts = detect_suspicious_patterns(df)
    assert any(a["type"] == "Possible port scan" for a in alerts)
