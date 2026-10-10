import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from parser import packets_to_dataframe
from detector import detect_suspicious_patterns
from capture import capture_live_packets, read_pcap_file
from database import save_records, load_records, clear_records

st.set_page_config(page_title="PacketSentry SOC", page_icon="🛡️", layout="wide")
st.title("🛡️ PacketSentry")
st.caption("Defensive network monitoring lab • Use only on networks you own or are authorized to monitor.")

with st.sidebar:
    st.header("Capture settings")
    mode = st.radio("Data source", ["Synthetic demo", "Live capture", "PCAP file"])
    max_packets = st.slider("Maximum packets", 10, 1000, 100, 10)
    timeout = st.slider("Capture duration (seconds)", 3, 30, 8)
    st.warning("Live capture requires Npcap on Windows or suitable capture permissions on Linux.")
    st.caption("Do not capture other people's traffic or upload private PCAPs.")

records = []
if mode == "Synthetic demo":
    demo_path = Path("sample_data/synthetic_packets.csv")
    if demo_path.exists():
        df = pd.read_csv(demo_path)
        st.info("Showing synthetic training data. These records are not live traffic.")
    else:
        st.error("Missing sample_data/synthetic_packets.csv")
        df = pd.DataFrame()
elif mode == "PCAP file":
    uploaded = st.file_uploader("Upload an authorized .pcap/.pcapng file", type=["pcap", "pcapng", "cap"])
    if uploaded:
        temp_path = Path("uploaded_capture.pcap")
        temp_path.write_bytes(uploaded.getvalue())
        try:
            packets = read_pcap_file(str(temp_path), max_packets=max_packets)
            df = packets_to_dataframe(packets)
            temp_path.unlink(missing_ok=True)
        except Exception as exc:
            st.error(f"Could not read capture: {exc}")
            df = pd.DataFrame()
    else:
        df = pd.DataFrame()
else:
    st.info("Choose the interface connected to your own lab network. Capture stops automatically.")
    interface = st.text_input("Interface name (leave blank for default)", value="")
    if st.button("Start authorized capture", type="primary"):
        try:
            with st.spinner(f"Capturing for up to {timeout} seconds..."):
                packets = capture_live_packets(count=max_packets, timeout=timeout, iface=interface.strip() or None)
            df = packets_to_dataframe(packets)
            st.success(f"Capture finished. Packets collected: {len(df)}")
        except Exception as exc:
            st.error(f"Capture failed: {exc}. Check Npcap/permissions and interface name.")
            df = pd.DataFrame()
    else:
        df = pd.DataFrame()

if not df.empty:
    for col in ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "length", "tcp_flags"]:
        if col not in df.columns:
            df[col] = None
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    alerts = detect_suspicious_patterns(df)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets analyzed", f"{len(df):,}")
    c2.metric("Unique source IPs", int(df["src_ip"].nunique()))
    c3.metric("Protocols", int(df["protocol"].nunique()))
    c4.metric("Potential alerts", len(alerts))
    left, right = st.columns(2)
    with left:
        proto = df["protocol"].fillna("OTHER").value_counts().rename_axis("Protocol").reset_index(name="Packets")
        st.plotly_chart(px.pie(proto, names="Protocol", values="Packets", title="Protocol distribution"), use_container_width=True)
    with right:
        timeline = df.dropna(subset=["timestamp"]).set_index("timestamp").resample("1s").size().reset_index(name="Packets")
        st.plotly_chart(px.line(timeline, x="timestamp", y="Packets", title="Packets per second"), use_container_width=True)
    st.subheader("Detection alerts")
    if alerts:
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    else:
        st.success("No configured rules matched this dataset. This does not prove the network is safe.")
    st.subheader("Packet records")
    st.dataframe(df, use_container_width=True, hide_index=True)
    col_a, col_b = st.columns(2)
    with col_a:
        st.download_button("Export packets as CSV", df.to_csv(index=False).encode("utf-8"), "packetsentry_packets.csv", "text/csv")
    with col_b:
        st.download_button("Export alerts as JSON", json.dumps(alerts, indent=2, default=str), "packetsentry_alerts.json", "application/json")
    if st.button("Save records to local SQLite database"):
        save_records(df, alerts)
        st.success("Records saved to packetsentry.db")
else:
    st.info("No records to display yet. Start with Synthetic demo to verify the dashboard.")

with st.expander("Previously saved records"):
    saved = load_records()
    if saved:
        st.write(f"Saved packet rows: {len(saved['packets'])} • Saved alerts: {len(saved['alerts'])}")
        if st.button("Clear local database"):
            clear_records()
            st.success("Local database cleared. Refresh the page to update this section.")
    else:
        st.caption("No saved records yet.")
