# PacketSentry — Network Threat Monitoring Lab

A beginner-friendly defensive network monitoring project for the CodeAlpha Basic Network Sniffer task.

## Features
- Analyze synthetic sample traffic without needing capture privileges.
- Capture a bounded number of packets from an authorized interface.
- Read authorized PCAP/PCAPNG captures.
- Extract timestamps, IP addresses, protocol, ports, packet length, and TCP flags.
- Flag simple suspicious patterns using transparent heuristics.
- View charts and export packet/alert data.
- Save metadata and alerts to a local SQLite database.

## Safety and privacy
Use only on your own computer, lab network, or networks for which you have explicit permission. Do not capture other people's traffic. Payloads are not displayed or saved by this app, but packet metadata can still be sensitive. Keep private captures out of GitHub.

Alerts are heuristic indicators, not proof of malicious activity. Validate findings and tune thresholds for the environment.

## Setup (Windows / Kali Linux)
Python 3.10+ recommended.

```bash
python -m venv .venv
```

Windows PowerShell:
```powershell
.venv\Scripts\Activate.ps1
```

Windows Command Prompt:
```bat
.venv\Scripts\activate.bat
```

Kali Linux:
```bash
source .venv/bin/activate
```

Install dependencies:
```bash
python -m pip install -r requirements.txt
```

Run dashboard:
```bash
streamlit run app.py
```

Open the local URL printed by Streamlit (usually http://localhost:8501).

## Live capture notes
- Windows: install Npcap from its official website. Run the terminal with appropriate privileges only if needed.
- Kali: use an authorized interface and appropriate capture permissions. A VM may only see its own virtual NIC traffic unless the virtual network is configured otherwise.
- In VirtualBox, NAT commonly limits visibility to the VM's own traffic. Host-only or an isolated internal network is suitable for lab tests. Do not switch to promiscuous capture on networks you do not own/control.
- Enter an interface name only if you know it. Use the synthetic demo first.

## Detection rules
- Possible port scan: source-to-destination pair has at least 10 unique destination ports in the selected dataset.
- High packet rate: source's average rate is at least 50 packets/sec across the capture interval.

These initial thresholds are demonstrations, not production-grade detection. Port-scan detection should use rolling time windows and TCP flag context for a more reliable next version.

## Project layout
- `app.py`: Streamlit dashboard
- `capture.py`: live capture and PCAP loading
- `parser.py`: packet field extraction
- `detector.py`: simple alert heuristics
- `database.py`: SQLite persistence
- `sample_data/synthetic_packets.csv`: fake training records
