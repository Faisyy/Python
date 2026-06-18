# Python-Based Intrusion Detection System

This project is a desktop Intrusion Detection System (IDS) built with Python. It monitors live network traffic or analyzes saved packet captures, then raises alerts for rule-based suspicious traffic indicators.

The GUI is built with CustomTkinter, packet handling is done with Scapy, and alert logs are written to the local `logs/` folder.

Important: this IDS is for controlled lab and educational use. Alerts should be treated as suspicious indicators, not confirmed attacks. Verify findings with packet analysis tools such as Wireshark.

## Features

- Live packet sniffing from the GUI.
- PCAP/PCAPNG file analysis.
- Timestamped alert logging.
- Packet and alert counters.
- Rule-based detection for:
  - DoS-style SYN flood behaviour
  - DoS-style ICMP flood behaviour
  - DoS-style UDP flood behaviour
  - TCP port scan behaviour
  - TCP flag scans: FIN, NULL, and XMAS
  - Suspicious port traffic / possible reverse shell indicators
  - ARP spoofing / possible MITM indicators

## Project Structure

```text
.
|-- main.py       # CustomTkinter GUI and application entry point
|-- sniffer.py    # Live capture and PCAP packet processing
|-- detector.py   # Rule-based detection logic and state
|-- logger.py     # Local log file creation and writes
|-- attacks/      # Kali VM lab traffic scripts for sample cases
|-- Admin.bat     # Windows helper to run the app
|-- tests/        # Local unittest detector coverage
`-- README.md     # Project documentation
```

## Requirements

Install the Python packages:

```powershell
pip install customtkinter scapy
```

For live packet sniffing on Windows, you will usually also need:

- Administrator privileges
- Npcap installed

PCAP analysis usually does not require Administrator privileges.

## Running the GUI

From the project folder:

```powershell
python main.py
```

On Windows, you can also run:

```powershell
Admin.bat
```

For live sniffing, run PowerShell, Command Prompt, or the batch file as Administrator.

## How to Use

1. Start the app with `python main.py`.
2. Use **Start Live Sniff** to monitor live traffic.
3. Use **Load PCAP** to analyze a `.pcap` or `.pcapng` file.
4. Watch **Packets Captured**, **Alerts**, and the alert log.
5. Use **Stop** to stop live sniffing or interrupt analysis.
6. Use **Clear Log** to reset the visible counters and detector state.

Each app session creates a log file like:

```text
logs/ids_YYYYMMDD_HHMMSS.log
```

## Detection Rules

The main detection logic is in `detector.py`.

| Rule | Trigger |
| --- | --- |
| DoS: SYN flood | More than 100 pure SYN packets from one source within 5 seconds |
| DoS: ICMP flood | More than 50 ICMP packets from one source within 5 seconds |
| DoS: UDP flood | More than 100 UDP packets from one source within 5 seconds |
| Port scan | More than 15 unique TCP destination ports from one source within 5 seconds |
| TCP FIN scan | TCP packet with FIN flag only |
| TCP NULL scan | TCP packet with no flags set |
| TCP XMAS scan | TCP packet with FIN, PSH, and URG flags set |
| Possible reverse shell indicator | TCP traffic involving suspicious destination ports |
| ARP spoofing / MITM indicator | One IP address appears with a different MAC address in ARP replies |

Suspicious TCP destination ports:

```text
4444, 1337, 31337, 6666, 9001
```

`8080` is intentionally not included by default because it is common for legitimate development, proxy, and alternate HTTP traffic.

The detector also includes an alert cooldown:

```text
ALERT_COOLDOWN = 60 seconds
```

This prevents the same source and alert type from repeatedly flooding the GUI and log file.

## Developer Notes

Packet flow:

```text
main.py -> sniffer.py -> detector.py -> logger.py
```

- `main.py` owns the GUI state and user actions.
- `sniffer.py` captures live packets or reads PCAP files, then forwards every packet to the detector.
- `detector.py` maintains detection state, thresholds, cooldowns, and alert rules.
- `logger.py` writes alert and info messages to disk.

Useful detector settings:

```python
TIME_WINDOW = 5
SYN_THRESHOLD = 100
ICMP_THRESHOLD = 50
PORT_THRESHOLD = 15
UDP_THRESHOLD = 100
ALERT_COOLDOWN = 60
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 9001}
TRUSTED_IPS = set()
```

To add a new rule:

1. Add a `_check_*` function in `detector.py`.
2. Call it from `detect(packet, app)`.
3. Use `_emit(message, app)` so alerts appear in both the GUI and log file.
4. Add or update unit tests in `tests/`.

## Running Tests

Run the local detector tests:

```powershell
python -m unittest
```

These tests build Scapy packets in memory and do not require live network access.

## Testing Evidence

For report and presentation evidence, test only inside a controlled lab using your own VM, your own laptop, or lecturer-approved targets.

The `attacks/` folder contains Python scripts that can be run from Kali VM to generate each sample traffic category. Each script requires `--confirm-lab` and only accepts private or loopback IP targets.

Example:

```bash
sudo python3 attacks/syn_flood.py --target 192.168.56.10 --confirm-lab
```

Recommended evidence to collect for each test category:

- IDS GUI screenshot showing the alert.
- IDS log file entry.
- Kali or test-machine terminal screenshot showing the controlled traffic.
- Wireshark screenshot showing matching packet evidence.
- Result table row with expected result, IDS result, Wireshark observation, and pass/fail status.

Suggested evidence categories:

```text
evidence/
|-- normal_traffic/
|-- syn_flood/
|-- icmp_flood/
|-- udp_flood/
|-- port_scan/
|-- tcp_flag_scan/
|-- reverse_shell_indicator/
|-- arp_spoofing/
`-- wireshark_comparison/
```

Do not run attack-style tests against public IPs, university servers, websites, or third-party systems.

## Limitations

- This IDS is rule-based and threshold-based.
- It detects suspicious indicators, not confirmed malware, reverse shells, or MITM attacks.
- Thresholds may need tuning for busy networks.
- Wireshark or another packet analysis tool should be used to verify important alerts.
