# IDS Project Implementation and Testing Plan

## 1. Project Direction

This project will continue from the existing Python-based Intrusion Detection System (IDS) repository. The current IDS already includes threshold-based detection for:

- SYN Flood
- ICMP Flood
- UDP Flood
- Port Scan
- Suspicious Ports

The next improvement is to expand the IDS into a stronger rule-based security monitoring tool by adding more detectable attack indicators and preparing proper testing evidence.

The final system should support:

1. SYN Flood Detection
2. ICMP Flood Detection
3. UDP Flood Detection
4. Port Scan Detection
5. DoS Attack Classification
6. Suspicious Port / Possible Reverse Shell Indicator
7. TCP Flag Scan Detection
8. ARP Spoofing / Possible Man-in-the-Middle Indicator

---

## 2. Main Objective

The main objective is to improve the existing IDS so that it can detect multiple suspicious network behaviours in a controlled lab environment. The tool should produce alert logs, screenshots, and comparison evidence that can be used in the project report and presentation.

The testing evidence will be based on at least 20 sample cases, including normal traffic and different attack-like traffic patterns.

---

## 3. Safe Lab Testing Environment

All testing must be conducted in a controlled environment only. The IDS must not be used to attack real production systems, public servers, university websites, or third-party networks.

Recommended setup:

| Device / System | Role |
|---|---|
| Windows laptop / Admin laptop | Runs the Python IDS and collects screenshots/logs |
| Kali Linux VM | Generates controlled test traffic |
| Target VM / Own laptop IP | Receives controlled traffic for testing |
| Wireshark | Used as comparison tool and packet evidence |

Recommended topology:

```text
Kali VM  --->  Target VM / Admin Laptop
              IDS running on Admin Laptop
              Wireshark capturing the same traffic
```

For ARP spoofing / possible MITM testing, a 3-device or 3-VM setup is better:

```text
Kali VM = traffic generator
Victim VM = simulated victim
Gateway / router / another VM = network gateway
IDS machine = monitors traffic on the same LAN
```

---

## 4. Development Plan

### Phase 1: Review Current IDS Code

Check the current repository structure and confirm how the files work together.

Expected structure:

| File | Purpose |
|---|---|
| `main.py` | GUI and main application interface |
| `sniffer.py` | Packet capture and packet forwarding to detector |
| `detector.py` | Detection rules and alert logic |
| `logger.py` | Stores alert logs |
| `README.md` | Documentation and instructions |

Main action:

- Confirm that the existing IDS runs successfully.
- Confirm that packet capture works.
- Confirm that existing alerts appear in the GUI and log file.
- Confirm that `.pcap` or `.pcapng` file analysis works, if supported.

---

### Phase 2: Add DoS Attack Classification

The existing SYN Flood, ICMP Flood, and UDP Flood thresholds already represent DoS-style behaviour.

Instead of treating them as separate unrelated alerts, update the alert message so they are grouped under DoS classification.

Example alert messages:

```text
DoS Detected: SYN Flood behaviour from 192.168.1.10
DoS Detected: ICMP Flood behaviour from 192.168.1.10
DoS Detected: UDP Flood behaviour from 192.168.1.10
```

Files to update:

- `detector.py`

Expected outcome:

- The IDS can clearly report DoS attack type.
- Report discussion becomes easier because all flood-based attacks can be explained as DoS indicators.

---

### Phase 3: Improve Suspicious Port / Possible Reverse Shell Indicator

The current IDS already checks suspicious ports such as:

- 4444
- 1337
- 31337
- 6666
- 9001
- 8080

These can be improved into a clearer detection feature called:

```text
Suspicious Port / Possible Reverse Shell Indicator
```

Important wording:

The IDS should not claim that it has confirmed a reverse shell. It should only say that the traffic may indicate suspicious remote access or possible reverse shell activity.

Example alert message:

```text
Possible Reverse Shell Indicator: outbound connection detected on suspicious port 4444
```

Files to update:

- `detector.py`
- `README.md`

Expected outcome:

- Suspicious port detection becomes more meaningful.
- The report can explain that the IDS detects indicators of suspicious outbound communication.

---

### Phase 4: Add TCP Flag Scan Detection

TCP flag scans are commonly used during reconnaissance. The IDS can detect unusual TCP flag combinations.

Recommended scan types to detect:

| Scan Type | TCP Flag Pattern | Meaning |
|---|---|---|
| FIN Scan | FIN flag only | Stealth scanning behaviour |
| NULL Scan | No TCP flags set | Abnormal TCP packet |
| XMAS Scan | FIN + PSH + URG flags | Stealth scanning behaviour |

Example alert messages:

```text
TCP Flag Scan Detected: FIN scan pattern from 192.168.1.10
TCP Flag Scan Detected: NULL scan pattern from 192.168.1.10
TCP Flag Scan Detected: XMAS scan pattern from 192.168.1.10
```

Files to update:

- `detector.py`

Expected outcome:

- IDS can detect more reconnaissance behaviours beyond basic port scanning.

---

### Phase 5: Allow ARP Packet Analysis

The current packet processing may only analyze IP packets. ARP packets do not use the same IP layer, so the sniffer should pass all packets to the detector.

File to update:

- `sniffer.py`

Required idea:

```python
def _process_packet(packet, app):
    app.increment_packets()
    detect(packet, app)
```

Expected outcome:

- ARP packets can reach `detector.py`.
- ARP spoofing detection becomes possible.

---

### Phase 6: Add ARP Spoofing / Possible MITM Detection

ARP spoofing is a common local network attack that can indicate possible Man-in-the-Middle activity.

Detection logic:

- Store IP-to-MAC address mapping from ARP packets.
- If the same IP address suddenly appears with a different MAC address, trigger an alert.

Example alert message:

```text
ARP Spoofing / MITM Indicator: IP 192.168.1.1 changed from AA:BB:CC:DD:EE:FF to 11:22:33:44:55:66
```

Files to update:

- `detector.py`
- `sniffer.py`
- `README.md`

Expected outcome:

- IDS can detect suspicious ARP mapping changes.
- The system can reasonably claim to detect MITM indicators, not full MITM confirmation.

---

### Phase 7: Optional GUI Update

The GUI does not need major changes because new alerts should appear automatically if the detector sends messages to the alert log.

Optional improvement in `main.py`:

Add a small detection coverage label:

```text
Detection Coverage: DoS Classification | SYN/ICMP/UDP Flood | Port Scan | TCP Flag Scan | Possible Reverse Shell | ARP Spoofing/MITM Indicator
```

File to update:

- `main.py`

Expected outcome:

- GUI looks clearer during presentation.
- Screenshots show the full capability of the IDS.

---

### Phase 8: Update README Documentation

Update the README so that it includes:

- New detection features
- How each detection rule works
- Threshold values
- Lab-only testing warning
- How to run the IDS
- How to collect test evidence
- Known limitations

Important limitation wording:

```text
This IDS is rule-based and threshold-based. Alerts should be treated as suspicious indicators, not confirmed attacks. Results should be verified using packet analysis tools such as Wireshark.
```

---

## 5. Kali VM Testing Plan

After the IDS is updated, prepare controlled lab testing scripts or commands from Kali VM.

Recommended test scripts:

| Script / Command Group | Purpose |
|---|---|
| `test_syn_flood.py` | Generates SYN-heavy traffic to trigger SYN Flood / DoS alert |
| `test_icmp_flood.sh` | Generates controlled ICMP traffic to trigger ICMP Flood alert |
| `test_udp_flood.py` | Generates UDP packet bursts to trigger UDP Flood alert |
| `test_port_scan.sh` | Scans multiple ports on the lab target to trigger Port Scan alert |
| `test_tcp_flag_scan.sh` | Generates FIN, NULL, or XMAS scan traffic |
| `test_reverse_shell_indicator.sh` | Simulates suspicious port connection to trigger possible reverse shell indicator |
| `test_arp_spoof_lab.py` | Generates ARP spoofing indicator in an isolated lab environment |

Important safety rule:

All scripts must target only your own VM, your own laptop, or a lecturer-approved lab target.

---

## 6. 20 Sample Case Plan

The project should prepare at least 20 sample cases. These do not need to be 20 separate PCAP files. They can be 20 clear test scenarios, detection logs, or dataset entries.

Recommended distribution:

| Case No. | Category | Number of Cases |
|---|---|---:|
| 1-3 | Normal traffic | 3 |
| 4-6 | SYN Flood / DoS | 3 |
| 7-9 | ICMP Flood / DoS | 3 |
| 10-12 | UDP Flood / DoS | 3 |
| 13-15 | Port Scan | 3 |
| 16-17 | TCP Flag Scan | 2 |
| 18-19 | Possible Reverse Shell Indicator | 2 |
| 20 | ARP Spoofing / MITM Indicator | 1 |

---

## 7. Evidence Collection Checklist

For every test category, collect evidence from both the IDS and Wireshark.

Required evidence:

| Evidence Type | What to Capture |
|---|---|
| IDS screenshot | GUI showing alert message |
| IDS log file | Saved alert log from the IDS |
| Kali screenshot | Terminal showing controlled test traffic |
| Wireshark screenshot | Packet capture showing matching traffic |
| Result table | Expected result vs IDS result vs Wireshark observation |

Suggested folder structure:

```text
evidence/
├── normal_traffic/
├── syn_flood/
├── icmp_flood/
├── udp_flood/
├── port_scan/
├── tcp_flag_scan/
├── reverse_shell_indicator/
├── arp_spoofing/
└── wireshark_comparison/
```

---

## 8. Result Table Template

Use this table in the report or poster:

| No. | Test Type | Input Source | Expected Result | IDS Result | Wireshark Observation | Status |
|---|---|---|---|---|---|---|
| 1 | Normal Traffic | Live capture / PCAP | No alert | No alert | Normal TCP/HTTPS traffic | Pass |
| 4 | SYN Flood | Kali test traffic | SYN Flood / DoS alert | Detected | Many SYN packets observed | Pass |
| 7 | ICMP Flood | Kali test traffic | ICMP Flood / DoS alert | Detected | High ICMP packet volume | Pass |
| 10 | UDP Flood | Kali test traffic | UDP Flood / DoS alert | Detected | High UDP packet volume | Pass |
| 13 | Port Scan | Kali test traffic | Port scan alert | Detected | Multiple destination ports observed | Pass |
| 16 | TCP Flag Scan | Kali test traffic | TCP flag scan alert | Detected | FIN/NULL/XMAS packets observed | Pass |
| 18 | Possible Reverse Shell Indicator | Suspicious port traffic | Suspicious port alert | Detected | TCP connection to port 4444 observed | Pass |
| 20 | ARP Spoofing / MITM Indicator | ARP test traffic | ARP spoofing alert | Detected | Duplicate IP/MAC mapping observed | Pass |

---

## 9. Wireshark Comparison Plan

Wireshark will be used as the comparison tool because it can capture and display raw packet evidence.

Comparison angle:

| Attack Type | IDS Tool | Wireshark |
|---|---|---|
| SYN Flood | Automatically alerts SYN Flood / DoS | Shows many SYN packets, but user must inspect manually |
| ICMP Flood | Automatically alerts ICMP Flood / DoS | Shows high ICMP traffic volume |
| UDP Flood | Automatically alerts UDP Flood / DoS | Shows high UDP traffic volume |
| Port Scan | Automatically alerts multiple port attempts | Shows traffic to many destination ports |
| TCP Flag Scan | Automatically alerts unusual TCP flags | Shows FIN, NULL, or XMAS packet flags |
| Reverse Shell Indicator | Flags suspicious port connection | Shows TCP connection to suspicious port |
| ARP Spoofing | Alerts IP-to-MAC change | Shows ARP replies and MAC mapping changes |

Main discussion point:

The IDS is easier for quick detection because it gives automatic alerts. Wireshark provides deeper packet-level verification but requires manual analysis.

---

## 10. Report Section Mapping

The final implementation and testing can be used in these report sections:

### Section 6: Technical Methodology

Include:

- System architecture
- Program modules
- Detection rules
- Threshold values
- Packet flow
- GUI flow
- Testing setup

### Section 7: Results and Discussion

Include:

- 20 test case result table
- IDS screenshots
- Log outputs
- Wireshark screenshots
- Comparison table
- Discussion of true positives, false positives, and limitations

### Section 8: Conclusion

Include:

- Summary of completed IDS
- How objectives were achieved
- Benefits of the tool
- Limitations
- Future improvements

---

## 11. Final Work Order

The recommended work order is:

1. Run the current IDS and confirm it works.
2. Backup the original repository.
3. Update `detector.py` for DoS classification.
4. Update suspicious port detection into possible reverse shell indicator.
5. Add TCP flag scan detection.
6. Update `sniffer.py` to pass ARP packets to the detector.
7. Add ARP spoofing / MITM indicator detection.
8. Optional: update `main.py` GUI label.
9. Update `README.md`.
10. Create Kali VM test scripts or commands.
11. Run each test in a controlled lab.
12. Save IDS screenshots and logs.
13. Save Wireshark comparison screenshots.
14. Complete the 20 sample case table.
15. Write Section 6, Section 7, and Section 8.
16. Prepare poster and promotional video.

---

## 12. Important Safety and Accuracy Notes

- Only test on your own device, VM, or lecturer-approved lab machines.
- Do not test against public IPs, university servers, websites, or third-party systems.
- Do not claim that the IDS confirms malware, reverse shell, or MITM with 100% certainty.
- Use careful wording such as:
  - "possible reverse shell indicator"
  - "ARP spoofing / possible MITM indicator"
  - "DoS-style behaviour"
  - "suspicious traffic pattern"
- Verify alerts using Wireshark before adding them to the report.
- Keep all screenshots, logs, and PCAP files organized as project evidence.
