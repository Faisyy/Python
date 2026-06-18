# Lab Attack Traffic Generators

These scripts generate controlled sample traffic for testing the Python IDS in a private lab. Run them from Kali Linux or another test VM against only your own VM, your own laptop, or a lecturer-approved lab target.

Do not run these scripts against public IPs, university systems, websites, or third-party networks.

## Requirements

Install Scapy on Kali:

```bash
sudo apt update
sudo apt install -y python3-scapy
```

Most scripts require root privileges because they craft packets:

```bash
sudo python3 script_name.py --target 192.168.56.10 --confirm-lab
```

## Scripts

| Script | IDS Detection Expected |
| --- | --- |
| `syn_flood.py` | DoS Detected: SYN Flood behaviour |
| `icmp_flood.py` | DoS Detected: ICMP Flood behaviour |
| `udp_flood.py` | DoS Detected: UDP Flood behaviour |
| `port_scan.py` | PORT SCAN detected |
| `tcp_flag_scan.py` | TCP Flag Scan Detected: FIN/NULL/XMAS |
| `reverse_shell_indicator.py` | Possible Reverse Shell Indicator |
| `arp_spoof_lab.py` | ARP Spoofing / MITM Indicator |

## Typical Workflow

1. Start the IDS on the monitoring machine.
2. Start Wireshark on the same network/interface for comparison.
3. Run one script from Kali VM against the lab target.
4. Save:
   - IDS GUI screenshot
   - IDS log entry
   - Kali terminal screenshot
   - Wireshark screenshot
   - Result table row

## Safety Controls

- Every script requires `--confirm-lab`.
- IP targets must be private or loopback addresses.
- Defaults are intentionally small and controlled.
- The reverse shell indicator script does not create a reverse shell; it only sends TCP traffic to a suspicious port so the IDS can flag the indicator.
