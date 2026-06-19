# Attack Sample Scripts for IDS Testing

This folder contains Python scripts that generate controlled lab traffic for testing whether the IDS detects each planned attack indicator.

Run these scripts from Kali Linux against only your own VM, your own laptop, or a lecturer-approved lab target. Do not run them against public IP addresses, university systems, websites, or third-party networks.

The scripts only accept private or loopback IP addresses such as:

```text
192.168.x.x
10.x.x.x
172.16.x.x - 172.31.x.x
127.0.0.1
```

## 1. Prepare Kali VM

Install Scapy:

```bash
sudo apt update
sudo apt install -y python3-scapy
```

Check that Python and Scapy are available:

```bash
python3 --version
python3 -c "import scapy; print('scapy ok')"
```

If the Scapy import works, the scripts are ready.

## 2. Copy or Open This Project on Kali

From Kali, go to the project folder:

```bash
cd /path/to/Python
```

Check that the attack scripts exist:

```bash
ls attacks
```

You should see files such as:

```text
syn_flood.py
icmp_flood.py
udp_flood.py
port_scan.py
tcp_flag_scan.py
reverse_shell_indicator.py
arp_spoof_lab.py
```

## 3. Start the IDS First

On the Windows IDS machine:

```powershell
python main.py
```

For live packet detection, run the IDS as Administrator. Click **Start Live Sniff** before running the Kali script.

Optional but recommended: start Wireshark on the IDS machine or target machine so you can compare the IDS alert with packet evidence.

## 4. Find Your Lab Target IP

On the target machine, find its IP address.

Windows:

```powershell
ipconfig
```

Linux:

```bash
ip addr
```

Use a private lab IP, for example:

```text
192.168.0.137
```

In the examples below, replace `192.168.0.137` with your own lab target IP.

## 5. Run Each Sample Case

Most scripts need `sudo` because Scapy sends crafted packets.

### SYN Flood / DoS Sample

Expected IDS alert:

```text
DoS Detected: SYN Flood behaviour
```

Command:

```bash
sudo python3 attacks/syn_flood.py --target 192.168.0.137
```

Optional settings:

```bash
sudo python3 attacks/syn_flood.py --target 192.168.0.137 --port 80 --count 130 --interval 0.01
```

### ICMP Flood / DoS Sample

Expected IDS alert:

```text
DoS Detected: ICMP Flood behaviour
```

Command:

```bash
sudo python3 attacks/icmp_flood.py --target 192.168.0.137
```

Optional settings:

```bash
sudo python3 attacks/icmp_flood.py --target 192.168.0.137 --count 70 --interval 0.01
```

### UDP Flood / DoS Sample

Expected IDS alert:

```text
DoS Detected: UDP Flood behaviour
```

Command:

```bash
sudo python3 attacks/udp_flood.py --target 192.168.0.137
```

Optional settings:

```bash
sudo python3 attacks/udp_flood.py --target 192.168.0.137 --port 5353 --count 130 --interval 0.01
```

### Port Scan Sample

Expected IDS alert:

```text
PORT SCAN detected
```

Command:

```bash
sudo python3 attacks/port_scan.py --target 192.168.0.137
```

Optional settings:

```bash
sudo python3 attacks/port_scan.py --target 192.168.0.137 --start-port 20 --ports 20 --interval 0.02
```

The IDS threshold is more than 15 unique TCP destination ports within 5 seconds, so the default `--ports 20` should trigger it.

### TCP Flag Scan Sample

Expected IDS alerts:

```text
TCP Flag Scan Detected: FIN scan pattern
TCP Flag Scan Detected: NULL scan pattern
TCP Flag Scan Detected: XMAS scan pattern
```

Run all three scan types:

```bash
sudo python3 attacks/tcp_flag_scan.py --target 192.168.0.137
```

Run only one scan type:

```bash
sudo python3 attacks/tcp_flag_scan.py --target 192.168.0.137 --scan fin
sudo python3 attacks/tcp_flag_scan.py --target 192.168.0.137 --scan null
sudo python3 attacks/tcp_flag_scan.py --target 192.168.0.137 --scan xmas
```

Optional settings:

```bash
sudo python3 attacks/tcp_flag_scan.py --target 192.168.0.137 --scan all --port 80 --repeat 1
```

### Possible Reverse Shell Indicator Sample

Expected IDS alert:

```text
Possible Reverse Shell Indicator
```

Command:

```bash
sudo python3 attacks/reverse_shell_indicator.py --target 192.168.0.137
```

Optional settings:

```bash
sudo python3 attacks/reverse_shell_indicator.py --target 192.168.0.137 --port 4444 --count 3
```

This script does not create a reverse shell. It only sends TCP traffic to a suspicious port so the IDS can flag the indicator.

### ARP Spoofing / MITM Indicator Sample

Expected IDS alert:

```text
ARP Spoofing / MITM Indicator
```

Use this only on an isolated lab network. You need:

- A claimed IP, usually a lab gateway or simulated gateway IP.
- A victim IP, usually your target VM/laptop IP.

Example:

```bash
sudo python3 attacks/arp_spoof_lab.py --claimed-ip 192.168.0.1 --victim-ip 192.168.0.137
```

Optional settings:

```bash
sudo python3 attacks/arp_spoof_lab.py \
  --claimed-ip 192.168.0.1 \
  --victim-ip 192.168.0.137 \
  --original-mac aa:bb:cc:dd:ee:ff \
  --changed-mac 00:11:22:33:44:55
```

The script sends two ARP replies for the same IP with different MAC addresses. The IDS should detect that the IP-to-MAC mapping changed.

## 6. Help Commands

Every script has help text:

```bash
python3 attacks/syn_flood.py --help
python3 attacks/icmp_flood.py --help
python3 attacks/udp_flood.py --help
python3 attacks/port_scan.py --help
python3 attacks/tcp_flag_scan.py --help
python3 attacks/reverse_shell_indicator.py --help
python3 attacks/arp_spoof_lab.py --help
```

Use these commands if you forget the available options.

## 7. Evidence to Collect

For each sample case, save:

- IDS GUI screenshot showing the alert.
- IDS log file entry from `logs/`.
- Kali terminal screenshot showing the command.
- Wireshark screenshot showing matching packet traffic.
- Result table row showing expected result, IDS result, Wireshark observation, and pass/fail status.

Suggested evidence folders:

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

## 8. Troubleshooting

If you see `Permission denied` or packets do not send:

```bash
sudo python3 attacks/script_name.py --target 192.168.0.137
```

If Python says Scapy is missing:

```bash
sudo apt install -y python3-scapy
```

If no IDS alert appears:

- Make sure the IDS is running as Administrator.
- Make sure **Start Live Sniff** is clicked.
- Make sure Kali and the target are on the same lab network.
- Make sure you used the correct target IP.
- Wait 60 seconds before repeating the same test, because the IDS has an alert cooldown.
- Check Wireshark to confirm the packets reached the monitored interface.

If the script rejects the IP address, use a private lab IP only. Public targets are intentionally blocked.

