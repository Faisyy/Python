from collections import defaultdict
import ipaddress
import time

from scapy.all import ARP, ICMP, IP, TCP, UDP

from logger import log_alert as file_log

# Tunable thresholds. Defaults assume a quiet home/lab LAN.
# On a busy network, raise them; if you see misses, lower them.
TIME_WINDOW = 5       # seconds, sliding window for rate-based checks
SYN_THRESHOLD = 100   # half-open SYNs per window before flagging
ICMP_THRESHOLD = 50   # ICMP packets per window
PORT_THRESHOLD = 15   # distinct dst ports per window
UDP_THRESHOLD = 100   # UDP packets per window

# How long to stay silent about the same (source, alert type) after firing.
ALERT_COOLDOWN = 60   # seconds

# Ports strongly associated with malware C2 / backdoors. 8080 is excluded
# because it is common legitimate dev/proxy/alt-HTTP traffic.
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 9001}

# Sources you never want to alert on, such as your own scanner or monitor.
TRUSTED_IPS = set()   # e.g. {"192.168.1.10", "192.168.1.11"}

# Detection state.
syn_tracker = defaultdict(list)      # src_ip -> [timestamps]
icmp_tracker = defaultdict(list)     # src_ip -> [timestamps]
udp_tracker = defaultdict(list)      # src_ip -> [timestamps]
port_tracker = defaultdict(dict)     # src_ip -> {dst_port: last_seen_ts}
arp_tracker = {}                     # claimed_ip -> mac_address
_last_alert = {}                     # (src_ip, alert_type) -> last_alert_ts


def reset_state():
    """Clear all detection memory after a user reset or before tests."""
    syn_tracker.clear()
    icmp_tracker.clear()
    udp_tracker.clear()
    port_tracker.clear()
    arp_tracker.clear()
    _last_alert.clear()


def _prune_times(tracker, src_ip, now):
    """Drop timestamps older than the current detection window."""
    tracker[src_ip] = [t for t in tracker[src_ip] if now - t < TIME_WINDOW]


def _prune_ports(src_ip, now):
    """Drop destination ports not seen within the current detection window."""
    ports = port_tracker[src_ip]
    for port in [port for port, ts in ports.items() if now - ts >= TIME_WINDOW]:
        del ports[port]


def _should_alert(src_ip, alert_type, now):
    """Return True when this source/type is outside the cooldown period."""
    key = (src_ip, alert_type)
    if now - _last_alert.get(key, 0) >= ALERT_COOLDOWN:
        _last_alert[key] = now
        return True
    return False


def _emit(msg, app):
    app.log_alert(msg)
    file_log(msg)


def _is_ignored(src_ip):
    """Skip trusted hosts and non-unicast sources."""
    if src_ip in TRUSTED_IPS:
        return True
    try:
        ip = ipaddress.ip_address(src_ip)
        if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return True
    except ValueError:
        pass
    return False


def _check_syn_flood(packet, src_ip, now, app):
    if TCP in packet and int(packet[TCP].flags) == 0x02:  # pure SYN, no ACK
        _prune_times(syn_tracker, src_ip, now)
        syn_tracker[src_ip].append(now)
        count = len(syn_tracker[src_ip])
        if count > SYN_THRESHOLD and _should_alert(src_ip, "DOS:SYN", now):
            _emit(
                f"DoS Detected: SYN Flood behaviour from {src_ip} "
                f"({count} SYNs in {TIME_WINDOW}s)",
                app,
            )


def _check_icmp_flood(packet, src_ip, now, app):
    if ICMP in packet:
        _prune_times(icmp_tracker, src_ip, now)
        icmp_tracker[src_ip].append(now)
        count = len(icmp_tracker[src_ip])
        if count > ICMP_THRESHOLD and _should_alert(src_ip, "DOS:ICMP", now):
            _emit(
                f"DoS Detected: ICMP Flood behaviour from {src_ip} "
                f"({count} packets in {TIME_WINDOW}s)",
                app,
            )


def _check_udp_flood(packet, src_ip, now, app):
    if UDP in packet:
        _prune_times(udp_tracker, src_ip, now)
        udp_tracker[src_ip].append(now)
        count = len(udp_tracker[src_ip])
        if count > UDP_THRESHOLD and _should_alert(src_ip, "DOS:UDP", now):
            _emit(
                f"DoS Detected: UDP Flood behaviour from {src_ip} "
                f"({count} UDP packets in {TIME_WINDOW}s)",
                app,
            )


def _check_port_scan(packet, src_ip, now, app):
    if TCP in packet:
        ports = port_tracker[src_ip]
        ports[packet[TCP].dport] = now
        _prune_ports(src_ip, now)
        count = len(ports)
        if count > PORT_THRESHOLD and _should_alert(src_ip, "PORTSCAN", now):
            _emit(
                f"PORT SCAN detected from {src_ip} "
                f"({count} unique ports in {TIME_WINDOW}s)",
                app,
            )


def _check_suspicious_port(packet, src_ip, now, app):
    if TCP in packet:
        dst_ip = packet[IP].dst
        dport = packet[TCP].dport
        if dport in SUSPICIOUS_PORTS:
            # Cooldown keyed per port so one connection does not alert per packet.
            if _should_alert(src_ip, f"SUSPPORT:{dport}", now):
                _emit(
                    "Possible Reverse Shell Indicator: "
                    f"TCP traffic involving suspicious port {dport} "
                    f"from {src_ip} to {dst_ip}",
                    app,
                )


def _check_tcp_flag_scan(packet, src_ip, now, app):
    if TCP not in packet:
        return

    flag_value = int(packet[TCP].flags)
    scan_type = None
    if flag_value == 0x01:
        scan_type = "FIN"
    elif flag_value == 0x00:
        scan_type = "NULL"
    elif flag_value == 0x29:
        scan_type = "XMAS"

    if scan_type and _should_alert(src_ip, f"TCPFLAG:{scan_type}", now):
        _emit(
            f"TCP Flag Scan Detected: {scan_type} scan pattern from {src_ip}",
            app,
        )


def _check_arp_spoofing(packet, now, app):
    if ARP not in packet or packet[ARP].op != 2:  # ARP reply/is-at
        return

    claimed_ip = packet[ARP].psrc
    current_mac = packet[ARP].hwsrc.lower()
    previous_mac = arp_tracker.get(claimed_ip)
    arp_tracker[claimed_ip] = current_mac

    if previous_mac and previous_mac != current_mac:
        if _should_alert(claimed_ip, "ARP_SPOOF", now):
            _emit(
                "ARP Spoofing / MITM Indicator: "
                f"IP {claimed_ip} changed from {previous_mac} to {current_mac}",
                app,
            )


def detect(packet, app):
    now = time.time()

    if ARP in packet:
        _check_arp_spoofing(packet, now, app)

    if IP not in packet:
        return

    src_ip = packet[IP].src
    if _is_ignored(src_ip):
        return

    _check_syn_flood(packet, src_ip, now, app)
    _check_icmp_flood(packet, src_ip, now, app)
    _check_port_scan(packet, src_ip, now, app)
    _check_udp_flood(packet, src_ip, now, app)
    _check_suspicious_port(packet, src_ip, now, app)
    _check_tcp_flag_scan(packet, src_ip, now, app)
