from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict
from logger import log_alert as file_log
import ipaddress
import time
 
# ─── Tunable thresholds ───────────────────────────────────────────────────────
# Tune these to YOUR network. Defaults assume a quiet home/lab LAN.
# On a busy network, raise them; if you see misses, lower them.
TIME_WINDOW    = 5      # seconds — sliding window for rate-based checks
SYN_THRESHOLD  = 100    # half-open SYNs per window before flagging
ICMP_THRESHOLD = 50     # ICMP packets per window
PORT_THRESHOLD = 15     # distinct dst ports per window (port scan)
UDP_THRESHOLD  = 100    # UDP packets per window
 
# How long to stay silent about the SAME (source, alert type) after firing.
# This is the main false-positive control: a sustained event now re-alerts at
# most once per cooldown instead of repeatedly as the counter rebuilds.
ALERT_COOLDOWN = 60     # seconds
 
# Ports strongly associated with malware C2 / backdoors. 8080 was removed on
# purpose — it's a normal dev/proxy/alt-HTTP port and produced constant noise.
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 9001}
 
# Sources you never want to alert on (your own scanner, a monitoring host…).
TRUSTED_IPS = set()     # e.g. {"192.168.1.10", "192.168.1.11"}
 
# ─── Detection state ──────────────────────────────────────────────────────────
syn_tracker  = defaultdict(list)   # src_ip -> [timestamps]
icmp_tracker = defaultdict(list)   # src_ip -> [timestamps]
udp_tracker  = defaultdict(list)   # src_ip -> [timestamps]
port_tracker = defaultdict(dict)   # src_ip -> {dst_port: last_seen_ts}
_last_alert  = {}                  # (src_ip, alert_type) -> last_alert_ts
 
 
def reset_state():
    """Clear all detection memory. Call this from the GUI's Clear Log so the
    detector doesn't keep counting from stale state after the user resets."""
    syn_tracker.clear()
    icmp_tracker.clear()
    udp_tracker.clear()
    port_tracker.clear()
    _last_alert.clear()
 
 
# ─── Helpers ──────────────────────────────────────────────────────────────────
def _prune_times(tracker, src_ip, now):
    """Drop timestamps older than the window."""
    tracker[src_ip] = [t for t in tracker[src_ip] if now - t < TIME_WINDOW]
 
 
def _prune_ports(src_ip, now):
    """Drop ports not seen within the window — makes the port scan check
    time-bounded instead of accumulating forever like the original set did."""
    ports = port_tracker[src_ip]
    for p in [p for p, ts in ports.items() if now - ts >= TIME_WINDOW]:
        del ports[p]
 
 
def _should_alert(src_ip, alert_type, now):
    """Cooldown gate. Returns True only if this (source, type) hasn't alerted
    within ALERT_COOLDOWN seconds. Updates the timestamp when it fires."""
    key = (src_ip, alert_type)
    if now - _last_alert.get(key, 0) >= ALERT_COOLDOWN:
        _last_alert[key] = now
        return True
    return False
 
 
def _emit(msg, app):
    app.log_alert(msg)
    file_log(msg)
 
 
def _is_ignored(src_ip):
    """Skip trusted hosts and non-unicast sources. Real attack traffic comes
    from unicast addresses; multicast/unspecified/reserved sources are almost
    always benign protocol chatter and a common source of false positives."""
    if src_ip in TRUSTED_IPS:
        return True
    try:
        ip = ipaddress.ip_address(src_ip)
        if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return True
    except ValueError:
        pass
    return False
 
 
# ─── Checks ───────────────────────────────────────────────────────────────────
def _check_syn_flood(packet, src_ip, now, app):
    if TCP in packet and packet[TCP].flags == 0x002:   # pure SYN, no ACK
        _prune_times(syn_tracker, src_ip, now)
        syn_tracker[src_ip].append(now)
        count = len(syn_tracker[src_ip])
        if count > SYN_THRESHOLD and _should_alert(src_ip, "SYN", now):
            _emit(f"SYN FLOOD detected from {src_ip} "
                  f"({count} SYNs in {TIME_WINDOW}s)", app)
 
 
def _check_icmp_flood(packet, src_ip, now, app):
    if ICMP in packet:
        _prune_times(icmp_tracker, src_ip, now)
        icmp_tracker[src_ip].append(now)
        count = len(icmp_tracker[src_ip])
        if count > ICMP_THRESHOLD and _should_alert(src_ip, "ICMP", now):
            _emit(f"ICMP FLOOD detected from {src_ip} "
                  f"({count} packets in {TIME_WINDOW}s)", app)
 
 
def _check_udp_flood(packet, src_ip, now, app):
    if UDP in packet:
        _prune_times(udp_tracker, src_ip, now)
        udp_tracker[src_ip].append(now)
        count = len(udp_tracker[src_ip])
        if count > UDP_THRESHOLD and _should_alert(src_ip, "UDP", now):
            _emit(f"UDP FLOOD detected from {src_ip} "
                  f"({count} UDP packets in {TIME_WINDOW}s)", app)
 
 
def _check_port_scan(packet, src_ip, now, app):
    if TCP in packet:
        ports = port_tracker[src_ip]
        ports[packet[TCP].dport] = now
        _prune_ports(src_ip, now)
        count = len(ports)
        if count > PORT_THRESHOLD and _should_alert(src_ip, "PORTSCAN", now):
            _emit(f"PORT SCAN detected from {src_ip} "
                  f"({count} unique ports in {TIME_WINDOW}s)", app)
 
 
def _check_suspicious_port(packet, src_ip, now, app):
    if TCP in packet:
        dport = packet[TCP].dport
        if dport in SUSPICIOUS_PORTS:
            # Cooldown keyed per port: each odd port reports once per cooldown
            # instead of once per packet (the original fired on every packet).
            if _should_alert(src_ip, f"SUSPPORT:{dport}", now):
                _emit(f"SUSPICIOUS PORT traffic from {src_ip} -> port {dport}", app)
 
 
# ─── Entry point ──────────────────────────────────────────────────────────────
def detect(packet, app):
    if IP not in packet:
        return
    src_ip = packet[IP].src
    if _is_ignored(src_ip):
        return
    now = time.time()
    _check_syn_flood(packet, src_ip, now, app)
    _check_icmp_flood(packet, src_ip, now, app)
    _check_port_scan(packet, src_ip, now, app)
    _check_udp_flood(packet, src_ip, now, app)
    _check_suspicious_port(packet, src_ip, now, app)