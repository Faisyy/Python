from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict
from logger import log_alert as file_log
import time

# ─── Tracking State ───────────────────────────────────────────────────────────
syn_tracker   = defaultdict(list)
icmp_tracker  = defaultdict(list)
port_tracker  = defaultdict(set)
udp_tracker   = defaultdict(list)

# ─── Thresholds ───────────────────────────────────────────────────────────────
TIME_WINDOW     = 5
SYN_THRESHOLD   = 100
ICMP_THRESHOLD  = 5
PORT_THRESHOLD  = 15
UDP_THRESHOLD   = 100

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 9001, 8080}


def _cleanup(tracker, src_ip, now):
    tracker[src_ip] = [t for t in tracker[src_ip] if now - t < TIME_WINDOW]


def _check_syn_flood(packet, src_ip, now, app):
    if TCP in packet and packet[TCP].flags == 0x002:
        _cleanup(syn_tracker, src_ip, now)
        syn_tracker[src_ip].append(now)
        if len(syn_tracker[src_ip]) > SYN_THRESHOLD:
            msg = f"SYN FLOOD detected from {src_ip} ({len(syn_tracker[src_ip])} SYNs in {TIME_WINDOW}s)"
            app.log_alert(msg)
            file_log(msg)
            syn_tracker[src_ip].clear()


def _check_icmp_flood(packet, src_ip, now, app):
    if ICMP in packet:
        _cleanup(icmp_tracker, src_ip, now)
        icmp_tracker[src_ip].append(now)
        if len(icmp_tracker[src_ip]) > ICMP_THRESHOLD:
            msg = f"ICMP FLOOD detected from {src_ip} ({len(icmp_tracker[src_ip])} packets in {TIME_WINDOW}s)"
            app.log_alert(msg)
            file_log(msg)
            icmp_tracker[src_ip].clear()


def _check_port_scan(packet, src_ip, now, app):
    if TCP in packet:
        dst_port = packet[TCP].dport
        port_tracker[src_ip].add(dst_port)
        if len(port_tracker[src_ip]) > PORT_THRESHOLD:
            msg = f"PORT SCAN detected from {src_ip} ({len(port_tracker[src_ip])} unique ports scanned)"
            app.log_alert(msg)
            file_log(msg)
            port_tracker[src_ip].clear()


def _check_udp_flood(packet, src_ip, now, app):
    if UDP in packet:
        _cleanup(udp_tracker, src_ip, now)
        udp_tracker[src_ip].append(now)
        if len(udp_tracker[src_ip]) > UDP_THRESHOLD:
            msg = f"UDP FLOOD detected from {src_ip} ({len(udp_tracker[src_ip])} UDP packets in {TIME_WINDOW}s)"
            app.log_alert(msg)
            file_log(msg)
            udp_tracker[src_ip].clear()


def _check_suspicious_port(packet, src_ip, app):
    if TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port in SUSPICIOUS_PORTS:
            msg = f"SUSPICIOUS PORT traffic from {src_ip} -> port {dst_port}"
            app.log_alert(msg)
            file_log(msg)


def detect(packet, app):
    if IP not in packet:
        return
    src_ip = packet[IP].src
    now = time.time()
    _check_syn_flood(packet, src_ip, now, app)
    _check_icmp_flood(packet, src_ip, now, app)
    _check_port_scan(packet, src_ip, now, app)
    _check_udp_flood(packet, src_ip, now, app)
    _check_suspicious_port(packet, src_ip, app)