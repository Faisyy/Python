#!/usr/bin/env python3
import argparse

from common import add_common_args, positive_int, warn_if_not_root
from scapy.all import IP, UDP, Raw, send


def main():
    parser = argparse.ArgumentParser(
        description="Generate controlled UDP-heavy lab traffic for IDS testing."
    )
    add_common_args(parser)
    parser.add_argument("--port", type=positive_int, default=5353, help="Destination UDP port.")
    parser.add_argument("--count", type=positive_int, default=130, help="Number of UDP packets.")
    parser.add_argument("--interval", type=float, default=0.01, help="Delay between packets.")
    args = parser.parse_args()

    warn_if_not_root()

    print(f"Sending {args.count} UDP packets to {args.target}:{args.port}")
    packet = IP(dst=args.target) / UDP(dport=args.port) / Raw(load=b"ids-lab-udp")
    send(packet, count=args.count, inter=args.interval, verbose=False)
    print("Done. Expected IDS alert: DoS Detected: UDP Flood behaviour.")


if __name__ == "__main__":
    main()
