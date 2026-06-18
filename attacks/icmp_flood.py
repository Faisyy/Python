#!/usr/bin/env python3
import argparse

from common import add_common_args, positive_int, warn_if_not_root
from scapy.all import ICMP, IP, send


def main():
    parser = argparse.ArgumentParser(
        description="Generate controlled ICMP echo traffic for IDS testing."
    )
    add_common_args(parser)
    parser.add_argument("--count", type=positive_int, default=70, help="Number of ICMP packets.")
    parser.add_argument("--interval", type=float, default=0.01, help="Delay between packets.")
    args = parser.parse_args()

    warn_if_not_root()

    print(f"Sending {args.count} ICMP echo packets to {args.target}")
    packet = IP(dst=args.target) / ICMP()
    send(packet, count=args.count, inter=args.interval, verbose=False)
    print("Done. Expected IDS alert: DoS Detected: ICMP Flood behaviour.")


if __name__ == "__main__":
    main()
