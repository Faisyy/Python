#!/usr/bin/env python3
import argparse
import random

from common import add_common_args, positive_int, warn_if_not_root
from scapy.all import IP, TCP, RandShort, send


def main():
    parser = argparse.ArgumentParser(
        description="Generate controlled SYN-heavy lab traffic for IDS testing."
    )
    add_common_args(parser)
    parser.add_argument("--port", type=positive_int, default=80, help="Destination TCP port.")
    parser.add_argument("--count", type=positive_int, default=130, help="Number of SYN packets.")
    parser.add_argument("--interval", type=float, default=0.01, help="Delay between packets.")
    args = parser.parse_args()

    warn_if_not_root()

    print(f"Sending {args.count} SYN packets to {args.target}:{args.port}")
    for _ in range(args.count):
        packet = IP(dst=args.target) / TCP(
            sport=RandShort(),
            dport=args.port,
            seq=random.randint(1000, 999999),
            flags="S",
        )
        send(packet, verbose=False, inter=args.interval)
    print("Done. Expected IDS alert: DoS Detected: SYN Flood behaviour.")


if __name__ == "__main__":
    main()
