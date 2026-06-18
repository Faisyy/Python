#!/usr/bin/env python3
import argparse

from common import add_common_args, positive_int, require_lab_confirmation, warn_if_not_root
from scapy.all import IP, TCP, RandShort, send


def main():
    parser = argparse.ArgumentParser(
        description="Send suspicious-port TCP traffic for possible reverse-shell indicator testing."
    )
    add_common_args(parser)
    parser.add_argument(
        "--port",
        type=positive_int,
        default=4444,
        help="Suspicious destination port. Default matches IDS rule.",
    )
    parser.add_argument("--count", type=positive_int, default=3, help="Number of TCP SYN packets.")
    parser.add_argument("--interval", type=float, default=0.05, help="Delay between packets.")
    args = parser.parse_args()

    require_lab_confirmation(args)
    warn_if_not_root()

    print(f"Sending {args.count} TCP SYN packet(s) to suspicious port {args.target}:{args.port}")
    packet = IP(dst=args.target) / TCP(sport=RandShort(), dport=args.port, flags="S")
    send(packet, count=args.count, inter=args.interval, verbose=False)
    print("Done. Expected IDS alert: Possible Reverse Shell Indicator.")
    print("Note: this script does not create a reverse shell.")


if __name__ == "__main__":
    main()
