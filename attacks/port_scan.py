#!/usr/bin/env python3
import argparse

from common import add_common_args, positive_int, require_lab_confirmation, warn_if_not_root
from scapy.all import IP, TCP, RandShort, send


def main():
    parser = argparse.ArgumentParser(
        description="Generate controlled multi-port SYN traffic for IDS port-scan testing."
    )
    add_common_args(parser)
    parser.add_argument("--start-port", type=positive_int, default=20, help="First destination port.")
    parser.add_argument("--ports", type=positive_int, default=20, help="Number of unique ports.")
    parser.add_argument("--interval", type=float, default=0.02, help="Delay between packets.")
    args = parser.parse_args()

    require_lab_confirmation(args)
    warn_if_not_root()

    end_port = args.start_port + args.ports - 1
    print(f"Sending SYN probes to {args.target} ports {args.start_port}-{end_port}")
    for port in range(args.start_port, args.start_port + args.ports):
        packet = IP(dst=args.target) / TCP(sport=RandShort(), dport=port, flags="S")
        send(packet, verbose=False, inter=args.interval)
    print("Done. Expected IDS alert: PORT SCAN detected.")


if __name__ == "__main__":
    main()
