#!/usr/bin/env python3
import argparse

from common import add_common_args, positive_int, warn_if_not_root
from scapy.all import IP, TCP, RandShort, send


FLAG_MAP = {
    "fin": "F",
    "null": 0,
    "xmas": "FPU",
}


def main():
    parser = argparse.ArgumentParser(
        description="Generate FIN, NULL, or XMAS TCP flag scan packets for IDS testing."
    )
    add_common_args(parser)
    parser.add_argument(
        "--scan",
        choices=["fin", "null", "xmas", "all"],
        default="all",
        help="TCP flag scan pattern to send.",
    )
    parser.add_argument("--port", type=positive_int, default=80, help="Destination TCP port.")
    parser.add_argument("--repeat", type=positive_int, default=1, help="Packets per scan type.")
    parser.add_argument("--interval", type=float, default=0.05, help="Delay between packets.")
    args = parser.parse_args()

    warn_if_not_root()

    scan_names = list(FLAG_MAP) if args.scan == "all" else [args.scan]
    for scan_name in scan_names:
        print(f"Sending {args.repeat} {scan_name.upper()} scan packet(s) to {args.target}:{args.port}")
        for _ in range(args.repeat):
            packet = IP(dst=args.target) / TCP(
                sport=RandShort(),
                dport=args.port,
                flags=FLAG_MAP[scan_name],
            )
            send(packet, verbose=False, inter=args.interval)
    print("Done. Expected IDS alert: TCP Flag Scan Detected.")


if __name__ == "__main__":
    main()
