import argparse
import ipaddress
import os


PRIVATE_TARGET_HELP = "Private lab target IP address, for example 192.168.0.137"


def positive_int(value):
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def validate_lab_target(target):
    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IP address: {target}") from exc

    if not (ip.is_private or ip.is_loopback):
        raise argparse.ArgumentTypeError(
            "target must be a private or loopback lab IP address"
        )
    return target


def warn_if_not_root():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Warning: Scapy packet sending usually requires sudo/root privileges.")


def add_common_args(parser, target=True):
    if target:
        parser.add_argument("--target", required=True, type=validate_lab_target, help=PRIVATE_TARGET_HELP)
    return parser

