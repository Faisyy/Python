import threading

from scapy.all import PcapReader, get_if_list, sniff

from detector import detect

_sniff_thread = None
_stop_flag = threading.Event()


def list_adapters():
    """Return Scapy sniffable adapters as display/value dictionaries."""
    try:
        from scapy.arch.windows import get_windows_if_list

        adapters = []
        for iface in get_windows_if_list():
            guid = iface.get("guid")
            name = iface.get("name") or "Unknown"
            description = iface.get("description") or ""
            ips = ", ".join(iface.get("ips") or [])
            value = f"\\Device\\NPF_{guid}" if guid else name

            label_parts = [name]
            if description and description != name:
                label_parts.append(description)
            if ips:
                label_parts.append(ips)
            adapters.append({"label": " | ".join(label_parts), "value": value})

        if adapters:
            return adapters
    except Exception:
        pass

    return [{"label": iface, "value": iface} for iface in get_if_list()]


def _process_packet(packet, app):
    """Callback fired for every captured packet."""
    app.increment_packets()
    detect(packet, app)


def start_sniff(app, iface=None):
    """Start live packet capture. Must run as Administrator on Windows."""
    _stop_flag.clear()

    def _sniff():
        try:
            sniff(
                iface=iface or None,
                prn=lambda pkt: _process_packet(pkt, app),
                store=False,
                stop_filter=lambda _: _stop_flag.is_set(),
            )
        except Exception as exc:
            app._log(f"[ERROR] Live sniff failed: {exc}")
            app.lbl_status.configure(text="Status: Sniff error", text_color="#ff6b6b")

    global _sniff_thread
    _sniff_thread = threading.Thread(target=_sniff, daemon=True)
    _sniff_thread.start()


def stop_sniff():
    """Signal the sniffer to stop."""
    _stop_flag.set()


def analyse_pcap(filepath, app):
    try:
        app._log("[*] Starting analysis...")
        app.start_progress_animation()

        count = 0
        with PcapReader(filepath) as reader:
            for packet in reader:
                if _stop_flag.is_set():
                    break
                _process_packet(packet, app)
                count += 1
                if count % 1000 == 0:
                    app._log(f"[*] Processed {count} packets...")

        app.stop_progress_animation()
        app._log(f"[*] Analysis complete. {count} packets processed.")
        app.lbl_status.configure(text="Status: Done", text_color="#00d4ff")

    except Exception as e:
        app.stop_progress_animation()
        app._log(f"[ERROR] {e}")
        app.lbl_status.configure(text="Status: Error", text_color="#ff6b6b")
