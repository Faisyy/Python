from scapy.all import PcapReader, sniff
import threading
from detector import detect

# ─── Sniff Control ────────────────────────────────────────────────────────────
_sniff_thread = None
_stop_flag = threading.Event()


def _process_packet(packet, app):
    """Callback fired for every captured packet."""
    app.increment_packets()
    detect(packet, app)


# ─── Live Sniffing ────────────────────────────────────────────────────────────
def start_sniff(app):
    """Start live packet capture on all interfaces. Must run as Administrator."""
    _stop_flag.clear()

    def _sniff():
        sniff(
            prn=lambda pkt: _process_packet(pkt, app),
            store=False,
            stop_filter=lambda _: _stop_flag.is_set()
        )

    global _sniff_thread
    _sniff_thread = threading.Thread(target=_sniff, daemon=True)
    _sniff_thread.start()


def stop_sniff():
    """Signal the sniffer to stop."""
    _stop_flag.set()


# ─── PCAP Analysis ────────────────────────────────────────────────────────────
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
