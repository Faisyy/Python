import customtkinter as ctk
from tkinter import filedialog
import threading
from logger import init_logger, log_info
from detector import reset_state

# Theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")




class IDSApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Python-Based IDS - Group 8A")
        self.geometry("900x650")
        self.resizable(False, False)
        self.is_sniffing = False
        self.packet_count = 0
        self.alert_count = 0
        self.adapter_map = {}
        self._build_ui()
        self.refresh_adapters()
        self.log_file = init_logger()        
        self._log(f"[*] Logging to: {self.log_file}")

    def _build_ui(self):
        # Title bar
        title_frame = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=0)
        title_frame.pack(fill="x", pady=(0, 5))
        ctk.CTkLabel(
            title_frame,
            text="Python-Based Intrusion Detection System",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#00d4ff"
        ).pack(side="left", padx=20, pady=12)
        ctk.CTkLabel(
            title_frame, text="Group 8A",
            font=ctk.CTkFont(size=12), text_color="#888888"
        ).pack(side="right", padx=20)

        # Stats bar
        stats_frame = ctk.CTkFrame(self, corner_radius=8)
        stats_frame.pack(fill="x", padx=15, pady=(0, 8))
        self.lbl_packets = ctk.CTkLabel(
            stats_frame, text="Packets Captured: 0",
            font=ctk.CTkFont(size=13)
        )
        self.lbl_packets.pack(side="left", padx=20, pady=8)
        self.lbl_alerts = ctk.CTkLabel(
            stats_frame, text="Alerts: 0",
            font=ctk.CTkFont(size=13), text_color="#ff6b6b"
        )
        self.lbl_alerts.pack(side="left", padx=20)
        self.lbl_status = ctk.CTkLabel(
            stats_frame, text="Status: Idle",
            font=ctk.CTkFont(size=13), text_color="#888888"
        )
        self.lbl_status.pack(side="right", padx=20)

        # Network adapter selector
        adapter_frame = ctk.CTkFrame(self, corner_radius=8)
        adapter_frame.pack(fill="x", padx=15, pady=(0, 8))
        ctk.CTkLabel(
            adapter_frame,
            text="Sniff Adapter",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left", padx=(15, 8), pady=8)
        self.adapter_combo = ctk.CTkComboBox(
            adapter_frame,
            width=610,
            values=["Scanning adapters..."],
            state="readonly"
        )
        self.adapter_combo.pack(side="left", padx=8, pady=8)
        self.btn_refresh_adapters = ctk.CTkButton(
            adapter_frame,
            text="Refresh",
            width=100,
            fg_color="#3a3a3a",
            hover_color="#4a4a4a",
            command=self.refresh_adapters
        )
        self.btn_refresh_adapters.pack(side="right", padx=15, pady=8)

        # Detection coverage label
        self.lbl_coverage = ctk.CTkLabel(
            self,
            text=(
                "Detection Coverage: DoS | Port Scan | TCP Flag Scan | "
                "Possible Reverse Shell | ARP Spoofing/MITM"
            ),
            font=ctk.CTkFont(size=11),
            text_color="#b8c7d9"
        )
        self.lbl_coverage.pack(anchor="w", padx=18, pady=(0, 6))

        # Alert log
        self.progress_bar = ctk.CTkProgressBar(self, width=870)
        self.progress_bar.pack(padx=15, pady=(0, 5))
        self.progress_bar.set(0)
        ctk.CTkLabel(
            self, text="Alert Log", font=ctk.CTkFont(size=13, weight="bold")
        ).pack(anchor="w", padx=18, pady=(0, 2))
        self.alert_box = ctk.CTkTextbox(
            self, width=870, height=340,
            font=ctk.CTkFont(family="Courier New", size=12),
            fg_color="#0d0d0d", text_color="#00ff88", corner_radius=8
        )
        self.alert_box.pack(padx=15, pady=(0, 10))
        self.alert_box.configure(state="disabled")
        self._log("IDS ready. Load a PCAP file or start live sniffing.")

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=(0, 12))
        self.btn_start = ctk.CTkButton(
            btn_frame, text="Start Live Sniff", width=180,
            fg_color="#1f6f3a", hover_color="#27913f",
            command=self.start_sniffing
        )
        self.btn_start.pack(side="left", padx=10)
        self.btn_stop = ctk.CTkButton(
            btn_frame, text="Stop", width=120,
            fg_color="#7a1f1f", hover_color="#a02525",
            state="disabled", command=self.stop_sniffing
        )
        self.btn_stop.pack(side="left", padx=10)
        self.btn_pcap = ctk.CTkButton(
            btn_frame, text="Load PCAP", width=150,
            fg_color="#1a3a6f", hover_color="#1f4a8f",
            command=self.load_pcap
        )
        self.btn_pcap.pack(side="left", padx=10)
        self.btn_clear = ctk.CTkButton(
            btn_frame, text="Clear Log", width=130,
            fg_color="#3a3a3a", hover_color="#4a4a4a",
            command=self.clear_log
        )
        self.btn_clear.pack(side="left", padx=10)

    def _log(self, message):
        self.alert_box.configure(state="normal")
        self.alert_box.insert("end", f"{message}\n")
        self.alert_box.see("end")
        self.alert_box.configure(state="disabled")

    def log_alert(self, message):
        """Called by detector.py to push an alert into the GUI."""
        self.alert_count += 1
        self.lbl_alerts.configure(text=f"Alerts: {self.alert_count}")
        self._log(f"[ALERT] {message}")

    def increment_packets(self):
        """Called by sniffer.py for every packet processed."""
        self.packet_count += 1
        self.lbl_packets.configure(text=f"Packets Captured: {self.packet_count}")

    def set_progress(self, value):
        self.progress_bar.set(value)
        self.update_idletasks()

    def start_progress_animation(self):
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

    def stop_progress_animation(self):
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1.0)

    def refresh_adapters(self):
        from sniffer import list_adapters

        try:
            adapters = list_adapters()
        except Exception as exc:
            self.adapter_map = {}
            self.adapter_combo.configure(values=["Adapter scan failed"])
            self.adapter_combo.set("Adapter scan failed")
            self._log(f"[ERROR] Could not scan adapters: {exc}")
            return

        if not adapters:
            self.adapter_map = {}
            self.adapter_combo.configure(values=["No adapters found"])
            self.adapter_combo.set("No adapters found")
            self._log("[ERROR] No sniff adapters found.")
            return

        self.adapter_map = {adapter["label"]: adapter["value"] for adapter in adapters}
        labels = list(self.adapter_map.keys())
        self.adapter_combo.configure(values=labels)

        current = self.adapter_combo.get()
        if current not in self.adapter_map:
            preferred = self._preferred_adapter_label(labels)
            self.adapter_combo.set(preferred)
        self._log(f"[*] Found {len(labels)} sniff adapter(s).")

    def _preferred_adapter_label(self, labels):
        for label in labels:
            lower = label.lower()
            if any(token in lower for token in ("virtualbox", "vmware", "host-only", "ethernet")):
                return label
        return labels[0]

    def selected_adapter(self):
        label = self.adapter_combo.get()
        return label, self.adapter_map.get(label)

    def start_sniffing(self):
        if self.is_sniffing:
            return
        adapter_label, adapter_value = self.selected_adapter()
        if not adapter_value:
            self._log("[ERROR] Select a sniff adapter before starting live sniff.")
            return
        self.is_sniffing = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.adapter_combo.configure(state="disabled")
        self.btn_refresh_adapters.configure(state="disabled")
        self.lbl_status.configure(text="Status: Sniffing...", text_color="#00ff88")
        self._log(f"[*] Live sniffing started on: {adapter_label}")
        
        from sniffer import start_sniff
        sniff_thread = threading.Thread(target=start_sniff, args=(self, adapter_value), daemon=True)
        sniff_thread.start()

    def stop_sniffing(self):
        self.is_sniffing = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.adapter_combo.configure(state="readonly")
        self.btn_refresh_adapters.configure(state="normal")
        self.lbl_status.configure(text="Status: Stopped", text_color="#ff6b6b")
        self._log("[*] Sniffing stopped.")
        
        from sniffer import stop_sniff
        stop_sniff()

    def load_pcap(self):
        filepath = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if filepath:
            self._log(f"[*] Loading PCAP: {filepath}")
            self.lbl_status.configure(text="Status: Analysing...", text_color="#ffaa00")
            self.btn_stop.configure(state="normal")

            from sniffer import analyse_pcap
            analyse_thread = threading.Thread(target=analyse_pcap, args=(filepath, self), daemon=True)
            analyse_thread.start()

    def clear_log(self):
        self.alert_box.configure(state="normal")
        self.alert_box.delete("1.0", "end")
        self.alert_box.configure(state="disabled")
        self.packet_count = 0
        self.alert_count = 0
        self.lbl_packets.configure(text="Packets Captured: 0")
        self.lbl_alerts.configure(text="Alerts: 0")
        self.lbl_status.configure(text="Status: Idle", text_color="#888888")
        self._log("Log cleared. IDS ready.")
        self.progress_bar.set(0)
        reset_state()


if __name__ == "__main__":
    app = IDSApp()
    app.mainloop()
