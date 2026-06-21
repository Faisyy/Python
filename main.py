import csv
from collections import Counter
from datetime import datetime
import os
import re
import subprocess
import sys
import threading
import time
from tkinter import Canvas, filedialog, ttk

import customtkinter as ctk

import detector
from logger import init_logger

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class IDSApp(ctk.CTk):
    # Initialize app state, build the GUI, and start periodic updates.
    def __init__(self):
        super().__init__()
        self.title("Python-Based IDS")
        self.geometry("1120x760")
        self.minsize(1060, 620)
        self.resizable(True, True)

        self.is_sniffing = False
        self.packet_count = 0
        self.alert_count = 0
        self.adapter_map = {}
        self.ui_thread_id = threading.get_ident()
        self.alert_records = []
        self.next_alert_id = 1
        self.source_counts = Counter()
        self.source_last_type = {}
        self.packet_rate_history = [0] * 30
        self.current_second_packets = 0
        self.current_pps = 0
        self.last_packet_time = "-"
        self.last_packet_epoch = 0
        self.session_started_at = None
        self.session_summary_autosaved = False
        self.sound_enabled = ctk.BooleanVar(value=True)
        self.sound_file = os.path.join(os.path.dirname(__file__), "amongus.mp3")
        self.high_severity_sound_file = os.path.join(os.path.dirname(__file__), "vineboom.mp3")
        self.sound_duration_ms = 1800
        self.last_sound_at = 0
        self.last_high_sound_at = 0
        self.high_alert_overlay = None
        self.alert_filter_severity = ctk.StringVar(value="All")
        self.alert_filter_type = ctk.StringVar(value="All")
        self.review_status_var = ctk.StringVar(value="Needs Review")
        self.pcap_replay_speed = ctk.StringVar(value="Fast")
        self.alert_categories = {
            "DoS": 0,
            "Port Scan": 0,
            "TCP Flag": 0,
            "Reverse Shell": 0,
            "ARP/MITM": 0,
            "Other": 0,
        }
        self.category_colors = {
            "DoS": "#38bdf8",
            "Port Scan": "#facc15",
            "TCP Flag": "#a78bfa",
            "Reverse Shell": "#fb7185",
            "ARP/MITM": "#34d399",
            "Other": "#94a3b8",
        }
        self.category_labels = {}
        self.source_labels = []
        self.rule_vars = {}
        self.threshold_entries = {}

        self._build_ui()
        self.refresh_adapters()
        self.log_file = init_logger()
        self._log(f"[*] Logging to: {self.log_file}")
        self.after(1000, self._update_packet_rate)
        self.after(1000, self._update_session_status)

    # Build all visual sections, tabs, controls, and action buttons.
    def _build_ui(self):
        self.configure(fg_color="#0b1020")
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(self, fg_color="#10172a", corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header_text = ctk.CTkFrame(header, fg_color="transparent")
        header_text.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(
            header_text,
            text="Python-Based Intrusion Detection System",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#e5f3ff",
        ).pack(anchor="w", padx=24, pady=(16, 2))
        ctk.CTkLabel(
            header_text,
            text="Live packet monitoring, PCAP analysis, and rule-based alerting",
            font=ctk.CTkFont(size=12),
            text_color="#8ea4c2",
        ).pack(anchor="w", padx=24, pady=(0, 16))

        sound_header = ctk.CTkFrame(header, fg_color="transparent")
        sound_header.pack(side="right", padx=24, pady=14)
        self.sound_switch = ctk.CTkSwitch(
            sound_header,
            text="Sound Alert",
            variable=self.sound_enabled,
            onvalue=True,
            offvalue=False,
            progress_color="#38bdf8",
            button_color="#e2e8f0",
            text_color="#e2e8f0",
        )
        self.sound_switch.pack(side="left", padx=(0, 8))
        self.btn_choose_sound = ctk.CTkButton(
            sound_header,
            text="📢",
            width=38,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self.choose_sound_file,
        )
        self.btn_choose_sound.pack(side="left")
        sound_header.pack_forget()

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_rowconfigure(6, weight=1)
        content.grid_columnconfigure(0, weight=1)

        stats_frame = ctk.CTkFrame(content, fg_color="#111827", corner_radius=8)
        stats_frame.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 10))

        self.lbl_packets = self._metric_label(stats_frame, "Packets Captured: 0", "#7dd3fc")
        self.lbl_packets.pack(side="left", padx=(18, 12), pady=12)

        self.lbl_alerts = self._metric_label(stats_frame, "Alerts: 0", "#fca5a5")
        self.lbl_alerts.pack(side="left", padx=12, pady=12)

        self.lbl_timer = self._metric_label(stats_frame, "Runtime: 00:00:00", "#c4b5fd")
        self.lbl_timer.pack(side="left", padx=12, pady=12)

        self.lbl_health = self._metric_label(stats_frame, "Health: Idle", "#cbd5e1")
        self.lbl_health.pack(side="left", padx=12, pady=12)

        self.lbl_status = self._metric_label(stats_frame, "Status: Idle", "#cbd5e1")
        self.lbl_status.pack(side="right", padx=18, pady=12)

        adapter_frame = ctk.CTkFrame(content, fg_color="#111827", corner_radius=8)
        adapter_frame.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))
        ctk.CTkLabel(
            adapter_frame,
            text="Sniff Adapter",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#dbeafe",
        ).pack(side="left", padx=(18, 10), pady=12)

        self.adapter_combo = ctk.CTkComboBox(
            adapter_frame,
            width=620,
            height=34,
            values=["Scanning adapters..."],
            state="readonly",
            fg_color="#0f172a",
            border_color="#334155",
            button_color="#1d4ed8",
            button_hover_color="#2563eb",
            dropdown_fg_color="#111827",
            dropdown_hover_color="#1e293b",
        )
        self.adapter_combo.pack(side="left", fill="x", expand=True, padx=8, pady=12)

        self.btn_refresh_adapters = ctk.CTkButton(
            adapter_frame,
            text="Refresh",
            width=110,
            height=34,
            fg_color="#334155",
            hover_color="#475569",
            command=self.refresh_adapters,
        )
        self.btn_refresh_adapters.pack(side="right", padx=18, pady=12)

        self.lbl_coverage = ctk.CTkLabel(
            content,
            text=(
                "Detection Coverage: DoS | Port Scan | TCP Flag Scan | "
                "Possible Reverse Shell | ARP Spoofing/MITM"
            ),
            font=ctk.CTkFont(size=12),
            text_color="#93c5fd",
        )
        self.lbl_coverage.grid(row=2, column=0, sticky="w", padx=22, pady=(0, 10))

        dashboard = ctk.CTkFrame(content, fg_color="#111827", corner_radius=8)
        dashboard.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 10))

        counter_panel = ctk.CTkFrame(dashboard, fg_color="transparent")
        counter_panel.pack(side="left", fill="both", expand=True, padx=14, pady=12)
        ctk.CTkLabel(
            counter_panel,
            text="Attack Dashboard",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0",
        ).pack(anchor="w", pady=(0, 8))

        category_grid = ctk.CTkFrame(counter_panel, fg_color="transparent")
        category_grid.pack(fill="x")
        for index, category in enumerate(self.alert_categories):
            tile = ctk.CTkFrame(category_grid, fg_color="#0f172a", corner_radius=6)
            tile.grid(row=index // 3, column=index % 3, sticky="ew", padx=4, pady=4)
            category_grid.grid_columnconfigure(index % 3, weight=1)
            ctk.CTkLabel(
                tile,
                text=category,
                font=ctk.CTkFont(size=11),
                text_color=self.category_colors[category],
            ).pack(anchor="w", padx=10, pady=(8, 0))
            value_label = ctk.CTkLabel(
                tile,
                text="0",
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color="#f8fafc",
            )
            value_label.pack(anchor="w", padx=10, pady=(0, 8))
            self.category_labels[category] = value_label

        chart_panel = ctk.CTkFrame(dashboard, fg_color="#0f172a", corner_radius=8)
        chart_panel.pack(side="right", padx=14, pady=12)
        ctk.CTkLabel(
            chart_panel,
            text="Alert Mix",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1",
        ).pack(pady=(8, 0))
        self.chart_canvas = Canvas(
            chart_panel,
            width=170,
            height=130,
            bg="#0f172a",
            highlightthickness=0,
        )
        self.chart_canvas.pack(padx=10, pady=(0, 8))
        self._draw_dashboard()

        ops_frame = ctk.CTkFrame(content, fg_color="#111827", corner_radius=8)
        ops_frame.grid(row=4, column=0, sticky="ew", padx=18, pady=(0, 10))
        ops_frame.grid_columnconfigure(0, weight=1)
        ops_frame.grid_columnconfigure(1, weight=1)
        ops_frame.grid_columnconfigure(2, weight=1)

        rate_panel = ctk.CTkFrame(ops_frame, fg_color="#0f172a", corner_radius=8)
        rate_panel.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        ctk.CTkLabel(
            rate_panel,
            text="Packets Per Second",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1",
        ).pack(anchor="w", padx=12, pady=(10, 0))
        self.pps_canvas = Canvas(rate_panel, width=250, height=82, bg="#0f172a", highlightthickness=0)
        self.pps_canvas.pack(fill="x", padx=10, pady=(0, 8))
        self._draw_packet_rate_graph()

        diagnostic_panel = ctk.CTkFrame(ops_frame, fg_color="#0f172a", corner_radius=8)
        diagnostic_panel.grid(row=0, column=1, sticky="nsew", padx=6, pady=12)
        ctk.CTkLabel(
            diagnostic_panel,
            text="Adapter Diagnostics",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1",
        ).pack(anchor="w", padx=12, pady=(10, 4))
        self.lbl_selected_adapter = self._small_info_label(diagnostic_panel, "Adapter: -")
        self.lbl_selected_adapter.pack(anchor="w", fill="x", padx=12, pady=1)
        self.lbl_current_pps = self._small_info_label(diagnostic_panel, "Current Rate: 0 pkt/s")
        self.lbl_current_pps.pack(anchor="w", fill="x", padx=12, pady=1)
        self.lbl_last_packet = self._small_info_label(diagnostic_panel, "Last Packet: -")
        self.lbl_last_packet.pack(anchor="w", fill="x", padx=12, pady=1)

        source_panel = ctk.CTkFrame(ops_frame, fg_color="#0f172a", corner_radius=8)
        source_panel.grid(row=0, column=2, sticky="nsew", padx=(6, 12), pady=12)
        ctk.CTkLabel(
            source_panel,
            text="Top Source IPs",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1",
        ).pack(anchor="w", padx=12, pady=(10, 4))
        for _ in range(3):
            label = self._small_info_label(source_panel, "-")
            label.pack(anchor="w", fill="x", padx=12, pady=1)
            self.source_labels.append(label)
        self._draw_top_sources()

        self.progress_bar = ctk.CTkProgressBar(
            content,
            width=920,
            height=8,
            progress_color="#38bdf8",
            fg_color="#1e293b",
        )
        self.progress_bar.grid(row=5, column=0, sticky="ew", padx=18, pady=(0, 10))
        self.progress_bar.set(0)

        log_tabs = ctk.CTkTabview(
            content,
            fg_color="#111827",
            segmented_button_fg_color="#0f172a",
            segmented_button_selected_color="#1d4ed8",
            segmented_button_selected_hover_color="#2563eb",
            segmented_button_unselected_color="#0f172a",
            segmented_button_unselected_hover_color="#1e293b",
        )
        log_tabs.grid(row=6, column=0, sticky="nsew", padx=18, pady=(0, 12))
        log_tabs.add("Alert Log")
        log_tabs.add("Recent Alerts")
        log_tabs.add("Detection Settings")
        log_tabs.add("PCAP Replay")
        log_tabs.add("Sound Settings")

        log_tab = log_tabs.tab("Alert Log")
        log_tab.grid_rowconfigure(0, weight=1)
        log_tab.grid_columnconfigure(0, weight=1)

        self.alert_box = ctk.CTkTextbox(
            log_tab,
            width=920,
            height=240,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#050816",
            text_color="#86efac",
            border_width=1,
            border_color="#1e293b",
            corner_radius=8,
        )
        self.alert_box.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        self.alert_box.configure(state="disabled")
        self._log("IDS ready. Select an adapter, load a PCAP file, or start live sniffing.")

        table_tab = log_tabs.tab("Recent Alerts")
        table_tab.grid_rowconfigure(1, weight=1)
        table_tab.grid_columnconfigure(0, weight=1)
        self._build_alert_table(table_tab)

        settings_tab = log_tabs.tab("Detection Settings")
        settings_tab.grid_columnconfigure(0, weight=1)
        self._build_settings_panel(settings_tab)

        replay_tab = log_tabs.tab("PCAP Replay")
        replay_tab.grid_columnconfigure(0, weight=1)
        self._build_replay_panel(replay_tab)

        sound_tab = log_tabs.tab("Sound Settings")
        sound_tab.grid_columnconfigure(0, weight=1)
        self._build_sound_settings_panel(sound_tab)

        btn_frame = ctk.CTkFrame(self, fg_color="#0b1020")
        btn_frame.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        button_group = ctk.CTkFrame(btn_frame, fg_color="transparent")
        button_group.pack(anchor="center")

        self.btn_start = ctk.CTkButton(
            button_group,
            text="Start Live Sniff",
            width=150,
            height=38,
            fg_color="#15803d",
            hover_color="#16a34a",
            command=self.start_sniffing,
        )
        self.btn_start.pack(side="left", padx=8)

        self.btn_stop = ctk.CTkButton(
            button_group,
            text="Stop",
            width=150,
            height=38,
            fg_color="#991b1b",
            hover_color="#b91c1c",
            state="disabled",
            command=self.stop_sniffing,
        )
        self.btn_stop.pack(side="left", padx=8)

        self.btn_pcap = ctk.CTkButton(
            button_group,
            text="Load PCAP",
            width=150,
            height=38,
            fg_color="#1d4ed8",
            hover_color="#2563eb",
            command=self.load_pcap,
        )
        self.btn_pcap.pack(side="left", padx=8)

        self.btn_clear = ctk.CTkButton(
            button_group,
            text="Clear Log",
            width=150,
            height=38,
            fg_color="#334155",
            hover_color="#475569",
            command=self.clear_log,
        )
        self.btn_clear.pack(side="left", padx=8)

        self.btn_export = ctk.CTkButton(
            button_group,
            text="Export CSV",
            width=150,
            height=38,
            fg_color="#0f766e",
            hover_color="#0d9488",
            command=self.export_alerts_csv,
        )
        self.btn_export.pack(side="left", padx=8)

        self.btn_summary = ctk.CTkButton(
            button_group,
            text="Export Summary",
            width=150,
            height=38,
            fg_color="#7c3aed",
            hover_color="#8b5cf6",
            command=self.export_session_summary,
        )
        self.btn_summary.pack(side="left", padx=8)

    # Create a reusable status metric label.
    def _metric_label(self, parent, text, color):
        return ctk.CTkLabel(
            parent,
            text=text,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=color,
            fg_color="#0f172a",
            corner_radius=6,
            padx=12,
            pady=6,
        )

    # Create a small reusable information label.
    def _small_info_label(self, parent, text):
        return ctk.CTkLabel(
            parent,
            text=text,
            font=ctk.CTkFont(size=11),
            text_color="#cbd5e1",
            anchor="w",
        )

    # Return the selected alert sound filename.
    def _sound_file_label(self):
        return os.path.basename(self.sound_file)

    # Build the recent alerts table, filters, and review controls.
    def _build_alert_table(self, parent):
        filter_bar = ctk.CTkFrame(parent, fg_color="#050816", corner_radius=8)
        filter_bar.grid(row=0, column=0, sticky="ew", padx=6, pady=(6, 0))
        ctk.CTkLabel(
            filter_bar,
            text="Severity",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1",
        ).pack(side="left", padx=(10, 6), pady=8)
        self.severity_filter_combo = ctk.CTkComboBox(
            filter_bar,
            width=120,
            values=["All", "High", "Medium", "Low"],
            variable=self.alert_filter_severity,
            state="readonly",
            command=lambda _: self.refresh_alert_table(),
        )
        self.severity_filter_combo.pack(side="left", padx=(0, 12), pady=8)
        ctk.CTkLabel(
            filter_bar,
            text="Type",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1",
        ).pack(side="left", padx=(0, 6), pady=8)
        self.type_filter_combo = ctk.CTkComboBox(
            filter_bar,
            width=150,
            values=["All"] + list(self.alert_categories.keys()),
            variable=self.alert_filter_type,
            state="readonly",
            command=lambda _: self.refresh_alert_table(),
        )
        self.type_filter_combo.pack(side="left", padx=(0, 12), pady=8)
        ctk.CTkButton(
            filter_bar,
            text="Clear Filters",
            width=110,
            height=30,
            fg_color="#334155",
            hover_color="#475569",
            command=self.clear_alert_filters,
        ).pack(side="left", padx=(0, 10), pady=8)
        ctk.CTkLabel(
            filter_bar,
            text="Review",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1",
        ).pack(side="left", padx=(0, 6), pady=8)
        self.review_status_combo = ctk.CTkComboBox(
            filter_bar,
            width=135,
            values=["Needs Review", "Confirmed", "False Positive"],
            variable=self.review_status_var,
            state="readonly",
        )
        self.review_status_combo.pack(side="left", padx=(0, 8), pady=8)
        self.review_note_entry = ctk.CTkEntry(
            filter_bar,
            width=180,
            height=30,
            placeholder_text="Note",
            fg_color="#0f172a",
            border_color="#334155",
            text_color="#e2e8f0",
        )
        self.review_note_entry.pack(side="left", padx=(0, 8), pady=8)
        ctk.CTkButton(
            filter_bar,
            text="Save Review",
            width=115,
            height=30,
            fg_color="#7c3aed",
            hover_color="#8b5cf6",
            command=self.save_alert_review,
        ).pack(side="left", padx=(0, 10), pady=8)

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "IDS.Treeview",
            background="#050816",
            foreground="#e2e8f0",
            fieldbackground="#050816",
            borderwidth=0,
            rowheight=26,
            font=("Segoe UI", 10),
        )
        style.configure(
            "IDS.Treeview.Heading",
            background="#0f172a",
            foreground="#bfdbfe",
            borderwidth=0,
            font=("Segoe UI", 10, "bold"),
        )
        style.map("IDS.Treeview", background=[("selected", "#1d4ed8")])

        columns = ("time", "severity", "type", "source", "destination", "review", "note", "details")
        self.alert_table = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            style="IDS.Treeview",
            selectmode="browse",
        )
        headings = {
            "time": "Time",
            "severity": "Severity",
            "type": "Type",
            "source": "Source",
            "destination": "Destination",
            "review": "Review",
            "note": "Note",
            "details": "Details",
        }
        widths = {
            "time": 80,
            "severity": 80,
            "type": 115,
            "source": 120,
            "destination": 120,
            "review": 115,
            "note": 140,
            "details": 360,
        }
        for column in columns:
            self.alert_table.heading(column, text=headings[column])
            self.alert_table.column(column, width=widths[column], minwidth=70, anchor="w")

        self.alert_table.tag_configure("High", foreground="#fca5a5")
        self.alert_table.tag_configure("Medium", foreground="#fde68a")
        self.alert_table.tag_configure("Low", foreground="#bfdbfe")

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.alert_table.yview)
        self.alert_table.configure(yscrollcommand=scrollbar.set)
        self.alert_table.grid(row=1, column=0, sticky="nsew", padx=(6, 0), pady=6)
        scrollbar.grid(row=1, column=1, sticky="ns", padx=(0, 6), pady=6)
        self.alert_table.bind("<<TreeviewSelect>>", self._load_selected_alert_review)

    # Build detection rule toggles and threshold settings.
    def _build_settings_panel(self, parent):
        container = ctk.CTkScrollableFrame(parent, fg_color="#050816", corner_radius=8)
        container.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        container.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(1, weight=1)

        rules_panel = ctk.CTkFrame(container, fg_color="#0f172a", corner_radius=8)
        rules_panel.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        ctk.CTkLabel(
            rules_panel,
            text="Detection Rules",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0",
        ).pack(anchor="w", padx=12, pady=(10, 6))

        rule_labels = {
            "dos": "DoS Flood Detection",
            "port_scan": "Port Scan Detection",
            "tcp_flag": "TCP Flag Scan Detection",
            "reverse_shell": "Possible Reverse Shell Indicator",
            "arp_mitm": "ARP Spoofing / MITM Indicator",
        }
        for key, label in rule_labels.items():
            var = ctk.BooleanVar(value=detector.DETECTION_ENABLED[key])
            self.rule_vars[key] = var
            switch = ctk.CTkSwitch(
                rules_panel,
                text=label,
                variable=var,
                onvalue=True,
                offvalue=False,
                progress_color="#38bdf8",
                button_color="#e2e8f0",
                text_color="#cbd5e1",
                command=lambda silent=True: self.apply_detection_settings(silent=silent),
            )
            switch.pack(anchor="w", padx=12, pady=4)

        thresholds_panel = ctk.CTkFrame(container, fg_color="#0f172a", corner_radius=8)
        thresholds_panel.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        ctk.CTkLabel(
            thresholds_panel,
            text="Threshold Settings",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0",
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(10, 6))

        threshold_fields = [
            ("time_window", "Time Window (s)", detector.TIME_WINDOW),
            ("syn_threshold", "SYN Threshold", detector.SYN_THRESHOLD),
            ("icmp_threshold", "ICMP Threshold", detector.ICMP_THRESHOLD),
            ("udp_threshold", "UDP Threshold", detector.UDP_THRESHOLD),
            ("port_threshold", "Port Threshold", detector.PORT_THRESHOLD),
            ("alert_cooldown", "Cooldown (s)", detector.ALERT_COOLDOWN),
        ]
        for row, (key, label, value) in enumerate(threshold_fields, start=1):
            ctk.CTkLabel(
                thresholds_panel,
                text=label,
                font=ctk.CTkFont(size=12),
                text_color="#cbd5e1",
            ).grid(row=row, column=0, sticky="w", padx=12, pady=4)
            entry = ctk.CTkEntry(
                thresholds_panel,
                width=90,
                height=28,
                fg_color="#050816",
                border_color="#334155",
                text_color="#e2e8f0",
            )
            entry.insert(0, str(value))
            entry.grid(row=row, column=1, sticky="e", padx=12, pady=4)
            self.threshold_entries[key] = entry

        button_row = ctk.CTkFrame(thresholds_panel, fg_color="transparent")
        button_row.grid(row=8, column=0, columnspan=2, sticky="e", padx=12, pady=(10, 12))
        ctk.CTkButton(
            button_row,
            text="Restore Defaults",
            width=130,
            height=32,
            fg_color="#334155",
            hover_color="#475569",
            command=self.restore_detection_defaults,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            button_row,
            text="Apply Settings",
            width=130,
            height=32,
            fg_color="#1d4ed8",
            hover_color="#2563eb",
            command=self.apply_detection_settings,
        ).pack(side="left")

    # Apply detection toggles and threshold values to the detector.
    def apply_detection_settings(self, silent=False):
        enabled = {key: var.get() for key, var in self.rule_vars.items()}
        thresholds = {}
        for key, entry in self.threshold_entries.items():
            raw_value = entry.get().strip()
            try:
                value = int(raw_value)
            except ValueError:
                self._log(f"[ERROR] Invalid threshold for {key}: {raw_value}")
                return
            if value <= 0:
                self._log(f"[ERROR] Threshold must be greater than 0: {key}")
                return
            thresholds[key] = value

        detector.configure_detection(enabled=enabled, thresholds=thresholds)
        detector.reset_state()
        if not silent:
            self._log("[*] Detection settings applied. Detector state reset.")

    # Restore detector rule toggles and thresholds to default values.
    def restore_detection_defaults(self):
        detector.reset_detection_config()
        detector.reset_state()

        for key, value in detector.DEFAULT_DETECTION_ENABLED.items():
            self.rule_vars[key].set(value)
        defaults = detector.DEFAULT_THRESHOLDS
        for key, entry in self.threshold_entries.items():
            entry.delete(0, "end")
            entry.insert(0, str(defaults[key]))
        self._log("[*] Detection settings restored to defaults. Detector state reset.")

    # Build PCAP replay speed controls.
    def _build_replay_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color="#050816", corner_radius=8)
        panel.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        ctk.CTkLabel(
            panel,
            text="PCAP Replay Speed",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0",
        ).pack(anchor="w", padx=14, pady=(14, 6))
        ctk.CTkLabel(
            panel,
            text="Choose how quickly packets are replayed when loading a PCAP file.",
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1",
        ).pack(anchor="w", padx=14, pady=(0, 10))
        ctk.CTkSegmentedButton(
            panel,
            values=["Fast", "Normal", "Slow"],
            variable=self.pcap_replay_speed,
            selected_color="#1d4ed8",
            selected_hover_color="#2563eb",
            unselected_color="#0f172a",
            unselected_hover_color="#1e293b",
        ).pack(anchor="w", padx=14, pady=(0, 12))
        ctk.CTkLabel(
            panel,
            text="Fast: no delay | Normal: 2 ms per packet | Slow: 20 ms per packet",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8",
        ).pack(anchor="w", padx=14, pady=(0, 14))

    # Build alert sound notification controls.
    def _build_sound_settings_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color="#050816", corner_radius=8)
        panel.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)
        ctk.CTkLabel(
            panel,
            text="Sound Settings",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e2e8f0",
        ).pack(anchor="w", padx=14, pady=(14, 8))
        ctk.CTkSwitch(
            panel,
            text="Enable sound notifications",
            variable=self.sound_enabled,
            onvalue=True,
            offvalue=False,
            progress_color="#38bdf8",
            button_color="#e2e8f0",
            text_color="#cbd5e1",
        ).pack(anchor="w", padx=14, pady=6)
        ctk.CTkButton(
            panel,
            text="📢 Choose Alert Sound",
            width=180,
            height=34,
            fg_color="#334155",
            hover_color="#475569",
            command=self.choose_sound_file,
        ).pack(anchor="w", padx=14, pady=(10, 6))
        self.lbl_sound_settings_file = ctk.CTkLabel(
            panel,
            text=f"Current alert sound: {os.path.basename(self.sound_file)}",
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1",
        )
        self.lbl_sound_settings_file.pack(anchor="w", padx=14, pady=(0, 6))
        ctk.CTkLabel(
            panel,
            text="High severity alerts use vineboom.mp3 and show the Noted overlay.",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8",
        ).pack(anchor="w", padx=14, pady=(0, 14))

    # Append a message to the on-screen alert log safely.
    def _log(self, message):
        if threading.get_ident() != self.ui_thread_id:
            self.after(0, self._log, message)
            return
        self.alert_box.configure(state="normal")
        self.alert_box.insert("end", f"{message}\n")
        self.alert_box.see("end")
        self.alert_box.configure(state="disabled")

    # Receive detector alerts and update all alert-related UI elements.
    def log_alert(self, message):
        if threading.get_ident() != self.ui_thread_id:
            self.after(0, self.log_alert, message)
            return
        self.alert_count += 1
        self.lbl_alerts.configure(text=f"Alerts: {self.alert_count}")
        category = self._classify_alert(message)
        severity = self._severity_for_category(category)
        record = self._build_alert_record(message, category, severity)
        self.next_alert_id += 1
        self.alert_records.append(record)
        if self._record_matches_filters(record):
            self._insert_alert_record(record)
        if record["source"] != "-":
            self.source_counts[record["source"]] += 1
            self.source_last_type[record["source"]] = category
            self._draw_top_sources()
        self.alert_categories[category] += 1
        self._draw_dashboard()
        if severity == "High":
            self.show_high_alert_banner(record)
        self._play_alert_sound()
        self._log(f"[ALERT] {message}")

    # Increment packet counters and update last packet timing.
    def increment_packets(self):
        if threading.get_ident() != self.ui_thread_id:
            self.after(0, self.increment_packets)
            return
        self.packet_count += 1
        self.current_second_packets += 1
        self.last_packet_time = datetime.now().strftime("%H:%M:%S")
        self.last_packet_epoch = time.time()
        self.lbl_packets.configure(text=f"Packets Captured: {self.packet_count}")
        self.lbl_last_packet.configure(text=f"Last Packet: {self.last_packet_time}")

    # Set the progress bar to a specific value.
    def set_progress(self, value):
        self.progress_bar.set(value)
        self.update_idletasks()

    # Start indeterminate progress animation during PCAP analysis.
    def start_progress_animation(self):
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

    # Stop progress animation and mark progress as complete.
    def stop_progress_animation(self):
        if threading.get_ident() != self.ui_thread_id:
            self.after(0, self.stop_progress_animation)
            return
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1.0)

    # Classify an alert message into a dashboard category.
    def _classify_alert(self, message):
        if "DoS Detected" in message:
            return "DoS"
        if "PORT SCAN" in message:
            return "Port Scan"
        if "TCP Flag Scan" in message:
            return "TCP Flag"
        if "Reverse Shell" in message:
            return "Reverse Shell"
        if "ARP Spoofing" in message or "MITM" in message:
            return "ARP/MITM"
        return "Other"

    # Convert an alert category into a severity level.
    def _severity_for_category(self, category):
        if category in {"DoS", "Reverse Shell", "ARP/MITM"}:
            return "High"
        if category in {"Port Scan", "TCP Flag"}:
            return "Medium"
        return "Low"

    # Convert an alert message into a structured table/export record.
    def _build_alert_record(self, message, category, severity):
        source = self._extract_match(message, r"from ([0-9A-Fa-f:.]+)")
        if category == "ARP/MITM":
            source = self._extract_match(message, r"IP ([0-9A-Fa-f:.]+)") or source
        destination = self._extract_match(message, r" to ([0-9A-Fa-f:.]+)")
        return {
            "id": str(self.next_alert_id),
            "time": datetime.now().strftime("%H:%M:%S"),
            "severity": severity,
            "type": category,
            "source": source or "-",
            "destination": destination or "-",
            "review": "Needs Review",
            "note": "",
            "details": message,
        }

    # Extract a regex match from alert text.
    def _extract_match(self, text, pattern):
        match = re.search(pattern, text)
        return match.group(1) if match else ""

    # Insert one structured alert record into the alerts table.
    def _insert_alert_record(self, record):
        self.alert_table.insert(
            "",
            "end",
            iid=record["id"],
            values=(
                record["time"],
                record["severity"],
                record["type"],
                record["source"],
                record["destination"],
                record["review"],
                record["note"],
                record["details"],
            ),
            tags=(record["severity"],),
        )
        rows = self.alert_table.get_children()
        if rows:
            self.alert_table.see(rows[-1])

    # Check whether an alert record matches the active table filters.
    def _record_matches_filters(self, record):
        severity_filter = self.alert_filter_severity.get()
        type_filter = self.alert_filter_type.get()
        if severity_filter != "All" and record["severity"] != severity_filter:
            return False
        if type_filter != "All" and record["type"] != type_filter:
            return False
        return True

    # Rebuild the alerts table using the current filters.
    def refresh_alert_table(self):
        for row in self.alert_table.get_children():
            self.alert_table.delete(row)
        for record in self.alert_records:
            if self._record_matches_filters(record):
                self._insert_alert_record(record)

    # Reset alert table filters back to All.
    def clear_alert_filters(self):
        self.alert_filter_severity.set("All")
        self.alert_filter_type.set("All")
        self.refresh_alert_table()

    # Save review status and notes for the selected alert.
    def save_alert_review(self):
        selected = self.alert_table.selection()
        if not selected:
            self._log("[*] Select an alert row before saving review notes.")
            return
        alert_id = selected[0]
        for record in self.alert_records:
            if record["id"] == alert_id:
                record["review"] = self.review_status_var.get()
                record["note"] = self.review_note_entry.get().strip()
                self.refresh_alert_table()
                self._log(f"[*] Review saved for alert #{alert_id}: {record['review']}")
                return

    # Load selected alert review values into the review controls.
    def _load_selected_alert_review(self, _event=None):
        selected = self.alert_table.selection()
        if not selected:
            return
        alert_id = selected[0]
        for record in self.alert_records:
            if record["id"] == alert_id:
                self.review_status_var.set(record["review"])
                self.review_note_entry.delete(0, "end")
                self.review_note_entry.insert(0, record["note"])
                return

    # Show a modal high-severity alert notification.
    def show_high_alert_banner(self, record):
        message = f"HIGH ALERT: {record['type']} from {record['source']}\n\n{record['details']}"
        self.dismiss_high_alert()
        self.high_alert_overlay = ctk.CTkFrame(self, fg_color="#020617")
        self.high_alert_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)

        modal = ctk.CTkFrame(
            self.high_alert_overlay,
            fg_color="#7f1d1d",
            border_width=2,
            border_color="#fecaca",
            corner_radius=12,
        )
        modal.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.72)

        ctk.CTkLabel(
            modal,
            text="High Severity Alert",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#fee2e2",
        ).pack(anchor="w", padx=22, pady=(20, 8))

        ctk.CTkLabel(
            modal,
            text=message,
            font=ctk.CTkFont(size=14),
            text_color="#fff7ed",
            justify="left",
            wraplength=620,
        ).pack(fill="x", padx=22, pady=(0, 18))

        ctk.CTkButton(
            modal,
            text="Noted",
            width=130,
            height=38,
            fg_color="#fee2e2",
            hover_color="#fecaca",
            text_color="#7f1d1d",
            command=self.dismiss_high_alert,
        ).pack(pady=(0, 20))

        self.high_alert_overlay.lift()
        self._play_high_severity_sound()

    # Dismiss the high-severity alert overlay.
    def dismiss_high_alert(self):
        overlay = getattr(self, "high_alert_overlay", None)
        if overlay is not None:
            overlay.destroy()
            self.high_alert_overlay = None

    # Redraw alert category counters and the alert mix chart.
    def _draw_dashboard(self):
        for category, label in self.category_labels.items():
            label.configure(text=str(self.alert_categories[category]))

        self.chart_canvas.delete("all")
        total = sum(self.alert_categories.values())
        if total == 0:
            self.chart_canvas.create_oval(38, 16, 132, 110, outline="#334155", width=12)
            self.chart_canvas.create_text(
                85,
                63,
                text="No alerts",
                fill="#94a3b8",
                font=("Segoe UI", 10, "bold"),
            )
            return

        start = 90
        for category, count in self.alert_categories.items():
            if count == 0:
                continue
            extent = 360 * count / total
            self.chart_canvas.create_arc(
                32,
                12,
                138,
                118,
                start=start,
                extent=extent,
                fill=self.category_colors[category],
                outline="#0f172a",
                width=2,
            )
            start += extent

        self.chart_canvas.create_oval(61, 41, 109, 89, fill="#0f172a", outline="#0f172a")
        self.chart_canvas.create_text(
            85,
            65,
            text=str(total),
            fill="#f8fafc",
            font=("Segoe UI", 16, "bold"),
        )

    # Update packets-per-second history once per second.
    def _update_packet_rate(self):
        self.current_pps = self.current_second_packets
        self.current_second_packets = 0
        self.packet_rate_history.append(self.current_pps)
        self.packet_rate_history = self.packet_rate_history[-30:]
        self.lbl_current_pps.configure(text=f"Current Rate: {self.current_pps} pkt/s")
        self._draw_packet_rate_graph()
        self.after(1000, self._update_packet_rate)

    # Update runtime and capture health status once per second.
    def _update_session_status(self):
        if self.session_started_at:
            elapsed = int(time.time() - self.session_started_at)
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.lbl_timer.configure(text=f"Runtime: {hours:02d}:{minutes:02d}:{seconds:02d}")
        else:
            self.lbl_timer.configure(text="Runtime: 00:00:00")

        if self.is_sniffing:
            age = time.time() - self.last_packet_epoch if self.last_packet_epoch else None
            if age is not None and age <= 5:
                self.lbl_health.configure(text="Health: Receiving", text_color="#86efac")
            elif age is not None and age <= 15:
                self.lbl_health.configure(text="Health: Quiet", text_color="#fde68a")
            else:
                self.lbl_health.configure(text="Health: No packets", text_color="#fca5a5")
        elif "Error" in self.lbl_status.cget("text"):
            self.lbl_health.configure(text="Health: Error", text_color="#fca5a5")
        else:
            self.lbl_health.configure(text="Health: Idle", text_color="#cbd5e1")
        self.after(1000, self._update_session_status)

    # Redraw the packets-per-second line graph.
    def _draw_packet_rate_graph(self):
        self.pps_canvas.delete("all")
        width = max(self.pps_canvas.winfo_width(), 250)
        height = 82
        pad = 10
        self.pps_canvas.create_line(pad, height - pad, width - pad, height - pad, fill="#1e293b")
        self.pps_canvas.create_line(pad, pad, pad, height - pad, fill="#1e293b")

        max_rate = max(max(self.packet_rate_history), 1)
        points = []
        for index, value in enumerate(self.packet_rate_history):
            x = pad + index * ((width - 2 * pad) / max(len(self.packet_rate_history) - 1, 1))
            y = (height - pad) - (value / max_rate) * (height - 2 * pad)
            points.extend([x, y])

        if len(points) >= 4:
            self.pps_canvas.create_line(*points, fill="#38bdf8", width=2, smooth=True)
        self.pps_canvas.create_text(
            width - pad,
            pad + 2,
            text=f"max {max_rate}",
            fill="#94a3b8",
            font=("Segoe UI", 8),
            anchor="ne",
        )

    # Update the top source IP list.
    def _draw_top_sources(self):
        top_sources = self.source_counts.most_common(3)
        for index, label in enumerate(self.source_labels):
            if index < len(top_sources):
                source, count = top_sources[index]
                last_type = self.source_last_type.get(source, "Unknown")
                label.configure(text=f"{source} | {count} alert(s) | {last_type}")
            else:
                label.configure(text="-")

    # Play the selected normal alert sound if enabled.
    def _play_alert_sound(self):
        if not self.sound_enabled.get():
            return
        if not os.path.exists(self.sound_file):
            self._log("[ERROR] Sound file missing: amongus.mp3")
            return
        now = time.time()
        if now - self.last_sound_at < 2:
            return
        self.last_sound_at = now
        threading.Thread(target=self._play_sound_worker, args=(self.sound_file,), daemon=True).start()

    # Play the high-severity sound if enabled.
    def _play_high_severity_sound(self):
        if not self.sound_enabled.get():
            return
        if not os.path.exists(self.high_severity_sound_file):
            self._log("[ERROR] High severity sound file missing: vineboom.mp3")
            return
        now = time.time()
        if now - self.last_high_sound_at < 2:
            return
        self.last_high_sound_at = now
        threading.Thread(
            target=self._play_sound_worker,
            args=(self.high_severity_sound_file,),
            daemon=True,
        ).start()

    # Play an audio file in a background worker.
    def _play_sound_worker(self, sound_file):
        if sys.platform.startswith("win"):
            escaped = sound_file.replace("'", "''")
            command = (
                "Add-Type -AssemblyName PresentationCore; "
                "$player = New-Object System.Windows.Media.MediaPlayer; "
                f"$player.Open([Uri]'{escaped}'); "
                "$player.Volume = 0.7; "
                "$player.Play(); "
                f"Start-Sleep -Milliseconds {self.sound_duration_ms}; "
                "$player.Stop(); "
                "$player.Close()"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return

        subprocess.run(
            ["python3", "-c", "print('Sound playback is only configured for Windows.')"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    # Open a file picker to choose the normal alert sound.
    def choose_sound_file(self):
        filepath = filedialog.askopenfilename(
            title="Select Alert Sound",
            filetypes=[
                ("Audio files", "*.mp3 *.wav *.wma"),
                ("MP3 files", "*.mp3"),
                ("WAV files", "*.wav"),
                ("All files", "*.*"),
            ],
        )
        if not filepath:
            return
        self.sound_file = filepath
        if hasattr(self, "lbl_sound_settings_file"):
            self.lbl_sound_settings_file.configure(
                text=f"Current alert sound: {os.path.basename(self.sound_file)}"
            )
        self._log(
            f"[*] Alert sound set to {os.path.basename(filepath)} "
            "for intrusion notifications."
        )

    # Refresh available Scapy sniff adapters.
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
            self.adapter_combo.set(self._preferred_adapter_label(labels))
        self._update_adapter_diagnostics()
        self._log(f"[*] Found {len(labels)} sniff adapter(s).")

    # Pick a likely useful adapter from the discovered adapter list.
    def _preferred_adapter_label(self, labels):
        for label in labels:
            lower = label.lower()
            if any(token in lower for token in ("virtualbox", "vmware", "host-only", "ethernet")):
                return label
        return labels[0]

    # Return the selected adapter label and Scapy interface value.
    def selected_adapter(self):
        label = self.adapter_combo.get()
        return label, self.adapter_map.get(label)

    # Update the selected adapter diagnostic label.
    def _update_adapter_diagnostics(self):
        label, _ = self.selected_adapter()
        if len(label) > 60:
            label = label[:57] + "..."
        self.lbl_selected_adapter.configure(text=f"Adapter: {label or '-'}")

    # Start live packet sniffing on the selected adapter.
    def start_sniffing(self):
        if self.is_sniffing:
            return

        adapter_label, adapter_value = self.selected_adapter()
        if not adapter_value:
            self._log("[ERROR] Select a sniff adapter before starting live sniff.")
            return

        self._update_adapter_diagnostics()
        self.is_sniffing = True
        self.session_started_at = time.time()
        self.session_summary_autosaved = False
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.adapter_combo.configure(state="disabled")
        self.btn_refresh_adapters.configure(state="disabled")
        self.lbl_status.configure(text="Status: Sniffing...", text_color="#86efac")
        self._log(f"[*] Live sniffing started on: {adapter_label}")

        from sniffer import start_sniff

        sniff_thread = threading.Thread(target=start_sniff, args=(self, adapter_value), daemon=True)
        sniff_thread.start()

    # Stop live sniffing and auto-save a session summary.
    def stop_sniffing(self):
        self.is_sniffing = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.adapter_combo.configure(state="readonly")
        self.btn_refresh_adapters.configure(state="normal")
        self.lbl_status.configure(text="Status: Stopped", text_color="#fca5a5")
        self._log("[*] Sniffing stopped.")

        from sniffer import stop_sniff

        stop_sniff()
        if not self.session_summary_autosaved:
            self.export_session_summary(auto=True, open_folder=False)
            self.session_summary_autosaved = True

    # Export alert records to a CSV file.
    def export_alerts_csv(self):
        if threading.get_ident() != self.ui_thread_id:
            self.after(0, self.export_alerts_csv)
            return

        if not self.alert_records:
            self._log("[*] No alerts to export yet.")
            return

        os.makedirs("exports", exist_ok=True)
        export_path = os.path.join(
            "exports",
            f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        with open(export_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=[
                    "id",
                    "time",
                    "severity",
                    "type",
                    "source",
                    "destination",
                    "review",
                    "note",
                    "details",
                ],
            )
            writer.writeheader()
            writer.writerows(self.alert_records)
        self._log(f"[*] Exported {len(self.alert_records)} alert(s) to: {export_path}")
        self._open_folder("exports")

    # Export a text summary of the current IDS session.
    def export_session_summary(self, auto=False, open_folder=True):
        if threading.get_ident() != self.ui_thread_id:
            self.after(0, self.export_session_summary, auto, open_folder)
            return

        os.makedirs("exports", exist_ok=True)
        prefix = "auto_session_summary" if auto else "session_summary"
        export_path = os.path.join(
            "exports",
            f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
        )
        adapter_label, _ = self.selected_adapter()
        most_common = "-"
        if self.alert_categories:
            category, count = max(self.alert_categories.items(), key=lambda item: item[1])
            if count > 0:
                most_common = f"{category} ({count})"

        with open(export_path, "w", encoding="utf-8") as report:
            report.write("Python-Based IDS Session Summary\n")
            report.write("=" * 34 + "\n\n")
            report.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report.write(f"Selected Adapter: {adapter_label or '-'}\n")
            report.write(f"Log File: {self.log_file}\n")
            report.write(f"Total Packets: {self.packet_count}\n")
            report.write(f"Total Alerts: {self.alert_count}\n")
            report.write(f"Most Common Alert Type: {most_common}\n")
            report.write(f"Last Packet Time: {self.last_packet_time}\n\n")

            report.write("Alert Counts by Type\n")
            report.write("-" * 20 + "\n")
            for category, count in self.alert_categories.items():
                report.write(f"{category}: {count}\n")

            report.write("\nTop Source IPs\n")
            report.write("-" * 14 + "\n")
            if self.source_counts:
                for source, count in self.source_counts.most_common(5):
                    report.write(
                        f"{source}: {count} alert(s), last type {self.source_last_type.get(source, '-')}\n"
                    )
            else:
                report.write("No alert sources recorded.\n")

            report.write("\nRecent Alerts\n")
            report.write("-" * 13 + "\n")
            if self.alert_records:
                for record in self.alert_records:
                    report.write(
                        f"[{record['time']}] {record['severity']} | {record['type']} | "
                        f"{record['source']} -> {record['destination']} | "
                        f"{record['review']} | {record['note']} | {record['details']}\n"
                    )
            else:
                report.write("No alerts recorded.\n")

        action = "Auto-saved" if auto else "Exported"
        self._log(f"[*] {action} session summary to: {export_path}")
        if open_folder:
            self._open_folder("exports")

    # Open an output folder in the operating system file explorer.
    def _open_folder(self, folder_path):
        os.makedirs(folder_path, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(os.path.abspath(folder_path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", folder_path])
            else:
                subprocess.Popen(["xdg-open", folder_path])
        except Exception as exc:
            self._log(f"[ERROR] Could not open folder {folder_path}: {exc}")

    # Load and analyze a selected PCAP or PCAPNG file.
    def load_pcap(self):
        filepath = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
        )
        if filepath:
            self._log(f"[*] Loading PCAP: {filepath}")
            self.lbl_status.configure(text="Status: Analysing...", text_color="#fbbf24")
            self.btn_stop.configure(state="normal")
            self.session_started_at = time.time()
            self.session_summary_autosaved = False

            from sniffer import analyse_pcap

            analyse_thread = threading.Thread(
                target=analyse_pcap,
                args=(filepath, self, self._pcap_replay_delay()),
                daemon=True,
            )
            analyse_thread.start()

    # Convert the selected PCAP replay speed into a packet delay.
    def _pcap_replay_delay(self):
        speed = self.pcap_replay_speed.get()
        if speed == "Slow":
            return 0.02
        if speed == "Normal":
            return 0.002
        return 0

    # Clear visible session data and reset detector state.
    def clear_log(self):
        self.alert_box.configure(state="normal")
        self.alert_box.delete("1.0", "end")
        self.alert_box.configure(state="disabled")
        self.packet_count = 0
        self.alert_count = 0
        self.alert_records.clear()
        self.next_alert_id = 1
        self.dismiss_high_alert()
        self.source_counts.clear()
        self.source_last_type.clear()
        self.packet_rate_history = [0] * 30
        self.current_second_packets = 0
        self.current_pps = 0
        self.last_packet_time = "-"
        self.last_packet_epoch = 0
        self.session_started_at = None
        self.session_summary_autosaved = False
        for row in self.alert_table.get_children():
            self.alert_table.delete(row)
        for category in self.alert_categories:
            self.alert_categories[category] = 0
        self.lbl_packets.configure(text="Packets Captured: 0")
        self.lbl_alerts.configure(text="Alerts: 0")
        self.lbl_status.configure(text="Status: Idle", text_color="#cbd5e1")
        self.lbl_timer.configure(text="Runtime: 00:00:00")
        self.lbl_health.configure(text="Health: Idle", text_color="#cbd5e1")
        self.lbl_current_pps.configure(text="Current Rate: 0 pkt/s")
        self.lbl_last_packet.configure(text="Last Packet: -")
        self._draw_packet_rate_graph()
        self._draw_top_sources()
        self._draw_dashboard()
        self._log("Log cleared. IDS ready.")
        self.progress_bar.set(0)
        detector.reset_state()


if __name__ == "__main__":
    app = IDSApp()
    app.mainloop()
