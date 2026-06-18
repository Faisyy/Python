import unittest

from scapy.all import ARP, ICMP, IP, TCP, UDP

import detector


class FakeApp:
    def __init__(self):
        self.alerts = []
        self.packet_count = 0

    def log_alert(self, message):
        self.alerts.append(message)

    def increment_packets(self):
        self.packet_count += 1


class DetectorTests(unittest.TestCase):
    def setUp(self):
        detector.reset_state()
        self._original_file_log = detector.file_log
        detector.file_log = lambda message: None
        self.app = FakeApp()

    def tearDown(self):
        detector.file_log = self._original_file_log
        detector.reset_state()

    def _detect_many(self, packet, count):
        for _ in range(count):
            detector.detect(packet.copy(), self.app)

    def test_syn_flood_alert_uses_dos_classification(self):
        packet = IP(src="10.0.0.10", dst="10.0.0.20") / TCP(dport=80, flags="S")

        self._detect_many(packet, detector.SYN_THRESHOLD + 1)

        self.assertTrue(any("DoS Detected: SYN Flood" in alert for alert in self.app.alerts))

    def test_icmp_flood_alert_uses_dos_classification(self):
        packet = IP(src="10.0.0.11", dst="10.0.0.20") / ICMP()

        self._detect_many(packet, detector.ICMP_THRESHOLD + 1)

        self.assertTrue(any("DoS Detected: ICMP Flood" in alert for alert in self.app.alerts))

    def test_udp_flood_alert_uses_dos_classification(self):
        packet = IP(src="10.0.0.12", dst="10.0.0.20") / UDP(dport=53)

        self._detect_many(packet, detector.UDP_THRESHOLD + 1)

        self.assertTrue(any("DoS Detected: UDP Flood" in alert for alert in self.app.alerts))

    def test_port_scan_alert_after_unique_port_threshold(self):
        src_ip = "10.0.0.13"

        for port in range(1, detector.PORT_THRESHOLD + 2):
            packet = IP(src=src_ip, dst="10.0.0.20") / TCP(dport=port, flags="S")
            detector.detect(packet, self.app)

        self.assertTrue(any("PORT SCAN detected" in alert for alert in self.app.alerts))

    def test_suspicious_port_alert_uses_reverse_shell_indicator_wording(self):
        packet = IP(src="10.0.0.14", dst="10.0.0.20") / TCP(dport=4444, flags="S")

        detector.detect(packet, self.app)

        self.assertTrue(
            any("Possible Reverse Shell Indicator" in alert for alert in self.app.alerts)
        )
        self.assertTrue(any("suspicious port 4444" in alert for alert in self.app.alerts))

    def test_tcp_flag_scan_alerts_for_fin_null_and_xmas(self):
        packets = [
            IP(src="10.0.0.15", dst="10.0.0.20") / TCP(dport=80, flags="F"),
            IP(src="10.0.0.16", dst="10.0.0.20") / TCP(dport=80, flags=0),
            IP(src="10.0.0.17", dst="10.0.0.20") / TCP(dport=80, flags="FPU"),
        ]

        for packet in packets:
            detector.detect(packet, self.app)

        self.assertTrue(any("FIN scan pattern" in alert for alert in self.app.alerts))
        self.assertTrue(any("NULL scan pattern" in alert for alert in self.app.alerts))
        self.assertTrue(any("XMAS scan pattern" in alert for alert in self.app.alerts))

    def test_arp_mapping_change_alerts_as_mitm_indicator(self):
        original = ARP(
            op=2,
            psrc="10.0.0.1",
            hwsrc="aa:bb:cc:dd:ee:ff",
            pdst="10.0.0.20",
            hwdst="11:22:33:44:55:66",
        )
        changed = ARP(
            op=2,
            psrc="10.0.0.1",
            hwsrc="00:11:22:33:44:55",
            pdst="10.0.0.20",
            hwdst="11:22:33:44:55:66",
        )

        detector.detect(original, self.app)
        detector.detect(changed, self.app)

        self.assertTrue(
            any("ARP Spoofing / MITM Indicator" in alert for alert in self.app.alerts)
        )

    def test_reset_state_clears_trackers_cooldowns_and_arp_mappings(self):
        detector.syn_tracker["10.0.0.1"].append(1)
        detector.icmp_tracker["10.0.0.1"].append(1)
        detector.udp_tracker["10.0.0.1"].append(1)
        detector.port_tracker["10.0.0.1"][80] = 1
        detector.arp_tracker["10.0.0.1"] = "aa:bb:cc:dd:ee:ff"
        detector._last_alert[("10.0.0.1", "TEST")] = 1

        detector.reset_state()

        self.assertFalse(detector.syn_tracker)
        self.assertFalse(detector.icmp_tracker)
        self.assertFalse(detector.udp_tracker)
        self.assertFalse(detector.port_tracker)
        self.assertFalse(detector.arp_tracker)
        self.assertFalse(detector._last_alert)


if __name__ == "__main__":
    unittest.main()
