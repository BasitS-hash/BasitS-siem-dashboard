"""Tests for threat_detector.ThreatDetector"""
from datetime import datetime, timedelta

import pytest

from threat_detector import ThreatDetector

MINIMAL_CONFIG = {
    "threat_detection": {
        "rules": [
            {
                "name": "Brute Force Detection",
                "type": "failed_login",
                "threshold": 3,
                "time_window": 300,
                "severity": "high",
            },
            {
                "name": "SQL Injection Detection",
                "type": "sql_injection",
                "patterns": [
                    r"(?i)(union.*select)",
                    r"(?i)(drop.*table)",
                ],
                "severity": "critical",
            },
            {
                "name": "XSS Detection",
                "type": "xss",
                "patterns": [
                    r"(?i)(<script.*?>)",
                    r"(?i)(javascript:)",
                ],
                "severity": "high",
            },
            {
                "name": "Port Scan Detection",
                "type": "port_scan",
                "threshold": 3,
                "time_window": 60,
                "severity": "medium",
            },
        ]
    }
}


@pytest.fixture()
def detector():
    return ThreatDetector(MINIMAL_CONFIG)


class TestBruteForceDetection:
    def test_no_alert_below_threshold(self, detector):
        log = {"message": "Failed password", "ip_address": "1.2.3.4", "timestamp": datetime.now()}
        alerts = detector.analyze_log(log)
        assert all(a.alert_type != "Brute Force Attack" for a in alerts)

    def test_alert_at_threshold(self, detector):
        """After threshold failures from the same IP we get a brute-force alert."""
        ip = "10.0.0.1"
        alerts = []
        for _ in range(3):
            log = {"message": "Failed password", "ip_address": ip, "timestamp": datetime.now()}
            alerts = detector.analyze_log(log)
        brute_alerts = [a for a in alerts if a.alert_type == "Brute Force Attack"]
        assert len(brute_alerts) >= 1

    def test_alert_has_correct_severity(self, detector):
        ip = "10.0.0.2"
        for _ in range(3):
            log = {"message": "Failed password", "ip_address": ip, "timestamp": datetime.now()}
            results = detector.analyze_log(log)
        brute = next((a for a in results if a.alert_type == "Brute Force Attack"), None)
        if brute:
            assert brute.severity == "high"

    def test_no_alert_without_ip_or_username(self, detector):
        log = {"message": "Failed password", "timestamp": datetime.now()}
        alerts = detector.analyze_log(log)
        brute = [a for a in alerts if a.alert_type == "Brute Force Attack"]
        assert brute == []

    def test_success_message_does_not_trigger(self, detector):
        log = {"message": "Successful login", "ip_address": "9.9.9.9", "timestamp": datetime.now()}
        alerts = detector.analyze_log(log)
        brute = [a for a in alerts if a.alert_type == "Brute Force Attack"]
        assert brute == []

    def test_old_events_not_counted(self, detector):
        """Events outside the time window should not count toward threshold."""
        ip = "5.5.5.5"
        old_time = datetime.now() - timedelta(seconds=400)
        for _ in range(2):
            log = {"message": "Failed password", "ip_address": ip, "timestamp": old_time}
            detector.analyze_log(log)
        # One recent failure — should NOT reach threshold of 3
        log = {"message": "Failed password", "ip_address": ip, "timestamp": datetime.now()}
        alerts = detector.analyze_log(log)
        brute = [a for a in alerts if a.alert_type == "Brute Force Attack"]
        assert brute == []


class TestSqlInjectionDetection:
    def test_union_select_detected(self, detector):
        log = {"message": "GET /?q=1 union select * from users", "ip_address": "1.2.3.4"}
        alerts = detector.analyze_log(log)
        sqli = [a for a in alerts if a.alert_type == "SQL Injection Attempt"]
        assert len(sqli) >= 1

    def test_drop_table_detected(self, detector):
        log = {"message": "drop table users", "ip_address": "1.2.3.4"}
        alerts = detector.analyze_log(log)
        sqli = [a for a in alerts if a.alert_type == "SQL Injection Attempt"]
        assert len(sqli) >= 1

    def test_sqli_severity_critical(self, detector):
        log = {"message": "union select 1,2,3", "ip_address": "2.2.2.2"}
        alerts = detector.analyze_log(log)
        sqli = next((a for a in alerts if a.alert_type == "SQL Injection Attempt"), None)
        if sqli:
            assert sqli.severity == "critical"

    def test_normal_query_not_detected(self, detector):
        log = {"message": "GET /search?q=hello+world", "ip_address": "3.3.3.3"}
        alerts = detector.analyze_log(log)
        sqli = [a for a in alerts if a.alert_type == "SQL Injection Attempt"]
        assert sqli == []


class TestXssDetection:
    def test_script_tag_detected(self, detector):
        log = {"message": "<script>alert(1)</script>", "ip_address": "1.1.1.1"}
        alerts = detector.analyze_log(log)
        xss = [a for a in alerts if a.alert_type == "XSS Attempt"]
        assert len(xss) >= 1

    def test_javascript_protocol_detected(self, detector):
        log = {"path": "javascript:alert(1)", "message": "xss", "ip_address": "1.1.1.1"}
        alerts = detector.analyze_log(log)
        xss = [a for a in alerts if a.alert_type == "XSS Attempt"]
        assert len(xss) >= 1

    def test_clean_html_not_detected(self, detector):
        log = {"message": "<p>Hello world</p>", "ip_address": "1.1.1.1"}
        alerts = detector.analyze_log(log)
        xss = [a for a in alerts if a.alert_type == "XSS Attempt"]
        assert xss == []


class TestPortScanDetection:
    def test_alert_at_threshold(self, detector):
        ip = "6.7.8.9"
        alerts = []
        for _ in range(3):
            log = {"message": "connection attempt", "ip_address": ip, "timestamp": datetime.now()}
            alerts = detector.analyze_log(log)
        port_scan = [a for a in alerts if a.alert_type == "Port Scan"]
        assert len(port_scan) >= 1

    def test_no_alert_without_ip(self, detector):
        for _ in range(5):
            log = {"message": "connection", "timestamp": datetime.now()}
            alerts = detector.analyze_log(log)
        ps = [a for a in alerts if a.alert_type == "Port Scan"]
        assert ps == []


class TestCacheCleanup:
    def test_cleanup_removes_old_events(self, detector):
        # Populate cache
        ip = "7.7.7.7"
        log = {"message": "Failed password", "ip_address": ip, "timestamp": datetime.now()}
        detector.analyze_log(log)
        key = f"failed_login_{ip}"
        assert len(detector.event_cache[key]) >= 1

        detector.cleanup_cache(hours=0)  # Cleanup with 0 hours — removes everything
        assert detector.event_cache.get(key, []) == []
