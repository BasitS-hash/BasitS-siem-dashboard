"""Tests for log_parser.LogParser"""
from datetime import datetime

import pytest

from log_parser import LogParser


@pytest.fixture()
def parser():
    return LogParser()


class TestParseSyslog:
    def test_extracts_message(self, parser):
        line = "Jan 15 10:30:45 myhost sshd[1234]: Failed password for root from 192.168.1.1"
        result = parser.parse_syslog(line)
        assert "Failed password" in result["message"]

    def test_extracts_hostname(self, parser):
        line = "Jan 15 10:30:45 myhost sshd[1234]: some message"
        result = parser.parse_syslog(line)
        assert result["hostname"] == "myhost"

    def test_extracts_ip(self, parser):
        line = "Jan 15 10:30:45 myhost sshd[1234]: Failed password for root from 10.0.0.5"
        result = parser.parse_syslog(line)
        assert result["ip_address"] == "10.0.0.5"

    def test_returns_generic_on_mismatch(self, parser):
        result = parser.parse_syslog("not a syslog line at all")
        assert "message" in result
        assert result["message"] == "not a syslog line at all"


class TestParseApache:
    SAMPLE = '192.168.1.1 - alice [01/Jan/2024:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234'

    def test_extracts_ip(self, parser):
        result = parser.parse_apache(self.SAMPLE)
        assert result["ip_address"] == "192.168.1.1"

    def test_extracts_username(self, parser):
        result = parser.parse_apache(self.SAMPLE)
        assert result["username"] == "alice"

    def test_extracts_status_code(self, parser):
        result = parser.parse_apache(self.SAMPLE)
        assert result["status_code"] == 200

    def test_severity_info_for_2xx(self, parser):
        result = parser.parse_apache(self.SAMPLE)
        assert result["severity"] == "info"

    def test_severity_warning_for_4xx(self, parser):
        line = '192.168.1.1 - - [01/Jan/2024:10:30:45 +0000] "GET /secret HTTP/1.1" 403 0'
        result = parser.parse_apache(line)
        assert result["severity"] == "warning"

    def test_extracts_method_and_path(self, parser):
        result = parser.parse_apache(self.SAMPLE)
        assert result["method"] == "GET"
        assert result["path"] == "/index.html"

    def test_anonymous_user_is_none(self, parser):
        line = '10.0.0.1 - - [01/Jan/2024:10:30:45 +0000] "GET / HTTP/1.1" 200 500'
        result = parser.parse_apache(line)
        assert result["username"] is None


class TestParseJson:
    def test_parses_valid_json(self, parser):
        import json
        payload = json.dumps({"message": "hello", "level": "warning", "ip": "1.2.3.4"})
        result = parser.parse_json(payload)
        assert result["message"] == "hello"
        assert result["severity"] == "warning"
        assert result["ip_address"] == "1.2.3.4"

    def test_falls_back_for_invalid_json(self, parser):
        result = parser.parse_json("not json {{{")
        assert result["message"] == "not json {{{"

    def test_timestamp_parsed_as_datetime(self, parser):
        import json
        payload = json.dumps({"message": "ok", "timestamp": "2024-01-01T12:00:00"})
        result = parser.parse_json(payload)
        assert isinstance(result["timestamp"], datetime)


class TestParseSecurity:
    def test_failed_login_detection(self, parser):
        result = parser.parse_security("authentication failure for user bob from 5.5.5.5")
        assert result["status"] == "failed"
        assert result["severity"] == "warning"

    def test_successful_login(self, parser):
        result = parser.parse_security("authentication successful for user alice")
        assert result.get("status") == "success"

    def test_firewall_event(self, parser):
        result = parser.parse_security("firewall blocked 10.0.0.1 on port 22")
        assert result["event_type"] == "firewall"
        assert result["severity"] == "warning"

    def test_extracts_ip(self, parser):
        result = parser.parse_security("connection blocked from 203.0.113.1")
        assert result["ip_address"] == "203.0.113.1"


class TestExtractHelpers:
    def test_extract_ip_v4(self, parser):
        assert parser._extract_ip("connected from 192.168.0.1 today") == "192.168.0.1"

    def test_extract_ip_none(self, parser):
        assert parser._extract_ip("no ip here") is None

    def test_extract_severity_critical(self, parser):
        assert parser._extract_severity("CRITICAL: system meltdown") == "critical"

    def test_extract_severity_error(self, parser):
        assert parser._extract_severity("ERROR: disk full") == "error"

    def test_extract_severity_warning(self, parser):
        assert parser._extract_severity("WARNING: low memory") == "warning"

    def test_extract_severity_debug(self, parser):
        assert parser._extract_severity("debug: tracing enabled") == "debug"

    def test_extract_severity_default_info(self, parser):
        assert parser._extract_severity("some random message") == "info"

    def test_parse_dispatch(self, parser):
        """parse() dispatches to the right sub-parser."""
        import json
        payload = json.dumps({"message": "structured log"})
        result = parser.parse(payload, "json")
        assert result["message"] == "structured log"
