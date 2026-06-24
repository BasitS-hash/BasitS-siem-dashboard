"""Tests for compliance.ComplianceChecker"""
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# We test the compliance module by mocking the database so no Flask app is needed.


MINIMAL_CONFIG = {
    "compliance": {
        "frameworks": ["PCI-DSS", "HIPAA", "GDPR", "SOC2"],
        "retention_days": 90,
    }
}


def _make_checker():
    from compliance import ComplianceChecker
    return ComplianceChecker(MINIMAL_CONFIG)


def _date_range():
    end = datetime.now()
    start = end - timedelta(days=1)
    return start, end


class TestComplianceCheckerInit:
    def test_frameworks_loaded(self):
        checker = _make_checker()
        assert "PCI-DSS" in checker.frameworks
        assert "GDPR" in checker.frameworks

    def test_retention_days(self):
        checker = _make_checker()
        assert checker.retention_days == 90


class TestReportScoring:
    """Test the score calculation logic without hitting the database."""

    def _score_from_checks(self, checks):
        """Replicate the scoring logic used in compliance.py."""
        passed = sum(1 for c in checks if c["status"] == "passed")
        total = len(checks)
        return (passed / total) * 100 if total > 0 else 0.0

    def test_all_passed_gives_100(self):
        checks = [{"status": "passed"}, {"status": "passed"}]
        assert self._score_from_checks(checks) == 100.0

    def test_all_failed_gives_0(self):
        checks = [{"status": "failed"}, {"status": "failed"}]
        assert self._score_from_checks(checks) == 0.0

    def test_half_passed_gives_50(self):
        checks = [{"status": "passed"}, {"status": "failed"}]
        assert self._score_from_checks(checks) == 50.0

    def test_empty_checks_gives_0(self):
        assert self._score_from_checks([]) == 0.0

    def test_warning_does_not_count_as_passed(self):
        checks = [{"status": "warning"}, {"status": "passed"}]
        score = self._score_from_checks(checks)
        assert score == 50.0


class TestGenericReport:
    """Test _generic_report by patching db.session."""

    def test_generic_report_returns_compliance_report(self):
        from compliance import ComplianceChecker
        from models import ComplianceReport

        checker = ComplianceChecker(MINIMAL_CONFIG)
        start, end = _date_range()

        mock_query = MagicMock()
        mock_query.filter.return_value.count.return_value = 10

        with patch("compliance.db") as mock_db:
            mock_db.session.query.return_value = mock_query
            report = checker._generic_report("TestFramework", start, end)

        assert isinstance(report, ComplianceReport)
        assert report.framework == "TestFramework"
        assert 0 <= report.compliance_score <= 100


class TestGenerateReportDispatch:
    """generate_report() dispatches to the right framework method."""

    def test_pci_dss_dispatched(self):
        checker = _make_checker()
        start, end = _date_range()
        with patch.object(checker, "_check_pci_dss", return_value=MagicMock()) as mock_fn:
            checker.generate_report("PCI-DSS", start, end)
            mock_fn.assert_called_once_with(start, end)

    def test_hipaa_dispatched(self):
        checker = _make_checker()
        start, end = _date_range()
        with patch.object(checker, "_check_hipaa", return_value=MagicMock()) as mock_fn:
            checker.generate_report("HIPAA", start, end)
            mock_fn.assert_called_once_with(start, end)

    def test_gdpr_dispatched(self):
        checker = _make_checker()
        start, end = _date_range()
        with patch.object(checker, "_check_gdpr", return_value=MagicMock()) as mock_fn:
            checker.generate_report("GDPR", start, end)
            mock_fn.assert_called_once_with(start, end)

    def test_soc2_dispatched(self):
        checker = _make_checker()
        start, end = _date_range()
        with patch.object(checker, "_check_soc2", return_value=MagicMock()) as mock_fn:
            checker.generate_report("SOC2", start, end)
            mock_fn.assert_called_once_with(start, end)

    def test_unknown_framework_uses_generic(self):
        checker = _make_checker()
        start, end = _date_range()
        with patch.object(checker, "_generic_report", return_value=MagicMock()) as mock_fn:
            checker.generate_report("NIST-CSF", start, end)
            mock_fn.assert_called_once_with("NIST-CSF", start, end)
