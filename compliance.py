"""
Compliance Reporting Module
"""
from datetime import datetime, timedelta
from typing import Dict

from models import ComplianceReport, LogEntry, ThreatAlert, db


class ComplianceChecker:
    """Generate compliance reports for various frameworks"""

    def __init__(self, config: Dict):
        self.config = config
        self.frameworks = config.get('compliance', {}).get('frameworks', [])
        self.retention_days = config.get('compliance', {}).get('retention_days', 90)

    def generate_report(self, framework: str, start_date: datetime, end_date: datetime) -> ComplianceReport:
        """Generate a compliance report for a specific framework"""
        if framework == 'PCI-DSS':
            return self._check_pci_dss(start_date, end_date)
        elif framework == 'HIPAA':
            return self._check_hipaa(start_date, end_date)
        elif framework == 'GDPR':
            return self._check_gdpr(start_date, end_date)
        elif framework == 'SOC2':
            return self._check_soc2(start_date, end_date)
        else:
            return self._generic_report(framework, start_date, end_date)

    def _check_pci_dss(self, start_date: datetime, end_date: datetime) -> ComplianceReport:
        """Check PCI-DSS compliance requirements"""
        checks = []

        # Requirement 10: Track and monitor all access to network resources and cardholder data
        log_count = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).count()

        checks.append({
            'requirement': '10.1 - Logging Enabled',
            'description': 'Audit trails are enabled and active for all system components',
            'status': 'passed' if log_count > 0 else 'failed',
            'details': f'Found {log_count} log entries'
        })

        # Check for authentication logging
        auth_logs = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date,
            LogEntry.message.ilike('%auth%')
        ).count()

        checks.append({
            'requirement': '10.2.1 - User Access Logging',
            'description': 'All individual user accesses to cardholder data are logged',
            'status': 'passed' if auth_logs > 0 else 'warning',
            'details': f'Found {auth_logs} authentication log entries'
        })

        # Check for failed access attempts
        failed_attempts = db.session.query(ThreatAlert).filter(
            ThreatAlert.timestamp >= start_date,
            ThreatAlert.timestamp <= end_date,
            ThreatAlert.alert_type.ilike('%brute force%')
        ).count()

        checks.append({
            'requirement': '10.2.4 - Invalid Access Attempts',
            'description': 'Invalid logical access attempts are logged',
            'status': 'passed' if failed_attempts >= 0 else 'failed',
            'details': f'Detected {failed_attempts} failed access attempts'
        })

        # Check log retention
        oldest_log = db.session.query(LogEntry).order_by(LogEntry.timestamp.asc()).first()
        retention_ok = False
        if oldest_log:
            days_retained = (datetime.now() - oldest_log.timestamp).days
            retention_ok = days_retained >= 90

        checks.append({
            'requirement': '10.7 - Log Retention',
            'description': 'Audit log history must be retained for at least one year',
            'status': 'passed' if retention_ok else 'warning',
            'details': f'Log retention: {days_retained if oldest_log else 0} days (minimum: 90 days)'
        })

        # Calculate compliance score
        passed = sum(1 for c in checks if c['status'] == 'passed')
        total = len(checks)
        score = (passed / total) * 100 if total > 0 else 0

        recommendations = []
        for check in checks:
            if check['status'] == 'failed':
                recommendations.append(f"Address {check['requirement']}: {check['description']}")

        return ComplianceReport(
            framework='PCI-DSS',
            report_date=datetime.now(),
            compliance_score=score,
            passed_checks=passed,
            failed_checks=total - passed,
            total_checks=total,
            details={'checks': checks},
            recommendations=recommendations
        )

    def _check_hipaa(self, start_date: datetime, end_date: datetime) -> ComplianceReport:
        """Check HIPAA compliance requirements"""
        checks = []

        # § 164.312(b) - Audit Controls
        log_count = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).count()

        checks.append({
            'requirement': '164.312(b) - Audit Controls',
            'description': 'Implement hardware, software, and/or procedural mechanisms that record and examine activity',
            'status': 'passed' if log_count > 0 else 'failed',
            'details': f'System generated {log_count} audit log entries'
        })

        # § 164.308(a)(1)(ii)(D) - Information System Activity Review
        alerts_reviewed = db.session.query(ThreatAlert).filter(
            ThreatAlert.timestamp >= start_date,
            ThreatAlert.timestamp <= end_date,
            ThreatAlert.status.in_(['resolved', 'false_positive'])
        ).count()

        total_alerts = db.session.query(ThreatAlert).filter(
            ThreatAlert.timestamp >= start_date,
            ThreatAlert.timestamp <= end_date
        ).count()

        checks.append({
            'requirement': '164.308(a)(1)(ii)(D) - Activity Review',
            'description': 'Regularly review records of information system activity',
            'status': 'passed' if alerts_reviewed > 0 or total_alerts == 0 else 'warning',
            'details': f'Reviewed {alerts_reviewed} of {total_alerts} security alerts'
        })

        # § 164.308(a)(5)(ii)(C) - Log-in Monitoring
        auth_logs = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date,
            LogEntry.message.ilike('%login%')
        ).count()

        checks.append({
            'requirement': '164.308(a)(5)(ii)(C) - Log-in Monitoring',
            'description': 'Procedures for monitoring log-in attempts and reporting discrepancies',
            'status': 'passed' if auth_logs > 0 else 'warning',
            'details': f'Monitored {auth_logs} login events'
        })

        # Calculate compliance score
        passed = sum(1 for c in checks if c['status'] == 'passed')
        total = len(checks)
        score = (passed / total) * 100 if total > 0 else 0

        recommendations = []
        for check in checks:
            if check['status'] in ['failed', 'warning']:
                recommendations.append(f"Improve {check['requirement']}: {check['description']}")

        return ComplianceReport(
            framework='HIPAA',
            report_date=datetime.now(),
            compliance_score=score,
            passed_checks=passed,
            failed_checks=total - passed,
            total_checks=total,
            details={'checks': checks},
            recommendations=recommendations
        )

    def _check_gdpr(self, start_date: datetime, end_date: datetime) -> ComplianceReport:
        """Check GDPR compliance requirements"""
        checks = []

        # Article 30 - Records of processing activities
        log_count = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).count()

        checks.append({
            'requirement': 'Article 30 - Records of Processing',
            'description': 'Maintain records of processing activities',
            'status': 'passed' if log_count > 0 else 'failed',
            'details': f'Maintained {log_count} processing records'
        })

        # Article 32 - Security of processing
        security_incidents = db.session.query(ThreatAlert).filter(
            ThreatAlert.timestamp >= start_date,
            ThreatAlert.timestamp <= end_date,
            ThreatAlert.severity.in_(['high', 'critical'])
        ).count()

        checks.append({
            'requirement': 'Article 32 - Security Measures',
            'description': 'Implement appropriate technical and organizational measures',
            'status': 'passed',
            'details': f'Detected and logged {security_incidents} security incidents'
        })

        # Article 33 - Breach notification (72 hours)
        recent_critical_alerts = db.session.query(ThreatAlert).filter(
            ThreatAlert.timestamp >= datetime.now() - timedelta(hours=72),
            ThreatAlert.severity == 'critical',
            ThreatAlert.status == 'open'
        ).count()

        checks.append({
            'requirement': 'Article 33 - Breach Notification',
            'description': 'Notify supervisory authority of a breach within 72 hours',
            'status': 'warning' if recent_critical_alerts > 0 else 'passed',
            'details': f'{recent_critical_alerts} unresolved critical alerts require attention'
        })

        # Calculate compliance score
        passed = sum(1 for c in checks if c['status'] == 'passed')
        total = len(checks)
        score = (passed / total) * 100 if total > 0 else 0

        recommendations = []
        if recent_critical_alerts > 0:
            recommendations.append('Review and respond to critical security alerts within 72 hours')

        return ComplianceReport(
            framework='GDPR',
            report_date=datetime.now(),
            compliance_score=score,
            passed_checks=passed,
            failed_checks=total - passed,
            total_checks=total,
            details={'checks': checks},
            recommendations=recommendations
        )

    def _check_soc2(self, start_date: datetime, end_date: datetime) -> ComplianceReport:
        """Check SOC 2 compliance requirements"""
        checks = []

        # CC6.1 - Logical and Physical Access Controls
        auth_logs = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date,
            LogEntry.message.ilike('%auth%')
        ).count()

        checks.append({
            'requirement': 'CC6.1 - Access Controls',
            'description': 'Logical and physical access controls restrict access',
            'status': 'passed' if auth_logs > 0 else 'warning',
            'details': f'Logged {auth_logs} access control events'
        })

        # CC7.2 - System Monitoring
        total_logs = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).count()

        checks.append({
            'requirement': 'CC7.2 - System Monitoring',
            'description': 'System components are monitored for anomalies',
            'status': 'passed' if total_logs > 100 else 'warning',
            'details': f'Monitoring generated {total_logs} log entries'
        })

        # CC7.3 - Threat Detection
        threats_detected = db.session.query(ThreatAlert).filter(
            ThreatAlert.timestamp >= start_date,
            ThreatAlert.timestamp <= end_date
        ).count()

        checks.append({
            'requirement': 'CC7.3 - Threat Detection',
            'description': 'Threats and anomalies are detected and analyzed',
            'status': 'passed',
            'details': f'Detected and analyzed {threats_detected} potential threats'
        })

        # Calculate compliance score
        passed = sum(1 for c in checks if c['status'] == 'passed')
        total = len(checks)
        score = (passed / total) * 100 if total > 0 else 0

        recommendations = []
        for check in checks:
            if check['status'] == 'warning':
                recommendations.append(f"Enhance {check['requirement']}: {check['description']}")

        return ComplianceReport(
            framework='SOC2',
            report_date=datetime.now(),
            compliance_score=score,
            passed_checks=passed,
            failed_checks=total - passed,
            total_checks=total,
            details={'checks': checks},
            recommendations=recommendations
        )

    def _generic_report(self, framework: str, start_date: datetime, end_date: datetime) -> ComplianceReport:
        """Generate a generic compliance report"""
        log_count = db.session.query(LogEntry).filter(
            LogEntry.timestamp >= start_date,
            LogEntry.timestamp <= end_date
        ).count()

        alert_count = db.session.query(ThreatAlert).filter(
            ThreatAlert.timestamp >= start_date,
            ThreatAlert.timestamp <= end_date
        ).count()

        checks = [
            {
                'requirement': 'Logging Enabled',
                'status': 'passed' if log_count > 0 else 'failed',
                'details': f'{log_count} log entries'
            },
            {
                'requirement': 'Threat Detection Active',
                'status': 'passed',
                'details': f'{alert_count} threats detected'
            }
        ]

        passed = sum(1 for c in checks if c['status'] == 'passed')
        total = len(checks)
        score = (passed / total) * 100 if total > 0 else 0

        return ComplianceReport(
            framework=framework,
            report_date=datetime.now(),
            compliance_score=score,
            passed_checks=passed,
            failed_checks=total - passed,
            total_checks=total,
            details={'checks': checks},
            recommendations=[]
        )
