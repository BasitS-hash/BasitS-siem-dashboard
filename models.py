"""
SIEM Dashboard - Database Models
"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class LogEntry(db.Model):
    """Store raw log entries"""
    __tablename__ = 'log_entries'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source = db.Column(db.String(100), index=True)
    log_type = db.Column(db.String(50), index=True)
    severity = db.Column(db.String(20), index=True)
    message = db.Column(db.Text)
    raw_data = db.Column(db.Text)
    ip_address = db.Column(db.String(45), index=True)
    username = db.Column(db.String(100), index=True)
    parsed_data = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source': self.source,
            'log_type': self.log_type,
            'severity': self.severity,
            'message': self.message,
            'ip_address': self.ip_address,
            'username': self.username,
            'parsed_data': self.parsed_data
        }


class ThreatAlert(db.Model):
    """Store detected threats and alerts"""
    __tablename__ = 'threat_alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    alert_type = db.Column(db.String(100), index=True)
    severity = db.Column(db.String(20), index=True)
    description = db.Column(db.Text)
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45))
    username = db.Column(db.String(100), index=True)
    rule_name = db.Column(db.String(200))
    status = db.Column(db.String(20), default='open', index=True)  # open, investigating, resolved, false_positive
    confidence = db.Column(db.Float)
    metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.String(100))
    notes = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'username': self.username,
            'rule_name': self.rule_name,
            'status': self.status,
            'confidence': self.confidence,
            'metadata': self.metadata
        }


class ComplianceReport(db.Model):
    """Store compliance reports"""
    __tablename__ = 'compliance_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    framework = db.Column(db.String(50), index=True)
    report_date = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    compliance_score = db.Column(db.Float)
    passed_checks = db.Column(db.Integer)
    failed_checks = db.Column(db.Integer)
    total_checks = db.Column(db.Integer)
    details = db.Column(db.JSON)
    recommendations = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'framework': self.framework,
            'report_date': self.report_date.isoformat() if self.report_date else None,
            'compliance_score': self.compliance_score,
            'passed_checks': self.passed_checks,
            'failed_checks': self.failed_checks,
            'total_checks': self.total_checks,
            'details': self.details,
            'recommendations': self.recommendations
        }


class SystemMetrics(db.Model):
    """Store system metrics and statistics"""
    __tablename__ = 'system_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    metric_type = db.Column(db.String(50), index=True)
    metric_value = db.Column(db.Float)
    metadata = db.Column(db.JSON)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'metric_type': self.metric_type,
            'metric_value': self.metric_value,
            'metadata': self.metadata
        }
