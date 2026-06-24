# API Reference

The SIEM Dashboard exposes a REST-style API via Flask routes alongside the Dash UI.

## Base URL

```
http://localhost:8050
```

## Models

### LogEntry

| Field | Type | Description |
|---|---|---|
| `id` | int | Primary key |
| `timestamp` | datetime | Log event time |
| `source` | str | Log source name |
| `log_type` | str | `syslog`, `apache`, `json`, `security` |
| `severity` | str | `debug`, `info`, `warning`, `error`, `critical` |
| `message` | str | Human-readable log message |
| `ip_address` | str | Source IP (may be null) |
| `username` | str | Associated user (may be null) |
| `parsed_data` | JSON | Full structured parse result |

### ThreatAlert

| Field | Type | Description |
|---|---|---|
| `id` | int | Primary key |
| `timestamp` | datetime | Detection time |
| `alert_type` | str | `Brute Force Attack`, `SQL Injection Attempt`, `XSS Attempt`, `Port Scan`, `Traffic Anomaly` |
| `severity` | str | `low`, `medium`, `high`, `critical` |
| `description` | str | Human-readable description |
| `source_ip` | str | Attacker IP (may be null) |
| `username` | str | Targeted account (may be null) |
| `rule_name` | str | Detection rule that fired |
| `status` | str | `open`, `investigating`, `resolved`, `false_positive` |
| `confidence` | float | 0.0–1.0 |
| `metadata` | JSON | Rule-specific detail |

### ComplianceReport

| Field | Type | Description |
|---|---|---|
| `id` | int | Primary key |
| `framework` | str | `PCI-DSS`, `HIPAA`, `GDPR`, `SOC2` |
| `report_date` | datetime | Report generation time |
| `compliance_score` | float | 0–100 percentage |
| `passed_checks` | int | Number of checks passing |
| `failed_checks` | int | Number of checks failing |
| `total_checks` | int | Total checks evaluated |
| `details` | JSON | Per-requirement check results |
| `recommendations` | JSON | List of remediation steps |

## Programmatic usage

Access the database directly via SQLAlchemy:

```python
from app import server
from models import db, ThreatAlert

with server.app_context():
    open_alerts = db.session.query(ThreatAlert).filter_by(status='open').all()
    for alert in open_alerts:
        print(alert.to_dict())
```

## `db_utils.py` CLI

```bash
python db_utils.py init    # create tables
python db_utils.py reset   # drop and recreate (data loss!)
python db_utils.py stats   # row counts
```

## Log ingestion API

The `LogParser` class accepts a raw log line and a type string:

```python
from log_parser import LogParser

parser = LogParser()
result = parser.parse("192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1234", "apache")
print(result["ip_address"])  # "192.168.1.1"
```

## Threat detection API

```python
from threat_detector import ThreatDetector
import yaml

with open("config.yaml") as f:
    config = yaml.safe_load(f)

detector = ThreatDetector(config)
alerts = detector.analyze_log({"message": "Failed password for root from 1.2.3.4", "ip_address": "1.2.3.4"})
```
