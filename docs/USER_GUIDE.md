# User Guide

## Dashboard tabs

### Overview

Real-time summary cards update every 30 seconds:

- **Total Logs** — events ingested in the past 24 hours
- **Active Threats** — open (unresolved) alerts
- **Critical Alerts** — severity = critical in the past 24 hours
- **Compliance Score** — average across all framework reports

Charts on this tab:
- Log Activity Timeline — hourly event volume
- Severity Distribution — pie chart of log severity levels
- Top Source IPs — bar chart of highest-traffic sources
- Log Types Distribution — breakdown by log format

### Threat Detection

- **Alert Timeline** — stacked area chart of alerts by severity over 7 days
- **Alert Types** — bar chart of detection rule triggers
- **Severity Breakdown** — pie chart of alert severity levels
- **Recent Alerts** — table of the 10 most recent alerts with status badges

### Compliance Reports

Select a framework from the dropdown to view:
- Framework compliance score
- Per-requirement check results with pass/fail/warning status
- Remediation recommendations

Supported frameworks: PCI-DSS, HIPAA, GDPR, SOC 2.

### Analytics

- **Geographic Distribution** — world map of top source IPs
- **Hourly Traffic Pattern** — average request counts by hour of day over 7 days

## Adding a log source

1. Edit `config.yaml` — add an entry under `log_sources`.
2. Supported types: `syslog`, `apache`, `json`, `security`.
3. Restart `log_ingestion.py`.

## Resolving an alert

Alerts start in `open` status. Update the status directly in the database:

```python
python db_utils.py stats   # find the alert ID
```

Or programmatically:

```python
from app import server
from models import db, ThreatAlert

with server.app_context():
    alert = db.session.get(ThreatAlert, 42)
    alert.status = "resolved"
    alert.resolved_by = "analyst@example.com"
    db.session.commit()
```

## Generating compliance reports manually

```python
from app import server
from models import db
from compliance import ComplianceChecker
from datetime import datetime, timedelta
import yaml

with open("config.yaml") as f:
    config = yaml.safe_load(f)

checker = ComplianceChecker(config)
end = datetime.now()
start = end - timedelta(days=30)

with server.app_context():
    report = checker.generate_report("PCI-DSS", start, end)
    db.session.add(report)
    db.session.commit()
    print(f"Score: {report.compliance_score:.1f}%")
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard shows "N/A" everywhere | No data ingested | Run `python generate_sample_data.py` |
| `SECRET_KEY` warning in logs | Env var not set | Set `SECRET_KEY` in `.env` |
| `date_trunc` errors | Using SQLite (PostgreSQL function) | Expected for SQLite — charts may show empty data; switch to PostgreSQL for full functionality |
| Log file not being watched | Path doesn't exist | The ingestion service creates the file automatically on start |
