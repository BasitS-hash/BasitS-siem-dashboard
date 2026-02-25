# Configuration Guide

## Overview

The SIEM Dashboard uses YAML configuration files for customization. The main configuration file is `config.yaml`.

## Configuration File Structure

```yaml
app:           # Application settings
database:      # Database configuration
log_sources:   # Log file sources
threat_detection:  # Threat detection rules
compliance:    # Compliance frameworks
alerts:        # Alert notifications
```

## Detailed Configuration

### Application Settings

```yaml
app:
  name: "SIEM Dashboard"
  host: "0.0.0.0"          # Listen on all interfaces
  port: 8050                # Dashboard port
  debug: true               # Enable debug mode (disable in production)
  secret_key: "change-this-to-a-random-secret-key"
```

**Security Note**: Generate a strong secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### Database Configuration

#### SQLite (Development)
```yaml
database:
  uri: "sqlite:///siem.db"
```

#### PostgreSQL (Production)
```yaml
database:
  uri: "postgresql://username:password@localhost:5432/siem_db"
```

#### MySQL
```yaml
database:
  uri: "mysql+pymysql://username:password@localhost:3306/siem_db"
```

### Log Sources

Configure multiple log sources with different formats:

```yaml
log_sources:
  - name: "System Logs"
    path: "./logs/system.log"
    type: "syslog"          # syslog, apache, json, security
    enabled: true

  - name: "Web Server Logs"
    path: "/var/log/nginx/access.log"
    type: "apache"
    enabled: true

  - name: "Application Logs"
    path: "/var/log/app/application.log"
    type: "json"
    enabled: true
```

**Supported Log Types**:
- `syslog`: Standard syslog format
- `apache`: Apache/NGINX access logs
- `json`: JSON formatted logs
- `security`: Custom security logs

### Threat Detection Rules

#### Brute Force Detection

```yaml
threat_detection:
  enabled: true
  rules:
    - name: "Brute Force Detection"
      type: "failed_login"
      threshold: 5              # Number of failed attempts
      time_window: 300          # Time window in seconds
      severity: "high"          # critical, high, medium, low
```

#### SQL Injection Detection

```yaml
    - name: "SQL Injection Detection"
      type: "sql_injection"
      patterns:
        - "(?i)(union.*select)"
        - "(?i)(select.*from.*where)"
        - "(?i)(drop.*table)"
        - "(?i)(insert.*into)"
      severity: "critical"
```

#### XSS Detection

```yaml
    - name: "XSS Detection"
      type: "xss"
      patterns:
        - "(?i)(<script.*?>)"
        - "(?i)(javascript:)"
        - "(?i)(onerror=)"
        - "(?i)(onclick=)"
      severity: "high"
```

#### Port Scan Detection

```yaml
    - name: "Port Scan Detection"
      type: "port_scan"
      threshold: 10             # Connections within time window
      time_window: 60           # Seconds
      severity: "medium"
```

#### Traffic Anomaly Detection

```yaml
    - name: "Unusual Traffic Volume"
      type: "traffic_anomaly"
      threshold_multiplier: 3.0  # 3x normal traffic
      severity: "medium"
```

### Compliance Configuration

```yaml
compliance:
  frameworks:
    - "PCI-DSS"
    - "HIPAA"
    - "GDPR"
    - "SOC2"
  reporting_schedule: "daily"   # daily, weekly, monthly
  retention_days: 90            # Log retention period
```

**Framework Details**:

- **PCI-DSS**: Payment card security requirements
- **HIPAA**: Healthcare data protection
- **GDPR**: EU data privacy regulation
- **SOC 2**: Service organization controls

### Alert Configuration

```yaml
alerts:
  email_notifications: true
  slack_notifications: false
  syslog_forwarding: false
```

## Environment Variables

Create a `.env` file for sensitive configuration:

```bash
# Database
DATABASE_URI=sqlite:///siem.db

# Application
SECRET_KEY=your-secret-key-here
DEBUG=True

# Email Alerts
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@example.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL=security@example.com

# Slack Alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Syslog Forwarding
SYSLOG_HOST=syslog-server.example.com
SYSLOG_PORT=514
```

## Custom Log Parsers

To add a custom log parser, edit `log_parser.py`:

```python
def parse_custom_format(self, log_line: str) -> Dict:
    """Parse custom log format"""
    # Your parsing logic
    pattern = r'(\d{4}-\d{2}-\d{2}) (\w+) (.+)'
    match = re.match(pattern, log_line)
    
    if match:
        date, level, message = match.groups()
        return {
            'timestamp': datetime.strptime(date, '%Y-%m-%d'),
            'severity': level.lower(),
            'message': message
        }
    
    return self.parse_generic(log_line)
```

Then register it:
```python
self.parsers = {
    'syslog': self.parse_syslog,
    'apache': self.parse_apache,
    'json': self.parse_json,
    'security': self.parse_security,
    'custom': self.parse_custom_format  # Add your parser
}
```

## Custom Threat Rules

Add custom detection logic in `threat_detector.py`:

```python
def _detect_custom_threat(self, log_data: Dict, rule: Dict) -> Optional[ThreatAlert]:
    """Detect custom threat pattern"""
    # Your detection logic
    if suspicious_condition:
        return ThreatAlert(
            alert_type='Custom Threat',
            severity='high',
            description='Detected suspicious activity',
            source_ip=log_data.get('ip_address'),
            rule_name=rule.get('name'),
            confidence=0.8
        )
    return None
```

## Performance Tuning

### Database Optimization

```yaml
database:
  uri: "postgresql://user:pass@localhost/siem_db?pool_size=20&max_overflow=30"
```

### Log Ingestion

```python
# Batch processing in log_ingestion.py
BATCH_SIZE = 100
FLUSH_INTERVAL = 5  # seconds
```

### Dashboard Refresh

```python
# In app.py, adjust refresh interval
dcc.Interval(
    id='interval-component',
    interval=60*1000,  # 60 seconds instead of 30
    n_intervals=0
)
```

## Security Best Practices

1. **Never commit `.env` file**
2. **Use strong secret keys**
3. **Enable HTTPS in production**
4. **Restrict database access**
5. **Implement authentication**
6. **Regular security updates**
7. **Log rotation and retention**
8. **Monitor dashboard access**

## Example Configurations

### Small Office Setup

```yaml
app:
  host: "127.0.0.1"  # Local only
  port: 8050
  debug: false

database:
  uri: "sqlite:///siem.db"

log_sources:
  - name: "System Logs"
    path: "/var/log/syslog"
    type: "syslog"
    enabled: true

threat_detection:
  rules:
    - name: "Basic Brute Force"
      type: "failed_login"
      threshold: 3
      time_window: 600
```

### Enterprise Setup

```yaml
app:
  host: "0.0.0.0"
  port: 443
  debug: false

database:
  uri: "postgresql://siem:password@db-server:5432/siem_db"

log_sources:
  - name: "Web Cluster"
    path: "/mnt/logs/web/*.log"
    type: "apache"
    enabled: true
  
  - name: "Application Logs"
    path: "/mnt/logs/app/*.json"
    type: "json"
    enabled: true

compliance:
  frameworks:
    - "PCI-DSS"
    - "SOC2"
  reporting_schedule: "daily"
  retention_days: 365
```

## Validation

Validate configuration:
```bash
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

## Support

For configuration issues:
1. Check syntax with YAML validator
2. Review logs for errors
3. Consult documentation
4. Open GitHub issue
