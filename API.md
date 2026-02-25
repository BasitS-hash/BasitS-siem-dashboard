# API Documentation

## Overview

The SIEM Dashboard can be extended with a REST API for integration with other systems.

## API Endpoints (Future Enhancement)

### Authentication

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}

Response:
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "expires_in": 3600
}
```

### Logs

#### Get Logs
```http
GET /api/logs?limit=100&offset=0&severity=error
Authorization: Bearer {token}

Response:
{
  "total": 1000,
  "logs": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:30:45Z",
      "source": "System Logs",
      "severity": "error",
      "message": "Connection failed",
      "ip_address": "192.168.1.100"
    }
  ]
}
```

#### Create Log Entry
```http
POST /api/logs
Authorization: Bearer {token}
Content-Type: application/json

{
  "source": "Custom App",
  "severity": "info",
  "message": "User logged in",
  "ip_address": "192.168.1.50",
  "username": "jdoe"
}

Response:
{
  "id": 1001,
  "created_at": "2024-01-15T10:31:00Z"
}
```

### Alerts

#### Get Alerts
```http
GET /api/alerts?status=open&severity=high
Authorization: Bearer {token}

Response:
{
  "total": 5,
  "alerts": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:25:00Z",
      "alert_type": "Brute Force Attack",
      "severity": "high",
      "status": "open",
      "source_ip": "45.123.45.67",
      "confidence": 0.9
    }
  ]
}
```

#### Update Alert Status
```http
PATCH /api/alerts/{id}
Authorization: Bearer {token}
Content-Type: application/json

{
  "status": "resolved",
  "notes": "False positive - authorized penetration test"
}

Response:
{
  "id": 1,
  "status": "resolved",
  "updated_at": "2024-01-15T10:35:00Z"
}
```

### Compliance

#### Get Compliance Reports
```http
GET /api/compliance/reports?framework=PCI-DSS
Authorization: Bearer {token}

Response:
{
  "reports": [
    {
      "id": 1,
      "framework": "PCI-DSS",
      "compliance_score": 85.5,
      "report_date": "2024-01-15",
      "passed_checks": 17,
      "failed_checks": 3,
      "total_checks": 20
    }
  ]
}
```

#### Generate Report
```http
POST /api/compliance/generate
Authorization: Bearer {token}
Content-Type: application/json

{
  "framework": "HIPAA",
  "start_date": "2024-01-01",
  "end_date": "2024-01-15"
}

Response:
{
  "report_id": 5,
  "status": "completed",
  "compliance_score": 92.3
}
```

### Statistics

#### Get Dashboard Statistics
```http
GET /api/stats/dashboard
Authorization: Bearer {token}

Response:
{
  "total_logs_24h": 15234,
  "active_threats": 12,
  "critical_alerts_24h": 3,
  "avg_compliance_score": 88.7,
  "top_ips": [
    {"ip": "192.168.1.100", "count": 523},
    {"ip": "10.0.0.50", "count": 412}
  ]
}
```

## Python Client Example

```python
import requests

class SIEMClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
    
    def get_logs(self, limit=100, severity=None):
        params = {'limit': limit}
        if severity:
            params['severity'] = severity
        
        response = requests.get(
            f'{self.base_url}/api/logs',
            headers=self.headers,
            params=params
        )
        return response.json()
    
    def get_alerts(self, status='open'):
        response = requests.get(
            f'{self.base_url}/api/alerts',
            headers=self.headers,
            params={'status': status}
        )
        return response.json()
    
    def update_alert(self, alert_id, status, notes=''):
        data = {'status': status, 'notes': notes}
        response = requests.patch(
            f'{self.base_url}/api/alerts/{alert_id}',
            headers=self.headers,
            json=data
        )
        return response.json()

# Usage
client = SIEMClient('http://localhost:8050', 'your-api-key')
logs = client.get_logs(limit=50, severity='error')
alerts = client.get_alerts(status='open')
```

## Webhooks

### Alert Webhook

Configure webhooks to receive real-time alerts:

```python
# In your application
webhook_url = 'https://your-app.com/webhook/siem-alerts'

# Payload format
{
  "event": "alert.created",
  "timestamp": "2024-01-15T10:30:00Z",
  "alert": {
    "id": 123,
    "type": "Brute Force Attack",
    "severity": "high",
    "source_ip": "45.123.45.67",
    "description": "Multiple failed login attempts detected"
  }
}
```

## Integration Examples

### Slack Integration

```python
import requests

def send_slack_alert(alert):
    webhook_url = 'YOUR_SLACK_WEBHOOK_URL'
    message = {
        'text': f'🚨 Security Alert: {alert.alert_type}',
        'attachments': [{
            'color': 'danger',
            'fields': [
                {'title': 'Severity', 'value': alert.severity, 'short': True},
                {'title': 'Source IP', 'value': alert.source_ip, 'short': True},
                {'title': 'Description', 'value': alert.description}
            ]
        }]
    }
    requests.post(webhook_url, json=message)
```

### Email Integration

```python
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(alert):
    msg = MIMEMultipart()
    msg['From'] = 'siem@example.com'
    msg['To'] = 'security@example.com'
    msg['Subject'] = f'SIEM Alert: {alert.alert_type}'
    
    body = f"""
    Security Alert Detected
    
    Type: {alert.alert_type}
    Severity: {alert.severity}
    Source IP: {alert.source_ip}
    Time: {alert.timestamp}
    
    Description: {alert.description}
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('your-email@gmail.com', 'your-app-password')
    server.send_message(msg)
    server.quit()
```

### Syslog Integration

```python
import logging
import logging.handlers

def send_syslog(alert):
    syslog = logging.handlers.SysLogHandler(
        address=('syslog-server.example.com', 514)
    )
    
    logger = logging.getLogger('SIEM')
    logger.setLevel(logging.INFO)
    logger.addHandler(syslog)
    
    logger.info(
        f'ALERT: {alert.alert_type} - '
        f'Severity: {alert.severity} - '
        f'Source: {alert.source_ip}'
    )
```

## Rate Limiting

API requests are rate-limited:
- 1000 requests per hour per API key
- 100 requests per minute

Headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1642345678
```

## Error Handling

Standard HTTP status codes:
- `200 OK`: Success
- `201 Created`: Resource created
- `400 Bad Request`: Invalid request
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

Error response format:
```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid severity level",
    "details": {
      "field": "severity",
      "allowed_values": ["critical", "high", "medium", "low"]
    }
  }
}
```

## Coming Soon

- GraphQL API
- WebSocket support for real-time updates
- Batch operations
- Advanced filtering and search
- Report scheduling
- Custom dashboard widgets API
