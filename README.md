# 🛡️ SIEM Dashboard

A comprehensive Python-based Security Information and Event Management (SIEM) dashboard with advanced log analysis, real-time threat detection, and compliance reporting capabilities.

## ✨ Features

### 📊 Log Analysis
- **Multi-format support**: Syslog, Apache/NGINX, JSON, and custom security logs
- **Real-time ingestion**: Continuous monitoring of log files with automatic parsing
- **Advanced parsing**: Intelligent extraction of IPs, usernames, timestamps, and severity levels
- **Searchable history**: Full-text search across all ingested logs

### 🔍 Threat Detection
- **Brute Force Detection**: Identifies multiple failed login attempts
- **SQL Injection Detection**: Pattern-based detection of SQL injection attacks
- **XSS Detection**: Identifies cross-site scripting attempts
- **Port Scan Detection**: Detects suspicious port scanning activity
- **Traffic Anomaly Detection**: Identifies unusual traffic patterns

### 📋 Compliance Reporting
- **PCI-DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **GDPR**: General Data Protection Regulation
- **SOC 2**: Service Organization Control 2

### 📈 Interactive Dashboard
- Real-time visualizations with auto-refresh
- Timeline charts for log activity and threats
- Geographic distribution maps
- Severity and alert type breakdowns
- Compliance score tracking
- Threat alert management

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/basitsherazi/basit-siem-dashboard.git
cd basit-siem-dashboard
```

2. **Create a virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure the application**
```bash
cp .env.example .env
# Edit .env with your settings
```

5. **Generate sample data (optional)**
```bash
python generate_sample_data.py
```

6. **Start the log ingestion service**
```bash
python log_ingestion.py &
```

7. **Start the dashboard**
```bash
python app.py
```

8. **Access the dashboard**

Open your browser and navigate to: `http://localhost:8050`

## 📁 Project Structure

```
basit-siem-dashboard/
├── app.py                      # Main dashboard application
├── models.py                   # Database models
├── log_parser.py              # Log parsing engine
├── threat_detector.py         # Threat detection rules
├── compliance.py              # Compliance reporting
├── log_ingestion.py           # Log ingestion service
├── generate_sample_data.py    # Sample data generator
├── config.yaml                # Configuration file
├── requirements.txt           # Python dependencies
├── .env.example              # Environment variables template
└── logs/                     # Log files directory
    ├── system.log
    ├── access.log
    ├── app.log
    └── security.log
```

## ⚙️ Configuration

Edit `config.yaml` to customize:

### Log Sources
```yaml
log_sources:
  - name: "System Logs"
    path: "./logs/system.log"
    type: "syslog"
    enabled: true
```

### Threat Detection Rules
```yaml
threat_detection:
  rules:
    - name: "Brute Force Detection"
      type: "failed_login"
      threshold: 5
      time_window: 300
      severity: "high"
```

### Compliance Frameworks
```yaml
compliance:
  frameworks:
    - "PCI-DSS"
    - "HIPAA"
    - "GDPR"
    - "SOC2"
  retention_days: 90
```

## 🔧 Usage

### Adding Custom Log Sources

1. Add your log source to `config.yaml`:
```yaml
log_sources:
  - name: "Custom App"
    path: "/var/log/custom_app.log"
    type: "json"
    enabled: true
```

2. Restart the log ingestion service

### Creating Custom Threat Detection Rules

Add new rules to `config.yaml`:
```yaml
threat_detection:
  rules:
    - name: "Custom Rule"
      type: "pattern_match"
      patterns:
        - "(?i)(suspicious_pattern)"
      severity: "medium"
```

### Generating Compliance Reports

Compliance reports are automatically generated daily. To manually generate:

```python
from compliance import ComplianceChecker
from datetime import datetime, timedelta

checker = ComplianceChecker(config)
report = checker.generate_report(
    'PCI-DSS',
    datetime.now() - timedelta(days=7),
    datetime.now()
)
```

## 📊 Dashboard Features

### Overview Tab
- Total logs in last 24 hours
- Active threat count
- Critical alerts
- Compliance score
- Log activity timeline
- Severity distribution
- Top source IPs
- Log type distribution

### Threat Detection Tab
- Threat alert timeline
- Alert types breakdown
- Severity analysis
- Recent alerts table with status tracking

### Compliance Tab
- Framework comparison scores
- Detailed compliance checks
- Recommendations
- Historical trends

### Analytics Tab
- Geographic distribution map
- Hourly traffic patterns
- Anomaly detection visualization

## 🛠️ Development

### Running Tests
```bash
# Add your test files to tests/
pytest tests/
```

### Database Migration
```bash
# For production with PostgreSQL
# Update config.yaml:
database:
  uri: "postgresql://username:password@localhost/siem_db"
```

### Custom Parsers

Extend `log_parser.py` to add custom log formats:

```python
def parse_custom_format(self, log_line: str) -> Dict:
    # Your parsing logic here
    return {
        'timestamp': datetime.now(),
        'message': log_line,
        'severity': 'info'
    }
```

## 🔒 Security Considerations

1. **Database**: Use PostgreSQL in production with proper authentication
2. **Secrets**: Never commit `.env` file; use environment variables
3. **Access Control**: Implement authentication for the dashboard
4. **HTTPS**: Deploy behind a reverse proxy with SSL/TLS
5. **Log Retention**: Configure appropriate retention policies

## 📈 Performance Optimization

- Use PostgreSQL for production deployments
- Implement log rotation to manage disk space
- Configure appropriate indexes on database tables
- Use Redis for caching (optional)
- Scale horizontally with multiple ingestion workers

## 🐛 Troubleshooting

### Dashboard not loading
- Check if the application is running: `ps aux | grep python`
- Verify port 8050 is not in use: `lsof -i :8050`
- Check logs for errors

### Logs not being ingested
- Verify log file paths in `config.yaml`
- Check file permissions
- Ensure log ingestion service is running

### Database errors
- Ensure database file/connection is accessible
- Run migrations if using PostgreSQL
- Check SQLAlchemy logs

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Flask and Dash frameworks
- Plotly for visualizations
- SQLAlchemy for database management
- The open-source security community

## 📞 Support

For issues, questions, or contributions:
- GitHub Issues: [basit-siem-dashboard/issues](https://github.com/basitsherazi/basit-siem-dashboard/issues)
- Email: support@example.com

## 🗺️ Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Email and Slack alert notifications
- [ ] API endpoints for integration
- [ ] User authentication and role-based access
- [ ] Export reports to PDF
- [ ] Integration with threat intelligence feeds
- [ ] Docker containerization
- [ ] Kubernetes deployment manifests

---

**Note**: This is a demonstration SIEM dashboard. For production use, implement proper authentication, use HTTPS, and follow security best practices.
Python-based SIEM dashboard with log analysis, threat detection, and compliance reporting
