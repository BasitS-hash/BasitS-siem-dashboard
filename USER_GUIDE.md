# User Guide

## Getting Started

### First Time Setup

1. **Start the Application**
   ```bash
   ./start.sh
   ```

2. **Access the Dashboard**
   - Open browser: `http://localhost:8050`
   - The dashboard will load with sample data

3. **Explore the Interface**
   - Navigate between tabs: Overview, Threat Detection, Compliance, Analytics
   - Cards update automatically every 30 seconds

## Dashboard Overview

### Main Interface

The dashboard consists of four main tabs:

#### 1. Overview Tab
- **Summary Cards**: Quick metrics for total logs, active threats, critical alerts, and compliance score
- **Log Activity Timeline**: Hourly breakdown of log ingestion
- **Severity Distribution**: Pie chart showing log severity levels
- **Top Source IPs**: Bar chart of most active IP addresses
- **Log Types**: Distribution of different log types

#### 2. Threat Detection Tab
- **Threat Alert Timeline**: Historical view of detected threats
- **Alert Types**: Breakdown of threat categories
- **Severity Breakdown**: Distribution of threat severity levels
- **Recent Alerts Table**: Real-time list of latest security alerts with status

#### 3. Compliance Reports Tab
- **Framework Scores**: Comparison of compliance scores across frameworks
- **Framework Selector**: Choose specific framework for detailed view
- **Compliance Details**: Detailed checks for selected framework
- **Recommendations**: Actionable items to improve compliance

#### 4. Analytics Tab
- **Geographic Distribution**: Map showing traffic sources (mock data)
- **Hourly Traffic Pattern**: Traffic trends by hour of day

## Common Tasks

### Viewing Logs

Logs are automatically ingested from configured sources and displayed in:
- Timeline charts (hourly aggregation)
- Severity distribution
- Source IP analysis

### Managing Threats

1. **View Active Threats**
   - Navigate to "Threat Detection" tab
   - Check "Recent Alerts" table
   - Filter by severity or status

2. **Alert Status Meanings**
   - **Open**: New, unreviewed alert
   - **Investigating**: Alert under review
   - **Resolved**: Threat mitigated
   - **False Positive**: Not a real threat

3. **Responding to Alerts** (via database/API)
   ```python
   from models import db, ThreatAlert
   
   alert = ThreatAlert.query.get(alert_id)
   alert.status = 'resolved'
   alert.notes = 'Blocked IP at firewall'
   db.session.commit()
   ```

### Compliance Reporting

1. **View Current Compliance**
   - Go to "Compliance Reports" tab
   - Check overall scores
   - Select framework for details

2. **Understanding Scores**
   - 90-100%: Excellent compliance
   - 80-89%: Good compliance
   - 70-79%: Needs improvement
   - Below 70%: Critical issues

3. **Following Recommendations**
   - Read recommendations at bottom of framework details
   - Address failed checks systematically
   - Re-run reports to track progress

### Adding Log Sources

1. **Edit Configuration**
   ```bash
   nano config.yaml
   ```

2. **Add New Source**
   ```yaml
   log_sources:
     - name: "My Application"
       path: "/var/log/myapp.log"
       type: "json"
       enabled: true
   ```

3. **Restart Services**
   ```bash
   # Stop current services (Ctrl+C)
   ./start.sh
   ```

### Customizing Threat Detection

1. **Edit Rules**
   ```bash
   nano config.yaml
   ```

2. **Add Custom Rule**
   ```yaml
   threat_detection:
     rules:
       - name: "Failed SSH Attempts"
         type: "failed_login"
         threshold: 3
         time_window: 600
         severity: "high"
   ```

3. **Restart to Apply**

## Features Explained

### Auto-Refresh
- Dashboard updates every 30 seconds
- No manual refresh needed
- Real-time monitoring

### Severity Levels
- **Critical**: Immediate action required
- **High**: Requires prompt attention
- **Medium**: Should be reviewed
- **Low**: Informational
- **Info**: Normal operations
- **Debug**: Technical details

### Threat Types

1. **Brute Force Attack**
   - Multiple failed login attempts
   - Default: 5 attempts in 5 minutes
   - Source IP tracked

2. **SQL Injection**
   - Pattern matching for SQL keywords
   - Checks request parameters
   - High severity by default

3. **XSS (Cross-Site Scripting)**
   - Detects script tags and JavaScript
   - Monitors user inputs
   - Prevents code injection

4. **Port Scan**
   - Rapid connection attempts
   - Multiple port access
   - Network reconnaissance detection

5. **Traffic Anomaly**
   - Unusual traffic volume
   - Baseline comparison
   - Adaptive thresholds

### Compliance Frameworks

#### PCI-DSS (Payment Card Industry)
**Focus**: Protecting cardholder data
- Logging requirements (Req 10)
- Access monitoring
- Log retention (1 year)

#### HIPAA (Healthcare)
**Focus**: Protected health information
- Audit controls (§164.312(b))
- Activity review
- Login monitoring

#### GDPR (EU Privacy)
**Focus**: Personal data protection
- Processing records (Art 30)
- Security measures (Art 32)
- Breach notification (Art 33)

#### SOC 2
**Focus**: Service organization controls
- Access controls (CC6.1)
- System monitoring (CC7.2)
- Threat detection (CC7.3)

## Maintenance

### Database Management

```bash
# View statistics
python db_utils.py stats

# Reset database (WARNING: deletes all data)
python db_utils.py reset

# Initialize fresh database
python db_utils.py init
```

### Log Rotation

Prevent disk space issues:
```bash
# In config.yaml, set retention
compliance:
  retention_days: 90

# Or use system logrotate
/var/log/siem/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
}
```

### Performance Optimization

1. **Reduce Refresh Interval** (if slow)
   ```python
   # In app.py
   interval=60*1000  # 60 seconds
   ```

2. **Database Cleanup**
   ```python
   # Delete old logs
   from datetime import datetime, timedelta
   cutoff = datetime.now() - timedelta(days=90)
   LogEntry.query.filter(LogEntry.timestamp < cutoff).delete()
   db.session.commit()
   ```

3. **Index Optimization**
   - Automatically indexed on: timestamp, severity, ip_address

## Troubleshooting

### Dashboard Not Loading

**Check Services**
```bash
ps aux | grep python
```

**Check Logs**
```bash
tail -f ingestion.log
```

**Restart Application**
```bash
./start.sh
```

### No Data Showing

**Verify Log Files**
```bash
ls -la logs/
cat logs/system.log
```

**Generate Test Data**
```bash
python generate_sample_data.py
```

**Check Database**
```bash
python db_utils.py stats
```

### High CPU Usage

**Reduce Update Frequency**
- Increase refresh interval
- Limit displayed data points

**Optimize Queries**
- Use time-based filtering
- Implement pagination

### Memory Issues

**Database Size**
```bash
# Check database file size
du -h siem.db

# Clean old records
python db_utils.py reset  # WARNING: deletes data
```

**Process Management**
```bash
# Monitor memory
top -p $(pgrep -f "python app.py")
```

## Best Practices

### Security
1. Change default secret key
2. Use HTTPS in production
3. Implement authentication
4. Restrict network access
5. Regular security updates

### Monitoring
1. Review alerts daily
2. Investigate unknowns
3. Update threat rules
4. Track compliance trends
5. Document incidents

### Maintenance
1. Regular database backups
2. Log rotation
3. Software updates
4. Capacity planning
5. Performance monitoring

## Advanced Usage

### API Integration
See `API.md` for programmatic access

### Custom Dashboards
Modify `app.py` to add custom visualizations

### Alert Automation
Configure webhooks for automated responses

### Reporting
Export compliance reports to PDF (future feature)

## Support

### Documentation
- README.md: Project overview
- INSTALLATION.md: Setup guide
- CONFIGURATION.md: Configuration reference
- API.md: API documentation
- USER_GUIDE.md: This document

### Help
- GitHub Issues
- Email: support@example.com
- Documentation: Full guides included

### Community
- Share configurations
- Report bugs
- Suggest features
- Contribute code

## Keyboard Shortcuts

- **Ctrl+C**: Stop services
- **F5**: Refresh browser
- **Cmd/Ctrl+T**: New browser tab

## Tips & Tricks

1. **Bookmark Dashboard**: Save `http://localhost:8050` for quick access
2. **Multiple Views**: Open different tabs in separate browser windows
3. **Export Data**: Use browser's screenshot feature for reports
4. **Test Alerts**: Use `generate_sample_data.py` with attack patterns
5. **Monitor Performance**: Keep an eye on refresh times

## What's Next?

1. **Learn Configuration**: Read `CONFIGURATION.md`
2. **Customize Rules**: Tailor threat detection to your needs
3. **Add Real Logs**: Connect actual log sources
4. **Set Up Alerts**: Configure email/Slack notifications
5. **Plan Compliance**: Focus on relevant frameworks

---

**Happy Monitoring! 🛡️**
