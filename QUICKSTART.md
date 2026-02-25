# 🚀 Quick Start Guide

Get your SIEM Dashboard running in 5 minutes!

## Prerequisites
- Python 3.8+ installed
- Terminal/Command Prompt access
- Web browser

## Installation (Choose One)

### Option A: Automatic Setup (Recommended)

**macOS/Linux:**
```bash
./start.sh
```

**Windows:**
```bash
start.bat
```

That's it! The script will:
✅ Create virtual environment
✅ Install dependencies
✅ Generate sample data
✅ Initialize database
✅ Start services
✅ Open dashboard at http://localhost:8050

### Option B: Manual Setup

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate sample data
python generate_sample_data.py

# 4. Initialize database
python db_utils.py init

# 5. Start log ingestion (Terminal 1)
python log_ingestion.py &

# 6. Start dashboard (Terminal 2)
python app.py
```

## First Steps

1. **Open Dashboard**
   - Navigate to: http://localhost:8050
   - You should see the SIEM Dashboard with sample data

2. **Explore Tabs**
   - **Overview**: View log statistics and activity
   - **Threat Detection**: See detected security threats
   - **Compliance**: Check compliance scores
   - **Analytics**: Analyze traffic patterns

3. **Check Sample Alerts**
   - Go to "Threat Detection" tab
   - View "Recent Alerts" table
   - Notice simulated brute force and injection attempts

## What You Get Out of the Box

✨ **200+ Sample Logs** across 4 log types
🚨 **Pre-configured Threat Detection** rules
📊 **Interactive Dashboard** with real-time updates
📋 **4 Compliance Frameworks** (PCI-DSS, HIPAA, GDPR, SOC2)
⚡ **Auto-refresh** every 30 seconds

## Quick Configuration

### Change Dashboard Port

Edit `config.yaml`:
```yaml
app:
  port: 8080  # Change from 8050
```

### Add Your Own Logs

Edit `config.yaml`:
```yaml
log_sources:
  - name: "My App"
    path: "/path/to/your/app.log"
    type: "json"  # or syslog, apache, security
    enabled: true
```

### Adjust Threat Sensitivity

Edit `config.yaml`:
```yaml
threat_detection:
  rules:
    - name: "Brute Force Detection"
      threshold: 3  # Lower = more sensitive
      time_window: 600  # seconds
```

## Stopping Services

**Press `Ctrl+C`** in the terminal

Or manually:
```bash
# Find processes
ps aux | grep python

# Kill processes
kill <PID>
```

## Common Issues

### Port Already in Use
```bash
# Change port in config.yaml
app:
  port: 8080
```

### No Data Showing
```bash
# Regenerate sample data
python generate_sample_data.py

# Restart services
./start.sh
```

### Import Errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate
pip install -r requirements.txt
```

## Next Steps

📖 **Read the Docs:**
- [README.md](README.md) - Full overview
- [USER_GUIDE.md](USER_GUIDE.md) - Detailed usage
- [CONFIGURATION.md](CONFIGURATION.md) - Advanced config

🔧 **Customize:**
- Add real log sources
- Create custom threat rules
- Configure compliance frameworks
- Set up email/Slack alerts

🚀 **Production:**
- Use PostgreSQL database
- Enable HTTPS
- Add authentication
- Set up monitoring

## Testing the Features

### Test Threat Detection
```bash
# Generate attack logs
python -c "
from generate_sample_data import SampleDataGenerator
gen = SampleDataGenerator()
with open('logs/security.log', 'a') as f:
    for log in gen.generate_attack_logs():
        f.write(log)
"

# Watch dashboard for new alerts
```

### View Database Stats
```bash
python db_utils.py stats
```

### Reset Everything
```bash
python db_utils.py reset
python generate_sample_data.py
./start.sh
```

## Demo Credentials

Currently no authentication required.

**Future versions will include:**
- Username: `admin`
- Password: `admin`
- Role-based access control

## Performance Expectations

**Hardware Requirements:**
- CPU: 2+ cores recommended
- RAM: 2GB minimum
- Disk: 1GB for application + logs

**Typical Performance:**
- Dashboard load: < 2 seconds
- Log ingestion: 1000s logs/second
- Database queries: < 100ms
- Auto-refresh: 30 seconds

## Quick Reference

### File Locations
```
config.yaml          # Main configuration
logs/               # Log files
siem.db             # SQLite database
ingestion.log       # Service logs
```

### Important Commands
```bash
./start.sh           # Start everything
python db_utils.py stats   # View statistics
python generate_sample_data.py  # Create test data
python db_utils.py reset   # Reset database
```

### URLs
- Dashboard: http://localhost:8050
- Change port in `config.yaml`

## Support

🐛 **Found a Bug?**
- Check existing issues
- Create new issue with details

💡 **Have a Question?**
- Read USER_GUIDE.md
- Check CONFIGURATION.md
- Open GitHub discussion

🚀 **Want to Contribute?**
- Fork repository
- Create feature branch
- Submit pull request

## Success Checklist

- [ ] Dashboard loads at http://localhost:8050
- [ ] See data in Overview tab
- [ ] Alerts visible in Threat Detection tab
- [ ] Compliance scores showing
- [ ] Auto-refresh working (watch timestamp)
- [ ] Can navigate between tabs
- [ ] No errors in terminal

## Congratulations! 🎉

You now have a fully functional SIEM Dashboard!

**What's Running:**
1. Log Ingestion Service (monitoring log files)
2. Threat Detection Engine (analyzing logs)
3. Web Dashboard (visualizing data)
4. Database (storing everything)

**Next:** Explore the dashboard and read the [USER_GUIDE.md](USER_GUIDE.md) for advanced features!

---

**Need Help?** Open an issue or check the documentation!

**Happy Monitoring!** 🛡️
