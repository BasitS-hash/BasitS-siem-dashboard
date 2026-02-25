# Installation Guide

## System Requirements

- Python 3.8 or higher
- 2GB RAM minimum
- 1GB disk space
- macOS, Linux, or Windows

## Installation Steps

### 1. Python Installation

#### macOS
```bash
# Using Homebrew
brew install python3

# Verify installation
python3 --version
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

#### Windows
Download from [python.org](https://www.python.org/downloads/)

### 2. Clone Repository

```bash
git clone https://github.com/basitsherazi/basit-siem-dashboard.git
cd basit-siem-dashboard
```

### 3. Setup Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate (macOS/Linux)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano config.yaml  # or use your preferred editor
```

### 6. Initialize Database

```bash
python db_utils.py init
```

### 7. Generate Sample Data (Optional)

```bash
python generate_sample_data.py
```

### 8. Start Services

#### Option A: Using startup script (Recommended)
```bash
chmod +x start.sh
./start.sh
```

#### Option B: Manual startup
```bash
# Terminal 1: Start log ingestion
python log_ingestion.py

# Terminal 2: Start dashboard
python app.py
```

### 9. Access Dashboard

Open browser: `http://localhost:8050`

## Production Deployment

### Using PostgreSQL

1. Install PostgreSQL:
```bash
# macOS
brew install postgresql

# Ubuntu/Debian
sudo apt install postgresql postgresql-contrib
```

2. Create database:
```bash
sudo -u postgres psql
CREATE DATABASE siem_db;
CREATE USER siem_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE siem_db TO siem_user;
\q
```

3. Update config.yaml:
```yaml
database:
  uri: "postgresql://siem_user:your_password@localhost/siem_db"
```

### Using Gunicorn (Production Server)

```bash
gunicorn -w 4 -b 0.0.0.0:8050 app:server
```

### Using Docker (Coming Soon)

```bash
docker-compose up -d
```

## Troubleshooting

### Import Errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate
pip install -r requirements.txt
```

### Port Already in Use
```bash
# Find process using port 8050
lsof -i :8050

# Kill the process
kill -9 <PID>
```

### Database Connection Issues
```bash
# Reset database
python db_utils.py reset

# Reinitialize
python db_utils.py init
```

### Permission Errors
```bash
# Make scripts executable
chmod +x start.sh

# Check log directory permissions
chmod 755 logs/
```

## Verification

Check installation:
```bash
python db_utils.py stats
```

Expected output:
```
📊 Database Statistics:
   Log Entries: XXX
   Threat Alerts: XX
   Compliance Reports: X
```

## Next Steps

1. Review `config.yaml` and customize for your environment
2. Add your log sources
3. Configure threat detection rules
4. Set up compliance frameworks
5. Configure alerts (email/Slack)

## Support

- Documentation: `README.md`
- Issues: GitHub Issues
- Email: support@example.com
