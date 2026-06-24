# SIEM Dashboard

A Python-based Security Information and Event Management (SIEM) dashboard with real-time log analysis, threat detection, and compliance reporting.

## Features

- **Multi-format log ingestion** — syslog, Apache/NGINX, JSON, security logs; file-watcher based
- **Threat detection** — brute-force, SQL injection, XSS, port scan, traffic anomaly rules
- **Compliance reports** — PCI-DSS, HIPAA, GDPR, SOC 2 with per-requirement check detail
- **Interactive dashboard** — Plotly/Dash UI, 30-second auto-refresh, dark theme
- **SQLAlchemy ORM** — SQLite by default, PostgreSQL-ready

## Quick start

```bash
git clone https://github.com/basitsherazi/basit-siem-dashboard.git
cd basit-siem-dashboard

python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Set SECRET_KEY in .env (see docs/CONFIGURATION.md)

python db_utils.py init
python generate_sample_data.py   # optional sample data

python log_ingestion.py &         # background log watcher
python app.py                     # dashboard on http://localhost:8050
```

## Documentation

| Document | Description |
|---|---|
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Step-by-step installation, virtual env, dependencies, production deployment |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Environment variables, `config.yaml` reference, `.env.example` |
| [docs/API.md](docs/API.md) | Data models, programmatic usage, CLI reference |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Dashboard walkthrough, adding log sources, resolving alerts, troubleshooting |

## Project structure

```
.
├── app.py                  # Dash + Flask application entry point
├── models.py               # SQLAlchemy models (LogEntry, ThreatAlert, ...)
├── log_parser.py           # Multi-format log parser
├── threat_detector.py      # Rule-based threat detection engine
├── compliance.py           # Compliance framework checkers
├── log_ingestion.py        # File-watcher log ingestion service
├── db_utils.py             # Database CLI (init / reset / stats)
├── generate_sample_data.py # Development sample data generator
├── config.yaml             # Non-secret operational configuration
├── requirements.txt        # Pinned Python dependencies
├── .env.example            # Environment variable template
├── docs/                   # Extended documentation
└── logs/                   # Log files (git-ignored except .gitkeep)
```

## Security

- All secrets (`SECRET_KEY`, `DATABASE_URI`) are read from environment variables — **never** commit `.env`
- Input validation on log ingestion; `yaml.safe_load` for config parsing
- Parameterized queries via SQLAlchemy ORM throughout
- See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for hardening guidance

## Running tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=. --cov-report=term-missing
```

## CI

GitHub Actions runs on every push and pull request:
- `ruff` lint + `bandit` SAST
- `pytest` with coverage
- `pip-audit` dependency vulnerability scan

## License

MIT — see [LICENSE](LICENSE).
