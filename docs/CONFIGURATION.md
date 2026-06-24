# Configuration

## Environment variables (`.env`)

All secrets **must** be supplied via environment variables, never in `config.yaml`.

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | yes | Flask session signing key — use a long random string |
| `DATABASE_URI` | no | SQLAlchemy URI; defaults to `sqlite:///siem.db` |
| `APP_HOST` | no | Bind host; defaults to `0.0.0.0` |
| `APP_PORT` | no | Bind port; defaults to `8050` |
| `APP_DEBUG` | no | `true`/`false`; defaults to `false` |

Generate a secure `SECRET_KEY`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## `config.yaml`

`config.yaml` contains **non-secret** operational settings.

### `app` section

```yaml
app:
  name: "SIEM Dashboard"
  host: "0.0.0.0"   # overridden by APP_HOST env var
  port: 8050         # overridden by APP_PORT env var
  debug: false       # overridden by APP_DEBUG env var
  # secret_key: NEVER set here — use the SECRET_KEY env var
```

### `database` section

```yaml
database:
  uri: "sqlite:///siem.db"
  # PostgreSQL: "postgresql://user:password@host/dbname"
  # URI is overridden by DATABASE_URI env var
```

### Log sources

```yaml
log_sources:
  - name: "System Logs"
    path: "./logs/system.log"
    type: "syslog"    # syslog | apache | json | security
    enabled: true
```

### Threat detection rules

Each rule has a `type`, optional `threshold`, `time_window` (seconds), and `severity` (`low | medium | high | critical`).

### Compliance

```yaml
compliance:
  frameworks:
    - "PCI-DSS"
    - "HIPAA"
    - "GDPR"
    - "SOC2"
  retention_days: 90
```

## `.env.example`

```dotenv
SECRET_KEY=replace-with-a-random-64-char-hex-string
DATABASE_URI=sqlite:///siem.db
APP_HOST=0.0.0.0
APP_PORT=8050
APP_DEBUG=false
```
